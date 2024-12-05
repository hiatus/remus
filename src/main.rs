use colored::Colorize;
use regex::RegexSet;
use std::{path,time};
use structopt::StructOpt;

// Local
mod core;

use core::crypto;
use core::utils;


#[derive(Debug, StructOpt)]
struct RemusOptions {
    #[structopt(
        short = "d", long = "decrypt", help = "Decrypt instead of encrypting"
    )]
    decrypt: bool,

    #[structopt(
        short = "k", long = "key-hex", value_name = "hex", help = "Specify AES key bytes in hexadecimal"
    )]
    key_hex: Option<String>,

    #[structopt(
        short = "K", long = "key-file", value_name = "file", help = "Read AES key bytes from a file"
    )]
    key_file: Option<String>,

    #[structopt(
        short = "e", long = "file-extension", value_name = "string", default_value = ".remus",
        help = "Specify a suffix to be appended to encrypted files or removed from decrypted files"
    )]
    file_extension: String,

    #[structopt(
        short = "r", long = "regex", value_name = "string",
        help = "Only process files that match a regular expression (except <target>...)"
    )]
    regex: Option<String>,

    #[structopt(
        short = "R", long = "regex-file", value_name = "file",
        help = "Like `-r`, but with multiple regular expressions defined in a file"
    )]
    regex_file: Option<String>,

    #[structopt(
        value_name = "target", parse(from_os_str), required = true,
        help = "Target files and directories to recursively encrypt or decrypt"
    )]
    targets: Vec<std::path::PathBuf>
}

fn main() {
    let opts = RemusOptions::from_args();

    let mut key = [0u8; crypto::SIZE_AES_KEY];
    let mut regexes = Vec::<String>::new();

    // Parse AES key
    if opts.key_hex.is_some() && opts.key_file.is_some() {
        println_error_custom!("Error", "Only one key-related option can be set");
        return;
    }

    if let Some(key_hex) = opts.key_hex {
        if key_hex.len() != crypto::SIZE_AES_KEY * 2 {
            println_error_custom!("Error", &format!("Invalid AES key: {}", key_hex));
            return;
        }

        if let Ok(key_bytes) = hex::decode(&key_hex) {
            key = key_bytes.try_into().unwrap();
        }
        else {
            println_error_custom!("Error", &format!("Failed to parse hex: {}", key_hex));
            return;
        }
    }
    else if let Some(key_file) = opts.key_file {
        if let Err(e) = crypto::read_aes_key(&key_file, &mut key) {
            println_error_custom!(
                "Error", &format!("Failed to read AES key from {}: {}", &key_file, e)
            );

            return;
        }
    }
    else {
        println_error_custom!("Error", "No AES key specified");
        return;
    }

    // Parse regular expressions
    if opts.regex.is_some() && opts.regex_file.is_some() {
        println_error_custom!("Error", "Only one regex-related option can be set");
        return;
    }

    if let Some(regex) = opts.regex {
        regexes.push(regex);
    }
    else if let Some(regex_file) = opts.regex_file {
        match utils::read_file_lines(&regex_file) {
            Ok(lines) => {
                for regex in lines {
                    regexes.push(regex);
                }
            },
            Err(e) => {
                println_error_custom!("Error", &format!("Failed to read {}: {}", regex_file, e));
                return;
            }
        }
    }

    if regexes.is_empty() {
        regexes.push(String::from("."));
    }

    let regex_set: RegexSet = match RegexSet::new(regexes) {
        Ok(rs) => rs,
        Err(e) => {
            println_error_custom!("Error", &format!("Invalid regular expression: {}", e));
            return;
        }
    };

    for i in 0..opts.targets.len() {
        let arg = &opts.targets[i].to_str().unwrap();
        let path = path::Path::new(arg);

        if ! (path.is_file() || path.is_dir()) {
            println_error_custom!("Error", &format!("No such file or directory: {}", arg));
            return;
        }
    }

    let mut file_count: usize = 0;
    let before = time::Instant::now();

    for i in 0..opts.targets.len() {
        let arg = &opts.targets[i].to_str().unwrap();
        let path = path::Path::new(arg);
        let filename = path.file_name().unwrap().to_str().unwrap();

        if path.is_file() {
            if ! regex_set.is_match(filename) {
                continue;
            }

            if opts.decrypt {
                if let Err(e) = crypto::decrypt_file(arg, &key, &opts.file_extension) {
                    println_error!(e);
                    println!();
                };

                continue;
            }

            if let Err(e) = crypto::encrypt_file(arg, &key, &opts.file_extension) {
                println_error!(e);
                println!();

                continue;
            }

            file_count += 1;
            continue;
        }

        if opts.decrypt {
            match crypto::decrypt_directory(arg, &key, &opts.file_extension, &regex_set) {
                Ok(n) => {
                    file_count += n
                },
                Err(e) => {
                    println_error!(e);
                    println!();
                }
            }

            continue;
        }

        match crypto::encrypt_directory(arg, &key, &opts.file_extension, &regex_set) {
            Ok(n) => {
                file_count += n
            },
            Err(e) => {
                println_error!(e);
                println!();

                continue;
            }
        }
    }

    if file_count > 0 {
        println!(
            "\n{} files processed in {:.3} seconds",
            file_count, (before.elapsed().as_millis() as f32) / 1000.0
        );
    }
}
