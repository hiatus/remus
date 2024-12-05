# remus

An extremely fast ransomware proof of concept for red team exercises. It's name stands for `r`ecursion, `e`ncryption, `mu`ltithreading and `s`eeking.

`remus` will recursively traverse all files and directories given to it as CLI arguments and encrypt files using AES128. The 128-bit key can be read from a file or specified in hexadecimal via CLI. The AES IV and the integrity challenge are written to the beginning of each encrypted file. Encrypted files are suffixed with `.remus` by default, but this can be changed (specify an empty suffix to disable the suffix and encrypt files in-place).

For a performance reference, on an 11th Gen Intel i7-11850H (8 cores, 16 threads), `remus` encrypted around 5GB of data divided in 28731 files on a complex directory tree in 4.53 seconds on average. Decryption time averaged 4.23 seconds.

**Disclaimer**: the sole purpose of this project is to simulate the impact of ransomware during red team exercises and is not intended to serve illegal objectives. I hold no responsibility for the misuse of this code.


## Features
- Extremely fast, multithreaded encryption.
- Regular expressions for filtering target files.
- CRC checks to prevent accidentally corrupting files that weren't previously encrypted by `remus`.
- Specifying a custom file extension (or none) for encrypted files.
- Portability (written in Rust).


## Building
- Just `git clone` the repository and `cargo build` the project:
```
$ git clone https://github.com/hiatus/remus
$ cd remus
$ cargo build --release
```
