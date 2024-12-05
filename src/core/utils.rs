use std::fs::File;
use std::io::{self,BufRead};


#[macro_export()]
macro_rules! gen_random_bytes {
    ($len:expr) => {
        rand::thread_rng().gen::<[u8; $len]>()
    };
}

#[macro_export]
macro_rules! gen_random_alnum {
    ($len:expr) => {
        rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), $len)
    };
}

#[macro_export]
macro_rules! concatenate {
    ($path:expr, $extension:expr, $path_size:expr, $extension_size:expr) => {
        {
            let mut s = String::with_capacity($path_size + $extension_size);

            s.push_str($path);
            s.push_str($extension);

            s
        }
    }
}

#[macro_export]
macro_rules! println_titled {
    ($title:expr, $message:expr) => {
        println!("{}: {}", $title.bold(), $message);
    }
}

#[macro_export]
macro_rules! println_error {
    ($error:expr) => {
        println!("{}: {}", format!("{:?}", $error.kind()).red().bold(), $error);
    }
}

#[macro_export]
macro_rules! println_error_custom {
    ($title:expr, $message:expr) => {
        println!("{}: {}", $title.red().bold(), $message);
    }
}


pub fn read_file_lines(path: &str) -> Result<Vec<String>, io::Error> {
	let mut lines = Vec::<String>::new();
	let file = File::open(path)?;

	for line in io::BufReader::new(file).lines() {
		lines.push(line?);
	}

	Ok(lines)
}
