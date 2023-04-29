// src/main.rs
use std::env;
use std::error::Error;

use find_duplicates::remove_duplicates;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let delete = args.contains(&String::from("--delete"));
    let path = args.get(1).expect("Missing directory argument");

    let (duplicate_count, size_saved) = remove_duplicates(path, delete)?;

    println!("\n{} duplicates found.", duplicate_count);
    println!("{} bytes saved by deleting duplicates.", size_saved);
    Ok(())
}
