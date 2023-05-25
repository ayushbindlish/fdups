//! `fdups` is a command-line utility for finding and removing duplicate files, fast.
//!
//! # Usage
//!
//! To run `fdups`, pass a directory path as the first argument:
//!
//! ```sh
//! fdups path/to/directory
//! ```
//!
//! If you want to automatically delete duplicates, use the `--delete` flag:
//!
//! ```sh
//! fdups path/to/directory --delete
//! ```
//!
//! # Examples
//!
//! ```no_run
//! use fdups::remove_duplicates;
//!
//! let path = "/path/to/directory";
//! let (duplicate_count, size_saved) = remove_duplicates(path, true)?;
//!
//! println!("Found {} duplicates, saved {} bytes by deleting them", duplicate_count, size_saved);
//! ```

use std::env;
use std::error::Error;

use fdups::find_remove_duplicates;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let delete = args.contains(&String::from("--delete"));

    // The first argument is the directory path
    let path = args.get(1).expect("Missing directory argument");

    let (total_files, duplicate_count, total_file_size, size_saved) =
        find_remove_duplicates(path, delete)?;

    println!("\n{total_files} total files found.");
    println!("\n{duplicate_count} duplicates found.");
    println!("{total_file_size} bytes in total.");
    println!("{size_saved} bytes saved by deleting duplicates.");

    Ok(())
}
