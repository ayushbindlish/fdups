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

use clap::Parser;
use std::error::Error;

use fdups::find_remove_duplicates;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The directory path to search for duplicates
    path: String,

    /// Automatically delete duplicate files
    #[arg(short, long)]
    delete: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let (total_files, duplicate_count, total_file_size, size_saved) =
        find_remove_duplicates(&args.path, args.delete)?;

    println!("\n{total_files} total files found.");
    println!("\n{duplicate_count} duplicates found.");
    println!("{total_file_size} bytes in total.");
    println!("{size_saved} bytes saved by deleting duplicates.");

    Ok(())
}
