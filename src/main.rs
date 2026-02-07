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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let report = find_remove_duplicates(&args.path, args.delete)?;

    println!("\n{} total files found.", report.total_files);
    println!("\n{} duplicates found.", report.duplicate_count);
    println!("{} bytes in total.", report.total_size_bytes);
    println!(
        "{} bytes saved by deleting duplicates.",
        report.size_saved_bytes
    );

    Ok(())
}
