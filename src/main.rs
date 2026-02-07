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
use env_logger::{Builder, Env};
use log::LevelFilter;

use fdups::find_remove_duplicates;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The directory path to search for duplicates
    path: String,

    /// Automatically delete duplicate files
    #[arg(short, long)]
    delete: bool,

    /// Show what would be deleted without actually deleting
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Output results in JSON format
    #[arg(short, long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let env = Env::default().filter_or("FDUPS_LOG", "info");
    Builder::from_env(env).init();

    // Set up signal handling for graceful shutdown
    ctrlc::set_handler(move || {
        log::warn!("Interrupt received, shutting down gracefully...");
        fdups::set_shutdown();
    })
    .expect("Error setting Ctrl+C handler");

    let report = find_remove_duplicates(&args.path, args.delete, args.dry_run)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("\n{} total files found.", report.total_files);
        println!("\n{} duplicates found.", report.duplicate_count);
        println!("{} bytes in total.", report.total_size_bytes);
        println!(
            "{} bytes saved by deleting duplicates{}.",
            report.size_saved_bytes,
            if args.dry_run { " (dry run)" } else { "" }
        );
    }

    Ok(())
}
