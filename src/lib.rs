#![allow(warnings)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs::{self, metadata, File};
use std::io::BufReader;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use dashmap::DashMap;
use env_logger::*;
use human_bytes::human_bytes;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use log::*;
use rayon::prelude::*;
use serde::Serialize;
use term_size::dimensions;
use thiserror::Error;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal that the tool should shut down gracefully
pub fn set_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Custom error type for fdups
#[derive(Error, Debug)]
pub enum FdupsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Operation interrupted by user")]
    Interrupted,
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("WalkDir error: {0}")]
    Walk(String),

    #[error("Unexpected error: {0}")]
    Other(String),
}

/// A structured report of the duplicate detection results
#[derive(Serialize, Debug, Default)]
pub struct DuplicateReport {
    pub total_files: u128,
    pub total_size_bytes: u128,
    pub duplicate_count: u128,
    pub size_saved_bytes: u128,
}

#[derive(Debug, Serialize, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: std::time::SystemTime,
}

/// Custom return type for grouping files by size
type GroupingRetVal = (HashMap<u64, Vec<FileEntry>>, u128, u128);

/// Use a constant for file buffer size, making it easier to modify if needed
pub const BUFFER_SIZE: usize = 65536;

/// Use a constant for partial hash size
pub const PARTIAL_HASH_SIZE: usize = 512;

/// Finds and Removes(if set) duplicate files in a directory tree.
///
/// # Arguments
///
/// * `path` - The path to the directory to search for duplicates in.
/// * `delete` - Whether or not to delete duplicate files automatically.
///
/// # Errors
///
/// Returns an `io::Error` if any file cannot be opened, read, or deleted, or a `Box<dyn Error>`
/// if any other error occurs.
///
/// # Examples
///
/// ```no_run
/// use fdups::find_remove_duplicates;
///
/// let path = "/path/to/directory";
/// let report = find_remove_duplicates(path, true, false).unwrap();
///
/// println!("Found {} duplicates, saved {} bytes by deleting them", report.duplicate_count, report.size_saved_bytes);
/// ```
#[allow(deprecated)]
pub fn find_remove_duplicates(
    path: &str,
    delete: bool,
    dry_run: bool,
) -> Result<DuplicateReport, FdupsError> {
    debug!("Grouping files by size");
    let (files_by_size, total_files, total_file_sizes_in_bytes) =
        group_files_by_size(path, true, true, true, true)?;
    // group files by size
    debug!("Finding potential duplicates");
    let potential_duplicates = find_potential_duplicates(files_by_size);
    // get potential duplicates
    debug!("Finding duplicates");
    let duplicates = find_duplicates_with_hasher_cache(potential_duplicates)?;
    // find duplicates
    debug!("Processing duplicates");
    let (duplicate_count, size_saved) = process_duplicates(duplicates, delete, dry_run)?;
    // process duplicates
    info!(
        "Duplicate Ratio: {}/{} ({:.2}%)",
        duplicate_count,
        total_files,
        (duplicate_count as f64 / total_files as f64) * 100.0
    );
    info!(
        "Size Reduction: {}/{} ({:.2}%)",
        human_bytes(size_saved as f64),
        human_bytes(total_file_sizes_in_bytes as f64),
        (size_saved as f64 / total_file_sizes_in_bytes as f64) * 100.0
    );
    Ok(DuplicateReport {
        total_files,
        total_size_bytes: total_file_sizes_in_bytes,
        duplicate_count,
        size_saved_bytes: size_saved,
    })
}

/// Finds duplicates among potential duplicate.
///
/// Given a vector of potential duplicate files, this function hashes each file and groups
/// them together based on their hash. It uses hashmap(dashmap) as a cache to store the hashes of the files
/// to avoid re-hashing files that have already been hashed. The result is a hash map where
/// each key is a hash and the corresponding value is a vector of file paths that have that hash.
///
/// # Arguments
///
/// * `potential_duplicates` - A vector of `PathBufs` representing potential duplicate files.
///
/// # Returns
///
/// A Result containing a hash map where each key is a hash and the corresponding value is
/// a vector of file entries that have that hash, or an error if one occurs.
///
/// # Examples
///``` no_run
/// use std::path::PathBuf;
/// use fdups::{find_duplicates_with_hasher_cache, FileEntry};
/// let potential_duplicates = vec![
///     FileEntry { path: PathBuf::from("file1.txt"), size: 0, mtime: std::time::SystemTime::now() }
/// ];
/// let duplicates = find_duplicates_with_hasher_cache(potential_duplicates).unwrap();
/// assert_eq!(duplicates.len(), 0);
/// ```
pub fn find_duplicates_with_hasher_cache(
    potential_duplicates: Vec<FileEntry>,
) -> Result<HashMap<String, Vec<FileEntry>>, FdupsError> {
    let partial_groups: DashMap<String, Vec<FileEntry>> = DashMap::new();

    let pb = ProgressBar::new(potential_duplicates.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .map_err(|e| FdupsError::Other(e.to_string()))?
            .progress_chars("#>-"),
    );
    pb.set_message("Hashing files...");

    // Step 1: Group by partial hash (Parallel)
    potential_duplicates.into_par_iter().for_each(|file_entry| {
        if is_shutdown() {
            return;
        }
        if let Ok(hash) = partial_hash_file(&file_entry.path) {
            partial_groups
                .entry(hash)
                .or_insert_with(Vec::new)
                .push(file_entry);
        }
        pb.inc(1);
    });

    if is_shutdown() {
        return Err(FdupsError::Interrupted);
    }

    pb.finish_with_message("Hashing complete");

    let final_groups: DashMap<String, Vec<FileEntry>> = DashMap::new();

    // Step 2: For each partial hash group, verify with full hash if needed (Parallel)
    // We convert to HashMap first because DashMap doesn't directly implement IntoParallelIterator efficiently
    let groups: HashMap<String, Vec<FileEntry>> = partial_groups.into_iter().collect();

    groups
        .into_par_iter()
        .for_each(|(partial_hash, files): (String, Vec<FileEntry>)| {
            if files.len() > 1 {
                // Multiple files have the same partial hash, verify with full hash
                let full_map: DashMap<String, Vec<FileEntry>> = DashMap::new();

                // Parallelize full hashing within the group
                files.into_par_iter().for_each(|file_entry| {
                    if let Ok(full_hash) = full_hash_file(&file_entry.path) {
                        full_map
                            .entry(full_hash)
                            .or_insert_with(Vec::new)
                            .push(file_entry);
                    }
                });

                // Add all groups from full_map to final_groups
                for (f_hash, f_files) in full_map {
                    final_groups.insert(f_hash, f_files);
                }
            } else {
                // Only one file, keep as is (original behavior)
                final_groups.insert(partial_hash, files);
            }
        });

    // Convert DashMap to HashMap for return type
    let mut result = HashMap::new();
    for (hash, files) in final_groups {
        result.insert(hash, files);
    }
    Ok(result)
}

/// Create a partial_hash_file function
pub fn partial_hash_file(file_path: &PathBuf) -> io::Result<String> {
    let mut file = BufReader::new(File::open(file_path)?);

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; PARTIAL_HASH_SIZE];
    let bytes_read = file.read(&mut buffer)?;
    hasher.update(&buffer[..bytes_read]);

    let hash = hasher.finalize();
    Ok(hash.to_hex().to_string())
}

/// This function groups all the files at the given path by their size.
///
/// # Arguments
///
/// * path - A string slice representing the path to search for files.
///
/// # Returns
///
/// A Result containing a `HashMap` that maps file sizes to vectors of `PathBufs` representing the file paths.
///
/// # Errors
///
/// Returns a Box<dyn Error> if there is an error accessing or reading the file metadata.
#[inline]
pub fn group_files_by_size(
    path: &str,
    include_hidden: bool,
    include_git_ignore: bool,
    include_git_ignore_global: bool,
    include_git_exclude: bool,
) -> Result<GroupingRetVal, FdupsError> {
    let mut group_files_by_size: HashMap<u64, Vec<FileEntry>> = HashMap::new();
    let mut total_size_in_bytes: u128 = 0;
    let mut visited_inodes: HashSet<(u64, u64)> = HashSet::new();

    let walker = WalkBuilder::new(path)
        .hidden(!include_hidden)
        .git_ignore(!include_git_ignore) // respect .gitignore files
        .git_global(!include_git_ignore_global) // respect global git ignore
        .git_exclude(!include_git_exclude) // respect git exclude files
        .build();
    let mut total_files: u128 = 0;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}: {pos} files")
            .map_err(|e| FdupsError::Other(e.to_string()))?,
    );
    pb.set_message("Scanning directory");

    for entry in walker.filter_map(Result::ok) {
        if is_shutdown() {
            pb.finish_with_message("Scanning interrupted");
            return Err(FdupsError::Interrupted);
        }
        let path = entry.path().to_owned();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                debug!("Skipping {} due to metadata error: {}", path.display(), e);
                continue;
            }
        };

        #[cfg(unix)]
        {
            let dev = metadata.dev();
            let ino = metadata.ino();

            if metadata.is_dir() {
                if !visited_inodes.insert((dev, ino)) {
                    debug!("Skipping already visited directory: {}", path.display());
                    continue;
                }
            } else if metadata.is_file() {
                if !visited_inodes.insert((dev, ino)) {
                    debug!("Skipping hard link of already processed file: {}", path.display());
                    continue;
                }
                
                total_files += 1;
                pb.set_position(total_files as u64);
                
                let size = metadata.len();
                let mtime = metadata.modified().unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
                total_size_in_bytes += size as u128;
                group_files_by_size
                    .entry(size)
                    .or_insert_with(Vec::new)
                    .push(FileEntry { path, size, mtime });
            }
        }

        #[cfg(not(unix))]
        {
            if metadata.is_file() {
                total_files += 1;
                pb.set_position(total_files as u64);
                
                let size = metadata.len();
                let mtime = metadata.modified().unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
                total_size_in_bytes += size as u128;
                group_files_by_size
                    .entry(size)
                    .or_insert_with(Vec::new)
                    .push(FileEntry { path, size, mtime });
            }
        }
    }
    pb.finish_with_message("Scanning complete");
    Ok((group_files_by_size, total_files, total_size_in_bytes))
}

/// Given a hashmap of files grouped by size, returns a vector of potential duplicate files.
///
/// # Arguments
///
/// * `files_by_size` - A hashmap of files grouped by size.
///
/// # Returns
///
/// A vector of potential duplicate file entries.
///
/// # Examples
///```no_run
/// use std::collections::HashMap;
/// use std::path::PathBuf;
/// use fdups::{find_potential_duplicates, FileEntry};
/// let mut files_by_size: HashMap<u64, Vec<FileEntry>> = HashMap::new();
/// let now = std::time::SystemTime::now();
/// files_by_size.insert(100, vec![
///     FileEntry { path: PathBuf::from("file1.txt"), size: 100, mtime: now },
///     FileEntry { path: PathBuf::from("file2.txt"), size: 100, mtime: now }
/// ]);
/// let potential = find_potential_duplicates(files_by_size);
/// assert_eq!(potential.len(), 2);
///```
#[must_use]
pub fn find_potential_duplicates(
    files_by_size: HashMap<u64, Vec<FileEntry>>,
) -> Vec<FileEntry> {
    let mut potential_duplicates = Vec::new();
    // Iterate through the hash map and add the files to the vector if there's more than one file with the same size
    for (_size, files) in files_by_size {
        if files.len() > 1 {
            potential_duplicates.extend(files);
        }
    }
    // Return the list of potential duplicate files
    potential_duplicates
}
#[macro_export]
macro_rules! print_filepath {
    ( $arg:expr,original ) => {{
        let (termsize_width, _) = dimensions().unwrap_or((80, 24));
        println!("{}", "=".repeat(termsize_width));
        println!("\t- {} [Original]", $arg.display());
    }};
    ( $arg:expr,duplicate ) => {{
        println!("\t- {} [Duplicate]", $arg.display());
    }};
    ( $arg:expr,deleted ) => {{
        println!("\t- {} [Deleted]", $arg.display());
    }};
    ( $arg:expr,dry_run ) => {{
        println!("\t- {} [Deleted] [Dry Run]", $arg.display());
    }};
}
/// Processes the detected duplicates and removes them if delete flag is set.
///
/// # Arguments
///
/// * duplicates - A hashmap containing the detected duplicates grouped by hash.
/// * delete - A flag indicating whether to delete the duplicate files or not.
///
/// # Returns
///
/// A tuple containing the number of duplicate files found and the total size saved by removing them.
///
/// # Examples
///```no_run
/// use std::collections::HashMap;
/// use std::path::PathBuf;
/// use std::error::Error;
/// fn main() -> Result<(), Box<dyn Error>> {
///     use fdups::{process_duplicates, FileEntry};
///     let mut files = Vec::new();
///     let now = std::time::SystemTime::now();
///     files.push(FileEntry { path: PathBuf::from("file1.txt"), size: 10, mtime: now });
///     files.push(FileEntry { path: PathBuf::from("file2.txt"), size: 10, mtime: now });
///     let mut duplicates = HashMap::new();
///     duplicates.insert("hash1".to_string(), files);
///     let (count, size) = process_duplicates(duplicates, false, false)?;
///     assert_eq!(count, 1);
///     assert!(size > 0);
///     Ok(())
/// }
/// ```
pub fn process_duplicates(
    duplicates: HashMap<String, Vec<FileEntry>>,
    delete: bool,
    dry_run: bool,
) -> Result<(u128, u128), FdupsError> {
    // Define variables to keep track of the number of duplicates and amount of disk space saved
    let mut duplicate_count: u128 = 0;
    let mut size_saved: u128 = 0;
    // Iterate through the duplicates
    for (_hash, mut files) in duplicates {
        // Check if there's more than one file with the same hash
        if files.len() > 1 {
            // Sort files by creation time (oldest first)
            files.sort_by_key(|file| {
                // Get the file's metadata to determine its creation time
                let metadata = metadata(&file.path).unwrap();
                metadata
                    .created()
                    .unwrap_or_else(|_| metadata.modified().unwrap())
            });
            // Iterate through the files with the same hash
            for (i, entry) in files.iter().enumerate() {
                if is_shutdown() {
                    return Err(FdupsError::Interrupted);
                }
                if i == 0 {
                    // If this is the first file, print that it is the original
                    print_filepath!(entry.path, original);
                } else {
                    // Liveness check: ensure file hasn't changed since initial scan
                    match metadata(&entry.path) {
                        Ok(current_meta) => {
                            let current_mtime = current_meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                            if current_meta.len() != entry.size || current_mtime != entry.mtime {
                                warn!("File {} changed since scan, skipping for safety.", entry.path.display());
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!("Could not verify liveness for {}, skipping: {}", entry.path.display(), e);
                            continue;
                        }
                    }

                    duplicate_count += 1;
                    size_saved += entry.size as u128;
                    
                    // If delete is true, delete the file
                    if delete {
                        if dry_run {
                            print_filepath!(entry.path, dry_run);
                        } else {
                            #[cfg(unix)]
                            {
                                // If the OS is Unix, set the file permissions to read-only before deleting
                                let mut permissions = metadata(&entry.path)?.permissions();
                                permissions.set_mode(0o644);
                                fs::set_permissions(&entry.path, permissions)?;
                            }
                            fs::remove_file(&entry.path)?;
                            // print that it's deleted
                            print_filepath!(entry.path, deleted);
                        }
                    } else {
                        // Otherwise, print that it's a duplicate
                        print_filepath!(entry.path, duplicate);
                    }
                }
            }
        }
    }
    // Return the number of duplicates and amount of disk space saved as a tuple
    Ok((duplicate_count, size_saved))
}

/// Computes the blake2b hash of a file.
///
/// # Arguments
///
/// * `file_path` - The path to the file to hash.
/// * `full` - A boolean indicating whether to hash the entire file or only the first chunk.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be opened or read.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use fdups::full_hash_file;
///
/// let file_path = PathBuf::from("path/to/file");
/// let hash_result = full_hash_file(&file_path);
/// match hash_result {
///     Ok(hash) => println!("Hash of file {}: {}", file_path.display(), hash),
///     Err(e) => eprintln!("Error hashing file {}: {}", file_path.display(), e),
/// }
/// ```
pub fn full_hash_file(file_path: &PathBuf) -> io::Result<String> {
    let mut file = BufReader::new(File::open(file_path)?); // Open the file in buffered mode

    let mut hasher = blake3::Hasher::new(); // Create a new blake3 hasher

    let mut buffer = [0; BUFFER_SIZE]; // Create a buffer to store file chunks

    // Read the file in chunks and update the hasher with each chunk
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Finalize the hasher and return the hash as a hex string
    let hash = hasher.finalize();
    Ok(hash.to_hex().to_string())
}

// ============================================================================
// UNIT TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    // -------------------------------------------------------------------------
    // Helper Functions for Tests
    // -------------------------------------------------------------------------

    /// Creates a file with the specified content
    fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    fn create_file_entry(path: PathBuf) -> FileEntry {
        let meta = metadata(&path).unwrap();
        FileEntry {
            path,
            size: meta.len(),
            mtime: meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        }
    }

    /// Creates a file with deterministic content of specified size
    fn create_sized_file(dir: &TempDir, name: &str, size: usize) -> PathBuf {
        let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        create_test_file(dir, name, &content)
    }

    // -------------------------------------------------------------------------
    // Tests for partial_hash_file
    // -------------------------------------------------------------------------

    #[test]
    fn test_partial_hash_identical_files_same_hash() {
        let dir = TempDir::new().unwrap();
        let content = b"Hello, World! This is test content for hashing.";

        let file1 = create_test_file(&dir, "file1.txt", content);
        let file2 = create_test_file(&dir, "file2.txt", content);

        let hash1 = partial_hash_file(&file1).unwrap();
        let hash2 = partial_hash_file(&file2).unwrap();

        assert_eq!(
            hash1, hash2,
            "Identical files should have identical partial hashes"
        );
    }

    #[test]
    fn test_partial_hash_different_files_different_hash() {
        let dir = TempDir::new().unwrap();

        let file1 = create_test_file(&dir, "file1.txt", b"Content A");
        let file2 = create_test_file(&dir, "file2.txt", b"Content B");

        let hash1 = partial_hash_file(&file1).unwrap();
        let hash2 = partial_hash_file(&file2).unwrap();

        assert_ne!(
            hash1, hash2,
            "Different files should have different partial hashes"
        );
    }

    #[test]
    fn test_partial_hash_only_reads_first_512_bytes() {
        let dir = TempDir::new().unwrap();

        // Create two files with same first 512 bytes but different content after
        let mut content1 = vec![0u8; 1024];
        let mut content2 = vec![0u8; 1024];

        // First 512 bytes are identical
        for i in 0..512 {
            content1[i] = (i % 256) as u8;
            content2[i] = (i % 256) as u8;
        }
        // Bytes after 512 are different
        for i in 512..1024 {
            content1[i] = 0;
            content2[i] = 255;
        }

        let file1 = create_test_file(&dir, "file1.dat", &content1);
        let file2 = create_test_file(&dir, "file2.dat", &content2);

        let hash1 = partial_hash_file(&file1).unwrap();
        let hash2 = partial_hash_file(&file2).unwrap();

        assert_eq!(
            hash1, hash2,
            "Files with same first 512 bytes should have same partial hash"
        );
    }

    #[test]
    fn test_partial_hash_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = create_test_file(&dir, "empty.txt", b"");

        let hash = partial_hash_file(&file).unwrap();
        assert!(!hash.is_empty(), "Empty file should still produce a hash");
    }

    // -------------------------------------------------------------------------
    // Tests for full_hash_file
    // -------------------------------------------------------------------------

    #[test]
    fn test_full_hash_identical_files_same_hash() {
        let dir = TempDir::new().unwrap();
        let content = b"Hello, World! This is test content for full hashing.";

        let file1 = create_test_file(&dir, "file1.txt", content);
        let file2 = create_test_file(&dir, "file2.txt", content);

        let hash1 = full_hash_file(&file1).unwrap();
        let hash2 = full_hash_file(&file2).unwrap();

        assert_eq!(
            hash1, hash2,
            "Identical files should have identical full hashes"
        );
    }

    #[test]
    fn test_full_hash_different_files_different_hash() {
        let dir = TempDir::new().unwrap();

        let file1 = create_test_file(&dir, "file1.txt", b"Content A");
        let file2 = create_test_file(&dir, "file2.txt", b"Content B");

        let hash1 = full_hash_file(&file1).unwrap();
        let hash2 = full_hash_file(&file2).unwrap();

        assert_ne!(
            hash1, hash2,
            "Different files should have different full hashes"
        );
    }

    #[test]
    fn test_full_hash_differs_from_partial_for_large_files() {
        let dir = TempDir::new().unwrap();
        // Create a file larger than 512 bytes
        let file = create_sized_file(&dir, "large.dat", 2048);

        let partial = partial_hash_file(&file).unwrap();
        let full = full_hash_file(&file).unwrap();

        assert_ne!(
            partial, full,
            "Partial and full hashes should differ for files > 512 bytes"
        );
    }

    #[test]
    fn test_full_hash_same_as_partial_for_small_files() {
        let dir = TempDir::new().unwrap();
        // Create a file smaller than 512 bytes
        let file = create_test_file(&dir, "small.txt", b"Small content");

        let partial = partial_hash_file(&file).unwrap();
        let full = full_hash_file(&file).unwrap();

        assert_eq!(
            partial, full,
            "Partial and full hashes should be identical for files <= 512 bytes"
        );
    }

    // -------------------------------------------------------------------------
    // Tests for group_files_by_size
    // -------------------------------------------------------------------------

    #[test]
    fn test_group_files_by_size_basic() {
        let dir = TempDir::new().unwrap();

        // Create files of different sizes
        create_test_file(&dir, "a.txt", b"small");
        create_test_file(&dir, "b.txt", b"medium content");
        create_test_file(&dir, "c.txt", b"small"); // Same size as a.txt

        let path_str = dir.path().to_str().unwrap();
        let (groups, total_files, _) =
            group_files_by_size(path_str, true, true, true, true).unwrap();

        // Should have 2 size groups (5 bytes and 14 bytes)
        assert_eq!(groups.len(), 2, "Should have 2 different size groups");

        // The group with size 5 should have 2 files
        let small_group = groups.get(&5).unwrap();
        assert_eq!(small_group.len(), 2, "Small size group should have 2 files");

        assert!(total_files >= 3, "Should have at least 3 files");
    }

    #[test]
    fn test_group_files_by_size_empty_directory() {
        let dir = TempDir::new().unwrap();
        let path_str = dir.path().to_str().unwrap();

        let (groups, total_files, total_size) =
            group_files_by_size(path_str, true, true, true, true).unwrap();

        assert!(groups.is_empty(), "Empty dir should have no groups");
        assert_eq!(total_files, 0, "Empty dir should have 0 files");
        assert_eq!(total_size, 0, "Empty dir should have 0 total size");
    }

    #[test]
    fn test_group_files_by_size_nested_directories() {
        let dir = TempDir::new().unwrap();

        // Create files in nested directories
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        create_test_file(&dir, "root.txt", b"root content");
        let nested_file = subdir.join("nested.txt");
        let mut f = File::create(&nested_file).unwrap();
        f.write_all(b"nested content").unwrap();

        let path_str = dir.path().to_str().unwrap();
        let (groups, total_files, _) =
            group_files_by_size(path_str, true, true, true, true).unwrap();

        // Should find files in both root and subdirectory
        let total_file_count: usize = groups.values().map(|v| v.len()).sum();
        assert_eq!(
            total_file_count, 2,
            "Should find 2 files total including nested"
        );
        assert!(total_files >= 2);
    }

    // -------------------------------------------------------------------------
    // Tests for find_potential_duplicates
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_potential_duplicates_filters_unique_sizes() {
        let mut files_by_size: HashMap<u64, Vec<FileEntry>> = HashMap::new();

        // Size 200: 2 files (should be included)
        let dup1 = PathBuf::from("/path/dup1.txt");
        let dup2 = PathBuf::from("/path/dup2.txt");
        files_by_size.insert(
            200,
            vec![
                FileEntry { path: dup1.clone(), size: 200, mtime: std::time::SystemTime::now() },
                FileEntry { path: dup2.clone(), size: 200, mtime: std::time::SystemTime::now() },
            ],
        );

        let potential = find_potential_duplicates(files_by_size);

        assert_eq!(
            potential.len(),
            2,
            "Should only include files from groups with 2+ files"
        );
    }

    #[test]
    fn test_find_potential_duplicates_empty_input() {
        let files_by_size: HashMap<u64, Vec<FileEntry>> = HashMap::new();
        let potential = find_potential_duplicates(files_by_size);
        assert!(potential.is_empty());
    }

    #[test]
    fn test_find_potential_duplicates_all_unique() {
        let mut files_by_size: HashMap<u64, Vec<FileEntry>> = HashMap::new();

        // All files have unique sizes
        for i in 0..10 {
            let path = PathBuf::from(format!("/path/file{}.txt", i));
            files_by_size.insert(
                i as u64 * 100,
                vec![FileEntry { path, size: i as u64 * 100, mtime: std::time::SystemTime::now() }],
            );
        }

        let potential = find_potential_duplicates(files_by_size);
        assert!(
            potential.is_empty(),
            "All unique sizes should result in no potential duplicates"
        );
    }

    // -------------------------------------------------------------------------
    // Tests for find_duplicates_with_hasher_cache
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_duplicates_with_identical_files() {
        let dir = TempDir::new().unwrap();
        let content = b"This is duplicate content for testing.";

        let file1 = create_test_file(&dir, "dup1.txt", content);
        let file2 = create_test_file(&dir, "dup2.txt", content);
        let file3 = create_test_file(&dir, "dup3.txt", content);

        let potential = vec![
            create_file_entry(file1.clone()),
            create_file_entry(file2.clone()),
            create_file_entry(file3.clone())
        ];
        let duplicates = find_duplicates_with_hasher_cache(potential).unwrap();

        // Should have 1 group containing all 3 files
        let groups_with_multiple: Vec<_> = duplicates
            .values()
            .filter(|files| files.len() > 1)
            .collect();

        assert_eq!(
            groups_with_multiple.len(),
            1,
            "Should have 1 duplicate group"
        );
        assert_eq!(
            groups_with_multiple[0].len(),
            3,
            "Duplicate group should have 3 files"
        );
    }

    #[test]
    fn test_find_duplicates_with_partial_hash_collision() {
        let dir = TempDir::new().unwrap();

        // Create files with same first 512 bytes but different content after
        // This tests the full hash verification path
        let mut content1 = vec![0u8; 1024];
        let mut content2 = vec![0u8; 1024];

        // Identical first 512 bytes
        for i in 0..512 {
            content1[i] = (i % 256) as u8;
            content2[i] = (i % 256) as u8;
        }
        // Different bytes after 512
        for i in 512..1024 {
            content1[i] = 0;
            content2[i] = 255;
        }

        let file1 = create_test_file(&dir, "collision1.dat", &content1);
        let file2 = create_test_file(&dir, "collision2.dat", &content2);

        let potential = vec![
            create_file_entry(file1.clone()),
            create_file_entry(file2.clone())
        ];
        let duplicates = find_duplicates_with_hasher_cache(potential).unwrap();

        // Should NOT be marked as duplicates because full hashes differ
        let duplicate_groups: Vec<_> = duplicates
            .values()
            .filter(|files| files.len() > 1)
            .collect();

        assert_eq!(
            duplicate_groups.len(),
            0,
            "Files with different full hashes should not be duplicates"
        );
    }

    #[test]
    fn test_find_duplicates_empty_input() {
        let potential: Vec<FileEntry> = vec![];
        let duplicates = find_duplicates_with_hasher_cache(potential).unwrap();
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_find_duplicates_single_file() {
        let dir = TempDir::new().unwrap();
        let file = create_test_file(&dir, "single.txt", b"Only one file");

        let potential = vec![create_file_entry(file)];
        let duplicates = find_duplicates_with_hasher_cache(potential).unwrap();

        // A single file cannot be a duplicate of anything
        let duplicate_groups: Vec<_> = duplicates
            .values()
            .filter(|files| files.len() > 1)
            .collect();
        assert!(duplicate_groups.is_empty());
    }

    // -------------------------------------------------------------------------
    // Tests for process_duplicates
    // -------------------------------------------------------------------------

    #[test]
    fn test_process_duplicates_counts_correctly() {
        let dir = TempDir::new().unwrap();
        let content = b"Duplicate content";

        let file1 = create_test_file(&dir, "orig.txt", content);
        let file2 = create_test_file(&dir, "dup1.txt", content);
        let file3 = create_test_file(&dir, "dup2.txt", content);

        let mut duplicates: HashMap<String, Vec<FileEntry>> = HashMap::new();
        duplicates.insert(
            "hash123".to_string(),
            vec![
                create_file_entry(file1.clone()),
                create_file_entry(file2.clone()),
                create_file_entry(file3.clone())
            ],
        );

        let (count, size_saved) = process_duplicates(duplicates, false, false).unwrap();

        // 3 files with same hash = 2 duplicates
        assert_eq!(count, 2, "Should report 2 duplicates");
        // Size saved = 2 * file_size
        assert_eq!(size_saved, 2 * content.len() as u128);
    }

    #[test]
    fn test_process_duplicates_with_delete() {
        let dir = TempDir::new().unwrap();
        let content = b"Content to delete";

        let file1 = create_test_file(&dir, "keep.txt", content);
        let file2 = create_test_file(&dir, "delete.txt", content);

        // Verify both files exist
        assert!(file1.exists());
        assert!(file2.exists());

        let mut duplicates: HashMap<String, Vec<FileEntry>> = HashMap::new();
        duplicates.insert(
            "hash456".to_string(),
            vec![
                create_file_entry(file1.clone()),
                create_file_entry(file2.clone())
            ]
        );

        let (count, _) = process_duplicates(duplicates, true, false).unwrap();

        assert_eq!(count, 1, "Should report 1 duplicate");
        // The oldest file (first created) should be kept
        // One of the files should be deleted
        let exists_count = [file1.exists(), file2.exists()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(exists_count, 1, "Only one file should remain after delete");
    }

    #[test]
    fn test_process_duplicates_no_duplicates() {
        let duplicates: HashMap<String, Vec<FileEntry>> = HashMap::new();
        let (count, size_saved) = process_duplicates(duplicates, false, false).unwrap();

        assert_eq!(count, 0);
        assert_eq!(size_saved, 0);
    }
}
