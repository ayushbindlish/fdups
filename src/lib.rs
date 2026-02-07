#![allow(warnings)]

use memmap2::Mmap;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs::{self, metadata, File};
use std::io::BufReader;
use std::io::{self, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use dashmap::DashMap;
use env_logger::*;
use human_bytes::human_bytes;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use lasso::{Rodeo, Spur, ThreadedRodeo};
use log::*;
use rayon::prelude::*;
use redb::{Database, ReadableTable, TableDefinition};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use term_size::dimensions;
use thiserror::Error;

#[cfg(target_os = "linux")]
mod ioctl {
    use nix::ioctl_readwrite;

    const FS_IOC_MAGIC: u8 = b'f';
    const FS_IOC_FIEMAP: u8 = 11;

    #[repr(C)]
    #[derive(Default)]
    pub struct FiemapExtent {
        pub fe_logical: u64,
        pub fe_physical: u64,
        pub fe_length: u64,
        pub fe_reserved64: [u64; 2],
        pub fe_flags: u32,
        pub fe_reserved: [u32; 3],
    }

    #[repr(C)]
    pub struct Fiemap {
        pub fm_start: u64,
        pub fm_length: u64,
        pub fm_flags: u32,
        pub fm_mapped_extents: u32,
        pub fm_extent_count: u32,
        pub fm_reserved: u32,
        pub fm_extents: [FiemapExtent; 1],
    }

    ioctl_readwrite!(fiemap, FS_IOC_MAGIC, FS_IOC_FIEMAP, Fiemap);
}

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

// Global path interner (Lasso)
static INTERNER: OnceLock<ThreadedRodeo> = OnceLock::new();

fn get_interner() -> &'static ThreadedRodeo {
    INTERNER.get_or_init(ThreadedRodeo::new)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileEntry {
    pub path_spur: Spur,
    pub size: u64,
    pub mtime: std::time::SystemTime,
    pub dev: u64,
    pub ino: u64,
}

impl FileEntry {
    pub fn new(path: PathBuf, size: u64, mtime: std::time::SystemTime, dev: u64, ino: u64) -> Self {
        let interner = get_interner();
        let path_str = path.to_string_lossy();
        let spur = interner.get_or_intern(&path_str);
        Self {
            path_spur: spur,
            size,
            mtime,
            dev,
            ino,
        }
    }

    pub fn path(&self) -> &'static std::path::Path {
        let interner = get_interner();
        let s = interner.resolve(&self.path_spur);
        std::path::Path::new(s)
    }
}

const CACHE_TABLE: TableDefinition<(u64, u64), (u64, u32, u64, &str)> =
    TableDefinition::new("fingerprints");

use cuckoofilter::CuckooFilter;
use std::collections::hash_map::DefaultHasher;
use std::sync::RwLock;

pub struct SignatureCache {
    db: Database,
    filter: RwLock<CuckooFilter<DefaultHasher>>,
}

impl SignatureCache {
    pub fn open(path: &str) -> Result<Self, FdupsError> {
        let db = Database::builder()
            .create(path)
            .map_err(|e: redb::DatabaseError| FdupsError::Other(e.to_string()))?;

        // Initialize and populate Cuckoo Filter from existing DB
        let mut filter = CuckooFilter::new();

        // Populate filter
        let read_txn = db
            .begin_read()
            .map_err(|e| FdupsError::Other(e.to_string()))?;
        if let Ok(table) = read_txn.open_table(CACHE_TABLE) {
            if let Ok(iter) = table.iter() {
                for item in iter {
                    if let Ok((key, _value)) = item {
                        let (dev, ino) = key.value();
                        let _ = filter.add(&(dev, ino));
                    }
                }
            }
        }

        Ok(Self {
            db,
            filter: RwLock::new(filter),
        })
    }

    pub fn get(
        &self,
        dev: u64,
        ino: u64,
        mtime: std::time::SystemTime,
        size: u64,
    ) -> Option<String> {
        // Fast path: Check in-memory filter first
        // If not in filter, it's definitely not in DB (no false negatives in Cuckoo Filter?)
        // Wait, Cuckoo Filter has NO False Negatives (if usage is correct).
        // Meaning: If it returns false, item is NOT in set.
        // It helps avoid DB lookup for cache miss.
        {
            let filter = self.filter.read().ok()?;
            if !filter.contains(&(dev, ino)) {
                return None;
            }
        }

        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(CACHE_TABLE).ok()?;
        let value = table.get((dev, ino)).ok()??;
        let (v_secs, v_nanos, v_size, v_hash) = value.value();

        let duration = mtime
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?;
        if v_secs == duration.as_secs() && v_nanos == duration.subsec_nanos() && v_size == size {
            return Some(v_hash.to_string());
        }
        None
    }

    pub fn set(
        &self,
        dev: u64,
        ino: u64,
        mtime: std::time::SystemTime,
        size: u64,
        hash: &str,
    ) -> Result<(), FdupsError> {
        // Add to in-memory filter
        {
            if let Ok(mut filter) = self.filter.write() {
                let _ = filter.add(&(dev, ino));
            }
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e: redb::TransactionError| FdupsError::Other(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CACHE_TABLE)
                .map_err(|e: redb::TableError| FdupsError::Other(e.to_string()))?;
            let duration = mtime
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            table
                .insert(
                    (dev, ino),
                    (duration.as_secs(), duration.subsec_nanos(), size, hash),
                )
                .map_err(|e: redb::StorageError| FdupsError::Other(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e: redb::CommitError| FdupsError::Other(e.to_string()))?;
        Ok(())
    }
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
/// let report = find_remove_duplicates(path, true, false, None, false).unwrap();
///
/// println!("Found {} duplicates, saved {} bytes by deleting them", report.duplicate_count, report.size_saved_bytes);
/// ```
#[allow(deprecated)]
pub fn find_remove_duplicates(
    path: &str,
    delete: bool,
    dry_run: bool,
    cache_path: Option<&str>,
    reflink: bool,
) -> Result<DuplicateReport, FdupsError> {
    let cache = if let Some(cp) = cache_path {
        Some(SignatureCache::open(cp)?)
    } else {
        None
    };

    debug!("Grouping files by size");
    let (files_by_size, total_files, total_file_sizes_in_bytes) =
        group_files_by_size(path, true, true, true, true)?;

    let potential_duplicates = find_potential_duplicates(files_by_size);

    debug!("Finding duplicates by hashing");
    let duplicates = find_duplicates_with_hasher_cache(potential_duplicates, cache.as_ref())?;

    debug!("Processing duplicates");
    let (duplicate_count, size_saved) = process_duplicates(duplicates, delete, dry_run, reflink)?;

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
/// A vector of file entries that have that hash, or an error if one occurs.
pub fn find_duplicates_with_hasher_cache(
    potential_duplicates: Vec<FileEntry>,
    cache: Option<&SignatureCache>,
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

    pb.set_message("Hashing files...");

    // Optimization: Sort by physical location (LBA) to minimize seeking on HDDs
    // This is "Bleeding-Edge" optimization #2
    let mut sorted_potential = potential_duplicates;

    // Only sort if we have a significant number of files, as getting LBA has overhead
    if sorted_potential.len() > 100 {
        pb.set_message("Optimizing I/O order...");
        sort_by_physical_location(&mut sorted_potential);
        pb.set_message("Hashing files...");
    }

    // Step 1: Group by partial hash (Parallel)
    sorted_potential.into_par_iter().for_each(|file_entry| {
        if is_shutdown() {
            return;
        }
        if let Ok(hash) = partial_hash_file(file_entry.path()) {
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
        .for_each(|(_partial_hash, files): (String, Vec<FileEntry>)| {
            if files.len() > 1 {
                // Tier 2: Tail Hashing
                let tail_map: DashMap<String, Vec<FileEntry>> = DashMap::new();
                files.into_par_iter().for_each(|file_entry| {
                    if is_shutdown() {
                        return;
                    }
                    if is_shutdown() {
                        return;
                    }
                    if let Ok(hash) = tail_hash_file(file_entry.path()) {
                        tail_map
                            .entry(hash)
                            .or_insert_with(Vec::new)
                            .push(file_entry);
                    }
                });

                // Tier 3: Full Hashing for remaining groups
                for (_tail_hash, tail_files) in tail_map {
                    if tail_files.len() > 1 {
                        let full_map: DashMap<String, Vec<FileEntry>> = DashMap::new();
                        tail_files.into_par_iter().for_each(|file_entry| {
                            if is_shutdown() {
                                return;
                            }
                            if let Ok(full_hash) = full_hash_file(&file_entry, cache) {
                                full_map
                                    .entry(full_hash)
                                    .or_insert_with(Vec::new)
                                    .push(file_entry);
                            }
                        });

                        for (full_hash, same_files) in full_map {
                            if same_files.len() > 1 {
                                final_groups.insert(full_hash, same_files);
                            }
                        }
                    }
                }
            }
        });

    if is_shutdown() {
        return Err(FdupsError::Interrupted);
    }

    Ok(final_groups.into_iter().collect())
}

/// Create a partial_hash_file function (Head Hash, 4KB)
pub fn partial_hash_file(file_path: &std::path::Path) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut buffer = [0; 4096];
    let n = file.read(&mut buffer)?;
    Ok(blake3::hash(&buffer[..n]).to_hex().to_string())
}

/// Create a tail_hash_file function (Tail Hash, 4KB)
pub fn tail_hash_file(file_path: &std::path::Path) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let len = file.metadata()?.len();
    if len <= 4096 {
        return partial_hash_file(file_path);
    }
    file.seek(SeekFrom::End(-4096))?;
    let mut buffer = [0; 4096];
    let n = file.read(&mut buffer)?;
    Ok(blake3::hash(&buffer[..n]).to_hex().to_string())
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
                    debug!(
                        "Skipping hard link of already processed file: {}",
                        path.display()
                    );
                    continue;
                }

                total_files += 1;
                pb.set_position(total_files as u64);

                let size = metadata.len();
                let mtime = metadata
                    .modified()
                    .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
                total_size_in_bytes += size as u128;

                // Intern the path
                let path_str = path.to_string_lossy();
                let spur = get_interner().get_or_intern(&path_str);

                group_files_by_size
                    .entry(size)
                    .or_insert_with(Vec::new)
                    .push(FileEntry {
                        path_spur: spur,
                        size,
                        mtime,
                        dev,
                        ino,
                    });
            }
        }

        #[cfg(not(unix))]
        {
            if metadata.is_file() {
                total_files += 1;
                pb.set_position(total_files as u64);

                let size = metadata.len();
                let mtime = metadata
                    .modified()
                    .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
                total_size_in_bytes += size as u128;

                // Intern the path
                let path_str = path.to_string_lossy();
                let spur = get_interner().get_or_intern(&path_str);

                group_files_by_size
                    .entry(size)
                    .or_insert_with(Vec::new)
                    .push(FileEntry {
                        path_spur: spur,
                        size,
                        mtime,
                        dev: 0,
                        ino: 0,
                    });
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
///     FileEntry::new(PathBuf::from("file1.txt"), 100, now, 0, 0),
///     FileEntry::new(PathBuf::from("file2.txt"), 100, now, 0, 0)
/// ]);
/// let potential = find_potential_duplicates(files_by_size);
/// assert_eq!(potential.len(), 2);
///```
#[must_use]
pub fn find_potential_duplicates(files_by_size: HashMap<u64, Vec<FileEntry>>) -> Vec<FileEntry> {
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
    ( $arg:expr,reflinked ) => {{
        println!("\t- {} [Reflinked]", $arg.display());
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
///     files.push(FileEntry::new(PathBuf::from("file1.txt"), 10, now, 0, 0));
///     files.push(FileEntry::new(PathBuf::from("file2.txt"), 10, now, 0, 0));
///     let mut duplicates = HashMap::new();
///     duplicates.insert("hash1".to_string(), files);
///     let (count, size) = process_duplicates(duplicates, false, false, false)?;
///     assert_eq!(count, 1);
///     assert!(size > 0);
///     Ok(())
/// }
/// ```
pub fn process_duplicates(
    duplicates: HashMap<String, Vec<FileEntry>>,
    delete: bool,
    dry_run: bool,
    reflink_requested: bool,
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
                let metadata = metadata(file.path()).unwrap();
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
                    print_filepath!(entry.path(), original);
                } else {
                    // Liveness check: ensure file hasn't changed since initial scan
                    match metadata(entry.path()) {
                        Ok(current_meta) => {
                            let current_mtime = current_meta
                                .modified()
                                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                            if current_meta.len() != entry.size || current_mtime != entry.mtime {
                                warn!(
                                    "File {} changed since scan, skipping for safety.",
                                    entry.path().display()
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Could not verify liveness for {}, skipping: {}",
                                entry.path().display(),
                                e
                            );
                            continue;
                        }
                    }

                    // If reflink is requested, try to reflink from the original
                    if reflink_requested && !dry_run {
                        let original_path = files[0].path();

                        #[cfg(target_os = "linux")]
                        match safe_reflink(original_path, entry.path()) {
                            Ok(_) => {
                                print_filepath!(entry.path(), reflinked);
                                duplicate_count += 1;
                                size_saved += entry.size as u128;
                                continue;
                            }
                            Err(e) => {
                                warn!("Safe reflink failed for {}: {}. Falling back to default behavior.", entry.path().display(), e);
                            }
                        }

                        #[cfg(not(target_os = "linux"))]
                        match reflink::reflink(original_path, entry.path()) {
                            Ok(_) => {
                                print_filepath!(entry.path(), reflinked);
                                duplicate_count += 1;
                                size_saved += entry.size as u128;
                                continue;
                            }
                            Err(e) => {
                                warn!(
                                    "Reflink failed for {}: {}. Falling back to default behavior.",
                                    entry.path().display(),
                                    e
                                );
                            }
                        }
                    }

                    duplicate_count += 1;
                    size_saved += entry.size as u128;

                    // If delete is true, delete the file
                    if delete {
                        if dry_run {
                            print_filepath!(entry.path(), dry_run);
                        } else {
                            #[cfg(unix)]
                            {
                                // If the OS is Unix, set the file permissions to read-only before deleting
                                let mut permissions = metadata(entry.path())?.permissions();
                                permissions.set_mode(0o644);
                                fs::set_permissions(entry.path(), permissions)?;
                            }
                            fs::remove_file(entry.path())?;
                            // print that it's deleted
                            print_filepath!(entry.path(), deleted);
                        }
                    } else {
                        // Otherwise, print that it's a duplicate
                        print_filepath!(entry.path(), duplicate);
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
/// use fdups::{full_hash_file, FileEntry};
///
/// let entry = FileEntry {
///     path: PathBuf::from("file.txt"),
///     size: 100,
///     mtime: std::time::SystemTime::now(),
///     dev: 0,
///     ino: 0
/// };
/// let hash_result = full_hash_file(&entry, None);
/// ```
pub fn full_hash_file(entry: &FileEntry, cache: Option<&SignatureCache>) -> io::Result<String> {
    if let Some(c) = cache {
        if let Some(h) = c.get(entry.dev, entry.ino, entry.mtime, entry.size) {
            return Ok(h);
        }
    }

    let file = File::open(entry.path())?;
    let meta = file.metadata()?;
    let len = meta.len();

    let hash_str = if len > 1_048_576 {
        unsafe {
            let mut hasher = blake3::Hasher::new();

            #[cfg(target_os = "linux")]
            {
                // Sparse file optimization: skip hashing holes
                if let Ok(hash) = hash_sparse_file(&file, &mut hasher) {
                    hash
                } else {
                    let mmap = Mmap::map(&file)?;
                    libc::posix_fadvise(
                        file.as_raw_fd(),
                        0,
                        len as libc::off_t,
                        libc::POSIX_FADV_SEQUENTIAL,
                    );
                    blake3::hash(&mmap).to_hex().to_string()
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let mmap = Mmap::map(&file)?;
                blake3::hash(&mmap).to_hex().to_string()
            }
        }
    } else {
        let mut reader = BufReader::new(file);
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; BUFFER_SIZE];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        hasher.finalize().to_hex().to_string()
    };

    if let Some(c) = cache {
        let _ = c.set(entry.dev, entry.ino, entry.mtime, entry.size, &hash_str);
    }

    Ok(hash_str)
}

#[cfg(target_os = "linux")]
fn hash_sparse_file(file: &File, hasher: &mut blake3::Hasher) -> io::Result<String> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let mut curr: i64 = 0;
    let size = file.metadata()?.len() as i64;
    let mut buffer = [0u8; BUFFER_SIZE];

    while curr < size {
        let data_start = unsafe { libc::lseek(fd, curr, libc::SEEK_DATA) };
        if data_start == -1 {
            let remaining = size - curr;
            if remaining > 0 {
                let mut left = remaining;
                let zeros = [0u8; BUFFER_SIZE];
                while left > 0 {
                    let to_write = std::cmp::min(left as usize, BUFFER_SIZE);
                    hasher.update(&zeros[..to_write]);
                    left -= to_write as i64;
                }
            }
            break;
        }

        if data_start > curr {
            let mut left = data_start - curr;
            let zeros = [0u8; BUFFER_SIZE];
            while left > 0 {
                let to_write = std::cmp::min(left as usize, BUFFER_SIZE);
                hasher.update(&zeros[..to_write]);
                left -= to_write as i64;
            }
        }

        let hole_start = unsafe { libc::lseek(fd, data_start, libc::SEEK_HOLE) };
        let data_end = if hole_start == -1 { size } else { hole_start };

        let data_len = data_end - data_start;
        let mut file_clone = file.try_clone()?;
        file_clone.seek(io::SeekFrom::Start(data_start as u64))?;
        let mut left = data_len;
        while left > 0 {
            let to_read = std::cmp::min(left as usize, BUFFER_SIZE);
            let n = file_clone.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            left -= n as i64;
        }

        curr = data_end;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Atomically replaces `target` with a reflink of `source`.
///
/// This function:
/// 1. Creates a temporary file in the same directory as `target`.
/// 2. Reflinks `source` to the temporary file.
/// 3. Atomically swaps the temporary file with `target` using `renameat2(RENAME_EXCHANGE)`.
/// 4. Deletes the (now swapped) temporary file which contains the old `target` data.
///
/// This ensures that `target` is never in a partially-written state and that we
/// don't lose the original data until the swap is complete (crash consistency).
#[cfg(target_os = "linux")]
fn safe_reflink(source: &std::path::Path, target: &std::path::Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Create a temp file in the same directory
    let target_dir = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid target parent"))?;
    let target_name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid target name"))?;

    let mut temp_name = target_name.to_owned();
    temp_name.push(".fdups_tmp");
    let temp_path = target_dir.join(&temp_name);

    // 1. Create temp file (if it exists, remove it first to be clean)
    if temp_path.exists() {
        fs::remove_file(&temp_path)?;
    }

    // 2. Reflink source to temp_path
    if let Err(e) = reflink::reflink(source, &temp_path) {
        // Clean up temp if failed
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    // 3. Atomic Swap (RENAME_EXCHANGE)
    // We replace `target` with `temp_path`. RENAME_EXCHANGE swaps them.
    let temp_c = CString::new(temp_path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            temp_c.as_ptr(),
            libc::AT_FDCWD,
            target_c.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }

    // Swap successful. `temp_path` now refers to the OLD target file.
    // Delete it.
    fs::remove_file(&temp_path)?;
    Ok(())
}

// ============================================================================
// LBA / PHYSICAL OFFSET UTILS
// ============================================================================

#[cfg(target_os = "linux")]
fn get_physical_offset(path: &std::path::Path) -> Option<u64> {
    use ioctl::{fiemap, Fiemap, FiemapExtent};

    // Open file securely
    let file = File::open(path).ok()?;
    let fd = file.as_raw_fd();

    // Prepare FIEMAP request for the first byte
    let mut fiemap_struct = Fiemap {
        fm_start: 0,
        fm_length: 1, // We only care about the start
        fm_flags: 0,  // FIEMAP_FLAG_SYNC
        fm_mapped_extents: 0,
        fm_extent_count: 1,
        fm_reserved: 0,
        fm_extents: [FiemapExtent::default()],
    };

    // Call ioctl
    unsafe {
        match fiemap(fd, &mut fiemap_struct) {
            Ok(_) => {
                if fiemap_struct.fm_mapped_extents > 0 {
                    Some(fiemap_struct.fm_extents[0].fe_physical)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn get_physical_offset(_path: &std::path::Path) -> Option<u64> {
    None
}

/// Sorts a vector of FileEntries by their physical location on disk.
/// This minimizes seek time on rotating media (HDDs).
fn sort_by_physical_location(entries: &mut Vec<FileEntry>) {
    // We use a temporary vector to store (lba, index) pairs to avoid repeated syscalls
    // during sorting comparison
    let mut lba_map: Vec<(u64, usize)> = entries
        .par_iter()
        .enumerate()
        .map(|(i, entry)| (get_physical_offset(entry.path()).unwrap_or(u64::MAX), i))
        .collect();

    // Sort by LBA
    lba_map.sort_unstable_by_key(|&(lba, _)| lba);

    // Reorder the original vector
    // This requires a bit of shuffling, or we can just reconstruct
    let orig = std::mem::take(entries);
    let mut new_vec = Vec::with_capacity(orig.len());

    // Create a lookup for quick move
    let mut orig_wrappers: Vec<Option<FileEntry>> = orig.into_iter().map(Some).collect();

    for (_, index) in lba_map {
        if let Some(entry) = orig_wrappers[index].take() {
            new_vec.push(entry);
        }
    }

    *entries = new_vec;
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
        #[cfg(unix)]
        let (dev, ino) = (meta.dev(), meta.ino());
        #[cfg(not(unix))]
        let (dev, ino) = (0, 0);

        FileEntry::new(
            path,
            meta.len(),
            meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            dev,
            ino,
        )
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
    fn test_head_hash_only_reads_first_4096_bytes() {
        let dir = TempDir::new().unwrap();
        let mut content1 = vec![0x41; 8192]; // 'A'
        let mut content2 = vec![0x41; 8192]; // 'A'
                                             // Same first 4096 bytes
                                             // Different bytes after 4096
        content2[4097] = 0x42; // 'B'

        let file1 = create_test_file(&dir, "head1.dat", &content1);
        let file2 = create_test_file(&dir, "head2.dat", &content2);

        let hash1 = partial_hash_file(&file1).unwrap();
        let hash2 = partial_hash_file(&file2).unwrap();

        assert_eq!(
            hash1, hash2,
            "Headers should be identical even if content after 4KB differs"
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

        let hash1 = full_hash_file(&create_file_entry(file1.clone()), None).unwrap();
        let hash2 = full_hash_file(&create_file_entry(file2.clone()), None).unwrap();

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

        let hash1 = full_hash_file(&create_file_entry(file1.clone()), None).unwrap();
        let hash2 = full_hash_file(&create_file_entry(file2.clone()), None).unwrap();

        assert_ne!(
            hash1, hash2,
            "Different files should have different full hashes"
        );
    }

    #[test]
    fn test_head_hash_differs_from_full_for_large_files() {
        let dir = TempDir::new().unwrap();
        // Create a file larger than 4096 bytes
        let file = create_sized_file(&dir, "large.dat", 8192);

        let partial = partial_hash_file(&file).unwrap();
        let full = full_hash_file(&create_file_entry(file.clone()), None).unwrap();

        assert_ne!(
            partial, full,
            "Head and full hashes should differ for files > 4KB"
        );
    }

    #[test]
    fn test_full_hash_same_as_partial_for_small_files() {
        let dir = TempDir::new().unwrap();
        // Small file (say 100 bytes) should have same head and full hash
        let file = create_sized_file(&dir, "small.dat", 100);

        let partial = partial_hash_file(&file).unwrap();
        let full = full_hash_file(&create_file_entry(file.clone()), None).unwrap();

        assert_eq!(
            partial, full,
            "Head and full hashes should be same for files < 4KB"
        );
    }

    #[test]
    fn test_tail_hash_different_for_different_tails() {
        let dir = TempDir::new().unwrap();
        let mut content1 = vec![0; 8192];
        let mut content2 = vec![0; 8192];
        content1[8191] = 1;
        content2[8191] = 2;

        let file1 = create_test_file(&dir, "f1.dat", &content1);
        let file2 = create_test_file(&dir, "f2.dat", &content2);

        // Heads are same (all zeros)
        assert_eq!(
            partial_hash_file(&file1).unwrap(),
            partial_hash_file(&file2).unwrap()
        );
        // Tails are different
        assert_ne!(
            tail_hash_file(&file1).unwrap(),
            tail_hash_file(&file2).unwrap()
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
                FileEntry::new(dup1.clone(), 200, std::time::SystemTime::now(), 0, 0),
                FileEntry::new(dup2.clone(), 200, std::time::SystemTime::now(), 0, 0),
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
                vec![FileEntry::new(
                    path,
                    i as u64 * 100,
                    std::time::SystemTime::now(),
                    0,
                    0,
                )],
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
            create_file_entry(file3.clone()),
        ];
        let duplicates = find_duplicates_with_hasher_cache(potential, None).unwrap();

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
            create_file_entry(file2.clone()),
        ];
        let duplicates = find_duplicates_with_hasher_cache(potential, None).unwrap();

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
        let duplicates = find_duplicates_with_hasher_cache(potential, None).unwrap();
        assert!(duplicates.is_empty());
    }

    #[test]
    fn test_find_duplicates_single_file() {
        let dir = TempDir::new().unwrap();
        let file = create_test_file(&dir, "single.txt", b"Only one file");

        let potential = vec![create_file_entry(file)];
        let duplicates = find_duplicates_with_hasher_cache(potential, None).unwrap();

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
                create_file_entry(file3.clone()),
            ],
        );

        let (count, size_saved) = process_duplicates(duplicates, false, false, false).unwrap();

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
                create_file_entry(file2.clone()),
            ],
        );

        let (count, _) = process_duplicates(duplicates, true, false, false).unwrap();

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
        let (count, size_saved) = process_duplicates(duplicates, false, false, false).unwrap();

        assert_eq!(count, 0);
        assert_eq!(size_saved, 0);
    }

    #[test]
    fn test_signature_cache_cuckoo() {
        use tempfile::NamedTempFile;
        // Create a temp file for the db
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Open cache
        let cache = SignatureCache::open(path).expect("Failed to open cache");

        // Set a value
        let dev = 1;
        let ino = 100;
        let mtime = std::time::SystemTime::UNIX_EPOCH;
        let size = 1024;
        let hash = "deadbeef";

        cache
            .set(dev, ino, mtime, size, hash)
            .expect("Failed to set cache");

        // Get it back (Hit)
        let result = cache.get(dev, ino, mtime, size);
        assert_eq!(result, Some(hash.to_string()));

        // Check miss (different ino)
        let result_miss = cache.get(dev, 101, mtime, size);
        assert_eq!(result_miss, None);

        // Re-open cache to check persistence and filter repopulation
        drop(cache);
        let cache2 = SignatureCache::open(path).expect("Failed to repoen cache");

        // Check hit again (should be in filter after repopulation)
        let result2 = cache2.get(dev, ino, mtime, size);
        assert_eq!(result2, Some(hash.to_string()));
    }
}
