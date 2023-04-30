use blake2::{Blake2b, Digest};
use dashmap::DashMap;
use generic_array::{typenum::U64, GenericArray};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, metadata, File};
use std::io::BufReader;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

/// Define the type for the data sent through the channel
type ChannelData = (String, PathBuf);

/// Use a constant for file buffer size, making it easier to modify if needed
pub const BUFFER_SIZE: usize = 512;

/// U64 represents an array length of 64 elements for blake2b
type OutSize = U64;

/// Finds duplicates among potential duplicate.
///
/// Given a vector of potential duplicate files, this function hashes each file and groups
/// them together based on their hash. It uses hashmap(dashmap) as a cache to store the hashes of the files
/// to avoid re-hashing files that have already been hashed. The result is a hash map where
/// each key is a hash and the corresponding value is a vector of file paths that have that hash.
///
/// # Arguments
///
/// * potential_duplicates - A vector of PathBufs representing potential duplicate files.
///
/// # Returns
///
/// A Result containing a hash map where each key is a hash and the corresponding value is
/// a vector of file paths that have that hash, or an error if one occurs.
///
/// # Examples
///``` no_run
/// use std::path::PathBuf;
/// use fdups::find_duplicates_with_hasher_cache;
/// let potential_duplicates = vec![
/// PathBuf::from("file1.txt"),
/// PathBuf::from("file2.txt"),
/// PathBuf::from("file3.txt")
/// ];
/// let duplicates = find_duplicates_with_hasher_cache(potential_duplicates).unwrap();
/// assert_eq!(duplicates.len(), 0);
/// ```
pub fn find_duplicates_with_hasher_cache(
    potential_duplicates: Vec<PathBuf>,
) -> Result<HashMap<String, Vec<PathBuf>>, Box<dyn Error>> {
    let mut duplicates: HashMap<String, Vec<PathBuf>> = HashMap::new(); // Create a hash map to store files grouped by size
                                                                        // Use DashMap for caching hashes
    let hasher_cache: Arc<DashMap<PathBuf, String>> = Arc::new(DashMap::new());

    let (tx, rx): (Sender<ChannelData>, Receiver<ChannelData>) = channel(); // Create a message passing channel to send hashes and file paths between threads

    potential_duplicates
        .into_par_iter()
        .for_each_with(tx.clone(), |tx, file_path| {
            // Remove Mutex locking
            if let Some(cached_hash) = hasher_cache.get(&file_path) {
                tx.send((cached_hash.clone(), file_path)).unwrap();
            } else {
                // Use partial_hash_file function
                let hash_result = partial_hash_file(&file_path);

                if let Ok(hash) = hash_result {
                    hasher_cache.insert(file_path.clone(), hash.clone());
                    tx.send((hash, file_path)).unwrap();
                }
            }
        });

    drop(tx); // Drop the sender so the receiver knows there are no more messages coming

    // Iterate through the received messages containing hashes and file paths
    for (hash, file_path) in rx {
        let file_list = duplicates.entry(hash).or_insert_with(Vec::new); // Get or create a vector of files with this hash
        if !file_list.is_empty() {
            let full_hash1 = full_hash_file(&file_path).unwrap();
            let mut is_duplicate = false;
            for dup_path in file_list.iter() {
                let full_hash2 = full_hash_file(dup_path).unwrap();
                if full_hash1 == full_hash2 {
                    is_duplicate = true;
                    break;
                }
            }
            if is_duplicate {
                file_list.push(file_path); // Add the file path to the vector
            }
        } else {
            file_list.push(file_path); // Add the file path to the vector
        }
    }
    Ok(duplicates)
}

// Create a partial_hash_file function
pub fn partial_hash_file(file_path: &PathBuf) -> io::Result<String> {
    let mut file = BufReader::new(File::open(file_path)?);

    let mut hasher = Blake2b::new();
    let mut buffer = [0; BUFFER_SIZE];
    let bytes_read = file.read(&mut buffer)?;
    hasher.update(&buffer[..bytes_read]);

    let hash: GenericArray<u8, OutSize> = hasher.finalize();
    Ok(format!("{:x}", hash))
}

/// This function groups all the files at the given path by their size.
///
/// # Arguments
///
/// * path - A string slice representing the path to search for files.
///
/// # Returns
///
/// A Result containing a HashMap that maps file sizes to vectors of PathBufs representing the file paths.
///
/// # Errors
///
/// Returns a Box<dyn Error> if there is an error accessing or reading the file metadata.
#[inline]
pub fn group_files_by_size(
    path: &str,
) -> Result<(HashMap<u64, Vec<PathBuf>>, u128), Box<dyn Error>> {
    let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut total_size_in_bytes: u128 = 0;

    let walker = WalkBuilder::new(path)
        .git_ignore(true) // respect .gitignore files
        .git_global(true) // respect global git ignore
        .git_exclude(true) // respect git exclude files
        .build();

    // Traverse the directory tree and filter out files and directories specified in .gitignore files
    for entry in walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().unwrap().is_file())
    {
        let size = entry.metadata()?.len(); // get file size
        total_size_in_bytes = size as u128;
        let file_list = files_by_size.entry(size).or_insert_with(Vec::new); // get or create a vector of files with this size
        file_list.push(entry.path().to_owned()); // add the file path to the vector
    }

    Ok((files_by_size, total_size_in_bytes))
}

/// Given a hashmap of files grouped by size, returns a vector of potential duplicate files.
///
/// # Arguments
///
/// * files_by_size - A hashmap of files grouped by size, where the key is the size of the file and the value is a vector of file paths.
///
/// # Returns
///
/// A vector of potential duplicate files, where each file appears more than once in the given hashmap.
///
/// # Examples
///
///```no_run
/// use std::collections::HashMap;
/// use std::path::PathBuf;
/// use fdups::find_potential_duplicates;
/// let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
/// files_by_size.insert(100, vec![PathBuf::from("file1.txt")]);
/// files_by_size.insert(200, vec![PathBuf::from("file2.txt"), PathBuf::from("file3.txt")]);
/// let potential_duplicates = find_potential_duplicates(files_by_size);
/// assert_eq!(potential_duplicates.len(), 2);
/// assert!(potential_duplicates.contains(&PathBuf::from("file2.txt")));
/// assert!(potential_duplicates.contains(&PathBuf::from("file3.txt")));
/// ```
pub fn find_potential_duplicates(files_by_size: HashMap<u64, Vec<PathBuf>>) -> Vec<PathBuf> {
    let mut potential_duplicates: Vec<PathBuf> = Vec::new(); // Create an empty vector to store potential duplicate files

    // Iterate through each entry in the hash map, which maps from file size to lists of paths
    for (_, files) in files_by_size {
        // If there is more than one file with the given size, add all of them to the potential duplicates list
        if files.len() > 1 {
            potential_duplicates.extend(files);
        }
    }
    // Return the list of potential duplicate files
    potential_duplicates
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
///use std::collections::HashMap;
/// use std::path::PathBuf;
/// use std::error::Error;
/// fn main() -> Result<(), Box<dyn Error>> {
/// use fdups::process_duplicates;
/// let mut files = Vec::new();
/// files.push(PathBuf::from("file1.txt"));
/// files.push(PathBuf::from("file2.txt"));
/// let mut duplicates = HashMap::new();
/// duplicates.insert("hash1".to_string(), files);
/// let (count, size) = process_duplicates(duplicates, true)?;
/// assert_eq!(count, 1);
/// assert!(size > 0);
/// Ok(())
/// }
/// ```
pub fn process_duplicates(
    duplicates: HashMap<String, Vec<PathBuf>>,
    delete: bool,
) -> Result<(usize, usize), Box<dyn Error>> {
    // Define variables to keep track of the number of duplicates and amount of disk space saved
    let mut duplicate_count = 0;
    let mut size_saved = 0;
    // Iterate through the duplicates
    for (_hash, mut files) in duplicates {
        // Check if there's more than one file with the same hash
        if files.len() > 1 {
            // Increment the duplicate count by the number of duplicate files
            duplicate_count += files.len() - 1;
            // Sort files by creation time (oldest first)
            files.sort_by_key(|file| {
                // Get the file's metadata to determine its creation time
                let metadata = metadata(file).unwrap();
                metadata
                    .created()
                    .unwrap_or_else(|_| metadata.modified().unwrap())
            });
            // Iterate through the files with the same hash
            for (i, file) in files.iter().enumerate() {
                if i == 0 {
                    // If this is the first file, print that it is the original
                    println!("  - {} [Original]\n", file.display());
                } else {
                    // Otherwise, it's a duplicate
                    // Get the size of the file to be deleted and add it to the total size saved
                    let file_size = metadata(file)?.len();
                    size_saved += file_size as usize;
                    // If delete is true, delete the file
                    if delete {
                        #[cfg(unix)]
                        {
                            // If the OS is Unix, set the file permissions to read-only before deleting
                            let mut permissions = metadata(file)?.permissions();
                            permissions.set_mode(0o644);
                            fs::set_permissions(file, permissions)?;
                        }
                        fs::remove_file(file)?;
                        println!("  - {} [Deleted]\n", file.display());
                    } else {
                        // Otherwise, print that it's a duplicate
                        println!("  - {} [Duplicate]\n", file.display());
                    }
                }
            }
        }
    }
    // Return the number of duplicates and amount of disk space saved as a tuple
    Ok((duplicate_count, size_saved))
}

/// Removes duplicate files in a directory tree.
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
/// use fdups::remove_duplicates;
///
/// let path = "/path/to/directory";
/// let (duplicate_count,total_file_sizes_in_bytes, size_saved) = remove_duplicates(path, true).unwrap();
///
/// println!("Found {} duplicates, saved {} bytes by deleting them", duplicate_count, size_saved);
/// ```
pub fn remove_duplicates(path: &str, delete: bool) -> Result<(usize, u128, usize), Box<dyn Error>> {
    let (files_by_size, total_file_sizes_in_bytes) = group_files_by_size(path)?; // group files by size
    let potential_duplicates = find_potential_duplicates(files_by_size); // get potential duplicates
    let duplicates = find_duplicates_with_hasher_cache(potential_duplicates)?; // find duplicates
    let (duplicate_count, size_saved) = process_duplicates(duplicates, delete)?; // process duplicates

    Ok((duplicate_count, total_file_sizes_in_bytes, size_saved)) // return number of duplicates and disk space saved
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

    let mut hasher = Blake2b::new(); // Create a new blake2b hasher

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
    let hash: GenericArray<u8, OutSize> = hasher.finalize();
    Ok(format!("{:x}", hash))
}
