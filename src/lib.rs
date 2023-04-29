// src/lib.rs
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, metadata, File};
use std::io::{self, Read};
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use ignore::WalkBuilder;
use rayon::prelude::*;

use lru::LruCache;

type ChannelData = (String, PathBuf);

pub fn remove_duplicates(path: &str, delete: bool) -> Result<(usize, usize), Box<dyn Error>> {
    let cache_size: NonZeroUsize = NonZeroUsize::new(16384).unwrap();

    let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new(); // Create a hash map to store files grouped by size

    // Use WalkBuilder to create a directory iterator that respects .gitignore files
    let walker = WalkBuilder::new(path)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build();

    for entry in walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().unwrap().is_file())
    {
        // Walk the directory tree, ignoring files and directories specified in .gitignore
        let size = entry.metadata()?.len(); // Get the file size
        let file_list = files_by_size.entry(size).or_insert_with(Vec::new); // Get or create a vector of files with this size
        file_list.push(entry.path().to_owned()); // Add the file path to the vector
    }

    let mut potential_duplicates: Vec<PathBuf> = Vec::new(); // Create a vector to store potential duplicate files

    for (_, files) in files_by_size {
        // For each size of files
        if files.len() > 1 {
            // If there's more than one file with this size
            potential_duplicates.extend(files); // Add all files to the potential duplicates vector
        }
    }

    let mut duplicates: HashMap<String, Vec<PathBuf>> = HashMap::new(); // Create a hash map to store duplicates grouped by hash
    let hasher_cache: Arc<Mutex<LruCache<PathBuf, String>>> =
        Arc::new(Mutex::new(LruCache::new(cache_size)));

    let (tx, rx): (Sender<ChannelData>, Receiver<ChannelData>) = channel(); // Create a message passing channel to send hashes and file paths between threads

    potential_duplicates
        .into_par_iter()
        .for_each_with(tx.clone(), |tx, file_path| {
            let hasher_cache = Arc::clone(&hasher_cache);
            let mut hasher_cache = hasher_cache.lock().unwrap();
            if let Some(cached_hash) = hasher_cache.get(&file_path) {
                tx.send((cached_hash.clone(), file_path)).unwrap();
            } else if let Ok(hash) = hash_file(&file_path) {
                hasher_cache.put(file_path.clone(), hash.clone());
                tx.send((hash, file_path)).unwrap(); // Send the hash and file path to the receiver
            }
        });

    drop(tx); // Drop the sender so the receiver knows there are no more messages coming

    for (hash, file_path) in rx {
        // For each received message containing a hash and file path
        let file_list = duplicates.entry(hash).or_insert_with(Vec::new); // Get or create a vector of files with this hash
        file_list.push(file_path); // Add the file path to the vector
    }

    let mut duplicate_count = 0; // Create a variable to count the number of duplicates
    let mut size_saved = 0; // Create a variable to keep track of the amount of disk space saved

    for (hash, mut files) in duplicates {
        // For each hash of duplicate files
        if files.len() > 1 {
            // If there's more than one file with this hash
            duplicate_count += files.len() - 1;

            // Sort files by creation time (oldest first)
            files.sort_by_key(|file| {
                let metadata = metadata(file).unwrap();
                metadata
                    .created()
                    .unwrap_or_else(|_| metadata.modified().unwrap())
            });

            println!("\n\n\nFound {} files with hash {}:\n", files.len(), hash);
            for (i, file) in files.iter().enumerate() {
                if i == 0 {
                    println!("  - {} [Original]\n", file.display());
                } else {
                    let file_size = metadata(file)?.len();
                    size_saved += file_size as usize;

                    if delete {
                        #[cfg(unix)]
                        {
                            let mut permissions = metadata(file)?.permissions();
                            permissions.set_mode(0o644);
                            fs::set_permissions(file, permissions)?;
                        }
                        fs::remove_file(file)?;
                        println!("  - {} [Deleted]\n", file.display());
                    } else {
                        println!("  - {} [Duplicate]\n", file.display());
                    }
                }
            }
        }
    }

    Ok((duplicate_count, size_saved))
}

fn hash_file(file_path: &PathBuf) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.input(&buffer[..bytes_read]);
    }

    Ok(hasher.result_str())
}
