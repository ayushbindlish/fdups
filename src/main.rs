use std::collections::HashMap;
use std::env;
use std::fs::{self, metadata, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use walkdir::WalkDir;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

fn main() {
    let args: Vec<String> = env::args().collect();
    let delete = args.contains(&String::from("--delete"));
    let path = args.get(1).expect("Missing directory argument");

    let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();

    for entry in WalkDir::new(path) {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            let size = entry.metadata().unwrap().len();
            let file_list = files_by_size.entry(size).or_insert_with(Vec::new);
            file_list.push(entry.into_path());
        }
    }

    let mut potential_duplicates: Vec<PathBuf> = Vec::new();

    for (_, files) in files_by_size {
        if files.len() > 1 {
            potential_duplicates.extend(files);
        }
    }

    let mut duplicates: HashMap<String, Vec<PathBuf>> = HashMap::new();

    for file_path in potential_duplicates {
        let hash = hash_file(&file_path).unwrap();
        let file_list = duplicates.entry(hash).or_insert_with(Vec::new);
        file_list.push(file_path);
    }

    let mut duplicate_count = 0;
    let mut size_saved = 0;

    for (hash, files) in duplicates {
        if files.len() > 1 {
            duplicate_count += files.len() - 1;
            println!("Found {} files with hash {}:", files.len(), hash);
            for (i, file) in files.iter().enumerate() {
                if i == 0 {
                    println!("  - {} [Original]", file.display());
                } else {
                    let file_size = metadata(file).unwrap().len();
                    size_saved += file_size as usize;

                    if delete {
                        let mut permissions = metadata(file).unwrap().permissions();
                        permissions.set_mode(0o644);
                        fs::set_permissions(file, permissions).unwrap();
                        fs::remove_file(file).unwrap();
                        println!("  - {} [Deleted]", file.display());
                    } else {
                        println!("  - {} [Duplicate]", file.display());
                    }
                }
            }
        }
    }

    println!("\n{} duplicates found.", duplicate_count);
    println!("{} bytes saved by deleting duplicates.", size_saved);
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
