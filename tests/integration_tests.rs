//! End-to-end integration tests for fdups
//!
//! These tests exercise the full workflow of the duplicate detection library,
//! testing realistic scenarios with actual file system operations.

use fdups::{
    find_duplicates_with_hasher_cache, find_potential_duplicates, group_files_by_size,
    process_duplicates,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Creates a file with the specified content
fn create_file(dir: &TempDir, path: &str, content: &[u8]) -> PathBuf {
    let file_path = dir.path().join(path);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = File::create(&file_path).unwrap();
    file.write_all(content).unwrap();
    file_path
}

/// Runs the full duplicate detection pipeline (without the logger issue)
fn find_duplicates(path: &str) -> fdups::DuplicateReport {
    let (files_by_size, total_files, total_size) =
        group_files_by_size(path, true, true, true, true).unwrap();
    let potential_duplicates = find_potential_duplicates(files_by_size);
    let duplicates = find_duplicates_with_hasher_cache(potential_duplicates, None).unwrap();
    let (duplicate_count, size_saved) = process_duplicates(duplicates, false, false, false).unwrap();
    fdups::DuplicateReport {
        total_files,
        total_size_bytes: total_size,
        duplicate_count,
        size_saved_bytes: size_saved,
    }
}

/// Runs the full pipeline with delete enabled
fn find_and_delete_duplicates(path: &str) -> fdups::DuplicateReport {
    let (files_by_size, total_files, total_size) =
        group_files_by_size(path, true, true, true, true).unwrap();
    let potential_duplicates = find_potential_duplicates(files_by_size);
    let duplicates = find_duplicates_with_hasher_cache(potential_duplicates, None).unwrap();
    let (duplicate_count, size_saved) = process_duplicates(duplicates, true, false, false).unwrap();
    fdups::DuplicateReport {
        total_files,
        total_size_bytes: total_size,
        duplicate_count,
        size_saved_bytes: size_saved,
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_e2e_no_duplicates() {
    let dir = TempDir::new().unwrap();

    // Create 5 unique files with different content
    for i in 0..5 {
        let content = format!("Unique content for file {}", i);
        create_file(&dir, &format!("file_{}.txt", i), content.as_bytes());
    }

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(
        report.duplicate_count, 0,
        "Should find no duplicates among unique files"
    );
}

#[test]
fn test_e2e_exact_duplicates() {
    let dir = TempDir::new().unwrap();
    let content = b"This is duplicate content shared by multiple files.";

    // Create 4 identical files
    for i in 0..4 {
        create_file(&dir, &format!("dup_{}.txt", i), content);
    }

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    // 4 identical files = 3 duplicates (1 original + 3 dups)
    assert_eq!(
        report.duplicate_count, 3,
        "Should find 3 duplicates among 4 identical files"
    );
    assert_eq!(
        report.size_saved_bytes,
        3 * content.len() as u128,
        "Size saved should be 3 * file size"
    );
}

#[test]
fn test_e2e_same_size_different_content() {
    let dir = TempDir::new().unwrap();

    // Create files with same size but different content
    create_file(&dir, "a.txt", b"abcdefgh"); // 8 bytes
    create_file(&dir, "b.txt", b"12345678"); // 8 bytes
    create_file(&dir, "c.txt", b"ABCDEFGH"); // 8 bytes

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(
        report.duplicate_count, 0,
        "Files with same size but different content should not be duplicates"
    );
}

#[test]
fn test_e2e_partial_hash_collision() {
    let dir = TempDir::new().unwrap();

    // Create files with identical first 512 bytes but different content after
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
        content1[i] = 0xAA;
        content2[i] = 0x55;
    }

    create_file(&dir, "partial1.dat", &content1);
    create_file(&dir, "partial2.dat", &content2);

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(
        report.duplicate_count, 0,
        "Files with same partial hash but different full content should NOT be duplicates"
    );
}

#[test]
fn test_e2e_empty_directory() {
    let dir = TempDir::new().unwrap();

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.total_size_bytes, 0);
    assert_eq!(report.size_saved_bytes, 0);
}

#[test]
fn test_e2e_nested_directories() {
    let dir = TempDir::new().unwrap();
    let content = b"Duplicate content in nested dirs";

    // Create duplicates across nested subdirectories
    create_file(&dir, "root.txt", content);
    create_file(&dir, "level1/a.txt", content);
    create_file(&dir, "level1/level2/b.txt", content);
    create_file(&dir, "other/c.txt", content);

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    // 4 identical files = 3 duplicates
    assert_eq!(
        report.duplicate_count, 3,
        "Should find duplicates across nested directories"
    );
}

#[test]
fn test_e2e_delete_removes_duplicates() {
    let dir = TempDir::new().unwrap();
    let content = b"Content to be deleted";

    // Create 3 identical files
    let file1 = create_file(&dir, "original.txt", content);
    let file2 = create_file(&dir, "dup1.txt", content);
    let file3 = create_file(&dir, "dup2.txt", content);

    // Verify all files exist before delete
    assert!(file1.exists());
    assert!(file2.exists());
    assert!(file3.exists());

    let path = dir.path().to_str().unwrap();
    let report = find_and_delete_duplicates(path);

    assert_eq!(report.duplicate_count, 2, "Should report 2 duplicates");

    // Count remaining files
    let remaining: Vec<_> = [file1, file2, file3]
        .into_iter()
        .filter(|f| f.exists())
        .collect();
    assert_eq!(
        remaining.len(),
        1,
        "Only 1 file should remain after deleting duplicates"
    );
}

#[test]
fn test_e2e_mixed_scenario() {
    let dir = TempDir::new().unwrap();

    // Create a realistic mixed scenario:
    // - Some unique files
    // - Some duplicates
    // - Some files with same size but different content

    // Unique files
    create_file(&dir, "unique1.txt", b"Unique content 1");
    create_file(&dir, "unique2.txt", b"Unique content 2 - longer");
    create_file(&dir, "unique3.txt", b"U3");

    // Duplicate set 1: 3 files
    let dup1_content = b"Duplicate set one content";
    create_file(&dir, "dup1_a.txt", dup1_content);
    create_file(&dir, "dup1_b.txt", dup1_content);
    create_file(&dir, "dup1_c.txt", dup1_content);

    // Duplicate set 2: 2 files
    let dup2_content = b"Different duplicate set";
    create_file(&dir, "set2/dup2_a.txt", dup2_content);
    create_file(&dir, "set2/dup2_b.txt", dup2_content);

    // Same size, different content (should NOT be duplicates)
    create_file(&dir, "same_size_1.txt", b"AAAAAAAA");
    create_file(&dir, "same_size_2.txt", b"BBBBBBBB");

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    // Dup set 1: 2 duplicates (1 original + 2 dups)
    // Dup set 2: 1 duplicate (1 original + 1 dup)
    // Total: 3 duplicates
    assert_eq!(
        report.duplicate_count, 3,
        "Should find 3 duplicates in mixed scenario"
    );
}

#[test]
fn test_e2e_large_files() {
    let dir = TempDir::new().unwrap();

    // Create larger files (1MB each)
    let size = 1024 * 1024;
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

    create_file(&dir, "large1.dat", &content);
    create_file(&dir, "large2.dat", &content);

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(
        report.duplicate_count, 1,
        "Should find 1 duplicate for 2 identical large files"
    );
    assert_eq!(
        report.size_saved_bytes, size as u128,
        "Size saved should be 1MB"
    );
}

#[test]
fn test_e2e_single_file() {
    let dir = TempDir::new().unwrap();

    create_file(&dir, "only_one.txt", b"Just one file");

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    assert_eq!(
        report.duplicate_count, 0,
        "Single file cannot have duplicates"
    );
}

#[test]
fn test_e2e_two_empty_files() {
    let dir = TempDir::new().unwrap();

    // Empty files are technically duplicates of each other
    create_file(&dir, "empty1.txt", b"");
    create_file(&dir, "empty2.txt", b"");

    let path = dir.path().to_str().unwrap();
    let report = find_duplicates(path);

    // Two empty files should be detected as duplicates
    assert_eq!(
        report.duplicate_count, 1,
        "Two empty files should be duplicates"
    );
}
