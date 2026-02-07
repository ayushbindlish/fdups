//! Benchmarks for fdups - measuring performance baselines before optimization
//!
//! Run with: cargo bench
//! View reports at: target/criterion/report/index.html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fdups::{
    find_duplicates_with_hasher_cache, find_potential_duplicates, full_hash_file,
    group_files_by_size, partial_hash_file,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
// These create controlled test environments so benchmarks are reproducible.

/// Creates a file with deterministic content of the specified size.
/// Using a pattern (i % 256) ensures the content is predictable yet varied.
fn create_file_with_size(dir: &TempDir, name: &str, size: usize) -> PathBuf {
    let file_path = dir.path().join(name);
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let mut file = File::create(&file_path).unwrap();
    file.write_all(&content).unwrap();
    file_path
}

/// Creates N files that are exact duplicates (same content).
/// This simulates the core use case of fdups.
fn create_duplicate_files(dir: &TempDir, count: usize, size: usize) -> Vec<PathBuf> {
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let mut paths = Vec::new();
    for i in 0..count {
        let file_path = dir.path().join(format!("dup_{}.dat", i));
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&content).unwrap();
        paths.push(file_path);
    }
    paths
}

/// Creates files that share the same first 512 bytes but differ afterwards.
/// This tests the partial hash collision handling - a critical code path
/// where files with matching partial hashes need full hash comparison.
fn create_partial_hash_collision_files(dir: &TempDir, count: usize) -> Vec<PathBuf> {
    // Same 512-byte prefix for all files (matches BUFFER_SIZE in lib.rs)
    let common_prefix: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    let mut paths = Vec::new();
    for i in 0..count {
        let file_path = dir.path().join(format!("collision_{}.dat", i));
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&common_prefix).unwrap();
        // Different suffix for each file - this is what makes them NOT duplicates
        let suffix: Vec<u8> = (0..1024).map(|j| ((i + j) % 256) as u8).collect();
        file.write_all(&suffix).unwrap();
        paths.push(file_path);
    }
    paths
}

// ============================================================================
// BENCHMARK: partial_hash_file
// ============================================================================
// WHAT: Measures time to hash only the first 512 bytes of a file.
// WHY: This is the first filter in duplicate detection. It's called for EVERY
//      potential duplicate, so its performance directly impacts overall speed.
// KEY INSIGHT: The time should be nearly constant regardless of file size
//              since we only read 512 bytes. If it scales with file size,
//              there's a bug (maybe opening/closing overhead).

fn bench_partial_hash_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("partial_hash_file");

    // Test with 1KB, 1MB, and 10MB files
    // Throughput is set to file size to calculate MB/s, but we expect
    // the actual throughput to be misleading since we only hash 512 bytes
    for size in [1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let dir = TempDir::new().unwrap();
        let file_path = create_file_with_size(&dir, "test.dat", *size);

        group.throughput(Throughput::Bytes(512)); // We only hash 512 bytes
        group.bench_with_input(
            BenchmarkId::new("file_size", human_size(*size)),
            size,
            |b, _| b.iter(|| partial_hash_file(black_box(&file_path))),
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: full_hash_file
// ============================================================================
// WHAT: Measures time to hash an entire file using Blake2b.
// WHY: This is called only when partial hashes match, so it's less frequent
//      but more expensive. This is where BUFFER_SIZE matters most.
// KEY INSIGHT: With 512-byte buffer, a 10MB file requires ~20,000 read() calls.
//              Increasing buffer to 64KB would reduce this to ~160 calls.

fn bench_full_hash_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_hash_file");

    for size in [1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let dir = TempDir::new().unwrap();
        let file_path = create_file_with_size(&dir, "test.dat", *size);

        // Throughput shows actual hashing speed in MB/s
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("file_size", human_size(*size)),
            size,
            |b, _| b.iter(|| full_hash_file(black_box(&file_path))),
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: group_files_by_size
// ============================================================================
// WHAT: Measures directory traversal and file metadata collection.
// WHY: This is the first step - grouping files by size before any hashing.
//      It involves filesystem operations (stat() calls) which can be slow.
// KEY INSIGHT: Performance here depends on filesystem type (SSD vs HDD),
//              directory structure depth, and number of files.

fn bench_group_files_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("group_files_by_size");

    for file_count in [10, 100, 500].iter() {
        let dir = TempDir::new().unwrap();

        // Create files with varying sizes to simulate realistic scenario
        for i in 0..*file_count {
            create_file_with_size(&dir, &format!("file_{}.dat", i), 1024 + i * 10);
        }

        let path_str = dir.path().to_str().unwrap().to_string();

        group.bench_with_input(
            BenchmarkId::new("file_count", file_count),
            file_count,
            |b, _| b.iter(|| group_files_by_size(black_box(&path_str), true, true, true, true)),
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: find_potential_duplicates
// ============================================================================
// WHAT: Measures filtering of size groups to find potential duplicates.
// WHY: This is a pure CPU operation (no I/O) that filters out unique-sized files.
// KEY INSIGHT: This should be very fast. If it's not, there's a data structure issue.

fn bench_find_potential_duplicates(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_potential_duplicates");

    for group_count in [100, 500, 1000].iter() {
        // Simulate realistic data: most files have unique sizes
        let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();

        for i in 0..*group_count {
            let size = (1000 + i * 100) as u64;
            // 1 in 5 groups has potential duplicates (2+ files with same size)
            let files_in_group = if i % 5 == 0 { 3 } else { 1 };
            let paths: Vec<PathBuf> = (0..files_in_group)
                .map(|j| PathBuf::from(format!("/fake/path/file_{}_{}.dat", i, j)))
                .collect();
            files_by_size.insert(size, paths);
        }

        group.bench_with_input(
            BenchmarkId::new("size_groups", group_count),
            group_count,
            |b, _| b.iter(|| find_potential_duplicates(black_box(files_by_size.clone()))),
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: find_duplicates_with_hasher_cache
// ============================================================================
// WHAT: Measures the core duplicate detection algorithm.
// WHY: This is where most of the work happens - partial hashing, grouping,
//      and full hashing for verification.
// KEY INSIGHT: This benchmark reveals the cost of:
//      1. Parallel partial hashing (should scale with CPU cores)
//      2. Full hash comparisons when partial hashes match
//      3. The overhead of DashMap concurrent access

fn bench_find_duplicates_with_hasher_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_duplicates_with_hasher_cache");

    // Scenario 1: Actual duplicates
    // All files are identical - partial hash matches, full hash matches
    for dup_count in [5, 20, 50].iter() {
        let dir = TempDir::new().unwrap();
        let paths = create_duplicate_files(&dir, *dup_count, 4096);

        group.bench_with_input(
            BenchmarkId::new("true_duplicates", dup_count),
            dup_count,
            |b, _| b.iter(|| find_duplicates_with_hasher_cache(black_box(paths.clone()))),
        );
    }

    // Scenario 2: Partial hash collisions (worst case for current algorithm)
    // Files have same 512-byte prefix but different content
    // This forces full hash computation for EVERY file
    for count in [5, 20].iter() {
        let dir = TempDir::new().unwrap();
        let paths = create_partial_hash_collision_files(&dir, *count);

        group.bench_with_input(
            BenchmarkId::new("partial_collisions", count),
            count,
            |b, _| b.iter(|| find_duplicates_with_hasher_cache(black_box(paths.clone()))),
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: Full Pipeline (Component-Based)
// ============================================================================
// WHAT: End-to-end benchmark of the duplicate detection pipeline.
// WHY: Measures real-world performance including all stages.
// NOTE: We call component functions directly instead of find_remove_duplicates
//       because the latter has a bug - it calls env_logger::Builder::init()
//       which panics when called multiple times. This is a real bug to fix!
// KEY INSIGHT: This reveals the combined effect of all optimizations/issues.

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.sample_size(10); // Fewer samples since these are slower

    // Scenario: Mixed directory with some duplicates
    {
        let dir = TempDir::new().unwrap();

        // 50 unique files (different sizes)
        for i in 0..50 {
            create_file_with_size(&dir, &format!("unique_{}.dat", i), 1024 + i * 100);
        }

        // 3 sets of duplicates (5 files each = 12 duplicate files)
        for set in 0..3 {
            let content: Vec<u8> = (0..2048).map(|j| ((set * 10 + j) % 256) as u8).collect();
            for i in 0..5 {
                let file_path = dir.path().join(format!("dup_set{}_{}.dat", set, i));
                let mut file = File::create(&file_path).unwrap();
                file.write_all(&content).unwrap();
            }
        }

        let path_str = dir.path().to_str().unwrap().to_string();

        // Benchmark the full workflow using component functions
        group.bench_function("65_files_15_dups", |b| {
            b.iter(|| {
                let (files_by_size, _, _) =
                    group_files_by_size(black_box(&path_str), true, true, true, true).unwrap();
                let potential_duplicates = find_potential_duplicates(files_by_size);
                let _duplicates = find_duplicates_with_hasher_cache(potential_duplicates).unwrap();
                // We skip process_duplicates since it does I/O printing
            })
        });
    }

    // Scenario: Nested directories (tests WalkBuilder performance)
    {
        let dir = TempDir::new().unwrap();

        for subdir_idx in 0..5 {
            let subdir = dir.path().join(format!("subdir_{}", subdir_idx));
            fs::create_dir(&subdir).unwrap();

            for i in 0..20 {
                let file_path = subdir.join(format!("file_{}.dat", i));
                let content: Vec<u8> = (0..1024)
                    .map(|j| ((subdir_idx * 100 + i + j) % 256) as u8)
                    .collect();
                let mut file = File::create(&file_path).unwrap();
                file.write_all(&content).unwrap();
            }
        }

        let path_str = dir.path().to_str().unwrap().to_string();

        group.bench_function("nested_100_files", |b| {
            b.iter(|| {
                let (files_by_size, _, _) =
                    group_files_by_size(black_box(&path_str), true, true, true, true).unwrap();
                let potential_duplicates = find_potential_duplicates(files_by_size);
                let _duplicates = find_duplicates_with_hasher_cache(potential_duplicates).unwrap();
            })
        });
    }

    group.finish();
}

// ============================================================================
// UTILITY
// ============================================================================

fn human_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{}MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

// ============================================================================
// CRITERION SETUP
// ============================================================================

criterion_group!(
    benches,
    bench_partial_hash_file,
    bench_full_hash_file,
    bench_group_files_by_size,
    bench_find_potential_duplicates,
    bench_find_duplicates_with_hasher_cache,
    bench_full_pipeline,
);

criterion_main!(benches);
