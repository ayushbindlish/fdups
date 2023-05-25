# Fdups

Fdups is a Rust-based command-line tool and library for detecting duplicate files within a specified directory. It leverages the power and performance of Rust to quickly and efficiently find duplicate files, providing both a binary for direct use and a library for integration into other projects.

<!-- TOC -->
* [Fdups](#fdups)
  * [Features](#features)
  * [Installation](#installation)
  * [Usage](#usage)
    * [Binary](#binary)
    * [Library](#library)
  * [License](#license)
  * [Contributing](#contributing)
<!-- TOC -->

## Features

- Fast and efficient duplicate file detection
- Supports recursive search through subdirectories
- Provides a binary for direct usage
- Offers a library for easy integration into other Rust projects
- Cross-platform compatibility


## Installation

To install Fdups, you need to have Rust installed on your system. If you don't have Rust, follow the instructions on the official Rust website.

Once you have Rust installed, clone this repository:
```rust
git clone https://github.com/ayushbindlish/fdups.git
cd fdups
```

Build and install the binary:

```bash
cargo build --release
cargo install --path .
```

## Usage
### Binary
To use the Fdups binary, run the following command:
```bash
fdups /path/to/directory
```
This will start the duplicate file search in the specified directory, including its subdirectories. The output will be a list of duplicate files grouped by their content.


### Library
To use the Fdups library in your own Rust project, add it as a dependency in your `Cargo.toml` file:

```rust
[dependencies]
fdups = { git = "https://github.com/ayushbindlish/fdups.git" }
```

Then, in your Rust source code, import the `fdups` crate and use its `find_duplicates` function:

```rust
use fdups::find_duplicates;

fn main() {
    let path = "/path/to/directory";
    let duplicates = find_duplicates(path).unwrap();
    
    for (hash, files) in duplicates {
        println!("Duplicate files (hash: {}):", hash);
        for file in files {
            println!("\t- {}", file.display());
        }
    }
}
```

## License
This project is licensed under the MIT OR Apache-2.0 License. See LICENSE-APACHE and LICENSE-MIT files for details.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests, and we'll review them as soon as possible.
