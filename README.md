# R-Squared Rust Library

A pure Rust implementation of the R-Squared blockchain library, providing cryptographic operations, blockchain transaction handling, data serialization, and storage capabilities.

## Features

- **🔐 ECC Module**: Elliptic curve cryptography, key management, and digital signatures
- **⛓️ Chain Module**: Blockchain operations, transaction building, and chain state management  
- **📦 Serializer Module**: Data serialization and deserialization for blockchain operations
- **💾 Storage Module**: Pluggable storage backends including S3, IPFS, and memory adapters

## Optional Features

- `wasm`: WebAssembly support for browser environments
- `async`: Asynchronous operations support
- `s3`: AWS S3 storage backend
- `ipfs`: IPFS storage backend
- `serde_support`: Serde serialization support

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
r-squared-rust = "0.1.0"

# Enable optional features as needed
r-squared-rust = { version = "0.1.0", features = ["async", "s3", "serde_support"] }
```

## Quick Start

```rust
use r_squared_rust::prelude::*;

fn main() -> Result<()> {
    // Generate a new private key
    let private_key = PrivateKey::generate()?;
    let public_key = private_key.public_key();
    
    println!("Generated public key: {:?}", public_key);
    
    // Create a transaction builder
    let mut tx_builder = TransactionBuilder::new();
    
    // Use memory storage adapter
    let storage = MemoryAdapter::new();
    storage.store("my_key", b"my_data")?;
    let data = storage.retrieve("my_key")?;
    
    println!("Retrieved data: {:?}", data);
    
    Ok(())
}
```

## Architecture

The library is organized into four main modules:

### ECC (Elliptic Curve Cryptography)
- Private/public key generation and management
- Digital signature creation and verification
- Address generation and validation
- AES encryption/decryption
- Hash functions (SHA-256, SHA-3, RIPEMD)

### Chain
- Transaction building and signing
- Blockchain state management
- Object ID handling
- Chain validation utilities
- Account login functionality

### Serializer
- Binary data serialization/deserialization
- Fast parsing utilities
- Type definitions and operations
- Template-based serialization

### Storage
- Pluggable storage adapter interface
- Memory storage adapter
- AWS S3 storage adapter (with `s3` feature)
- IPFS storage adapter (with `ipfs` feature)
- Personal data management utilities

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `std` | Standard library support (enabled by default) | - |
| `async` | Asynchronous operations | `tokio`, `futures` |
| `s3` | AWS S3 storage backend | `aws-sdk-s3`, `aws-config` |
| `ipfs` | IPFS storage backend | `ipfs-api-backend-hyper` |
| `serde_support` | Serde serialization | `serde`, `serde_json` |

## Examples

### Key Generation and Signing

```rust
use r_squared_rust::ecc::{PrivateKey, hash};

// Generate keys
let private_key = PrivateKey::generate()?;
let public_key = private_key.public_key();

// Hash and sign data
let data = b"Hello, R-Squared!";
let hash = hash::sha256(data);
// Signing functionality will be implemented in future versions
```

### Storage Operations

```rust
use r_squared_rust::storage::{MemoryAdapter, StorageAdapter};

let storage = MemoryAdapter::new();

// Store data
storage.store("user:123", b"user data")?;

// Retrieve data
let data = storage.retrieve("user:123")?;

// Check existence
if storage.exists("user:123")? {
    println!("User data exists");
}

// Delete data
storage.delete("user:123")?;
```

### Transaction Building

```rust
use r_squared_rust::chain::{TransactionBuilder, Operation};

let mut builder = TransactionBuilder::new();

let operation = Operation {
    op_type: "transfer".to_string(),
    data: vec![/* operation data */],
};

builder.add_operation(operation)?;
let transaction = builder.build()?;
```

## Development

### Building

```bash
# Build with default features
cargo build

# Build with all features
cargo build --all-features

# Build for WebAssembly
cargo build --target wasm32-unknown-unknown --features wasm
```

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run tests with all features
cargo test --all-features
```

### Benchmarking

```bash
# Run benchmarks
cargo bench
```

## Compatibility

- **Rust Version**: 1.70 or higher
- **Platforms**: Linux, macOS, Windows
- **No-std**: Supported (disable `std` feature)

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This library is a Rust port of the original [R-Squared-js](https://github.com/R-Squared-Project/R-Squared-js) JavaScript library, maintaining API compatibility while leveraging Rust's performance and safety features.

## Roadmap

- [ ] Complete ECC implementation with full signing/verification
- [ ] Implement comprehensive serialization formats
- [ ] Add more storage backends (Redis, PostgreSQL)
- [ ] WebAssembly bindings and npm package
- [ ] Performance optimizations and benchmarks
- [ ] Complete API documentation
- [ ] Migration tools from JavaScript version