# Getting Started with R-Squared Rust Library

## Prerequisites

- Rust (latest stable version)
- Cargo package manager
- Basic understanding of Rust programming

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
r-squared = { git = "https://github.com/your-org/r-squared-rust" }
```

## Quick Start Examples

### 1. Key Generation and Management

```rust
use r_squared::ecc::{KeyPair, Address};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new key pair
    let key_pair = KeyPair::generate()?;
    
    // Get public key
    let public_key = key_pair.public_key();
    
    // Create an address from public key
    let address = Address::from_public_key(&public_key)?;
    
    println!("Address: {}", address);
    
    Ok(())
}
```

### 2. Transaction Creation and Signing

```rust
use r_squared::chain::Transaction;
use r_squared::ecc::KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let sender_key_pair = KeyPair::generate()?;
    let recipient_key_pair = KeyPair::generate()?;
    
    // Create transaction
    let transaction = Transaction::builder()
        .from(&sender_key_pair)
        .to(&recipient_key_pair.public_key())
        .amount(100.0)
        .build()?;
    
    // Sign transaction
    let signed_transaction = transaction.sign(&sender_key_pair)?;
    
    Ok(())
}
```

### 3. Data Serialization

```rust
use r_squared::serializer::{Serializer, Format};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Serializable struct
    #[derive(Serialize, Deserialize)]
    struct User {
        name: String,
        age: u32,
    }

    let user = User {
        name: "Alice".to_string(),
        age: 30,
    };

    // Serialize to different formats
    let json_data = Serializer::serialize(&user, Format::Json)?;
    let binary_data = Serializer::serialize(&user, Format::Binary)?;
    
    // Deserialize back
    let decoded_user: User = Serializer::deserialize(&json_data, Format::Json)?;
    
    Ok(())
}
```

### 4. Storage Backend Usage

```rust
use r_squared::storage::{StorageBackend, LocalStorage, S3Storage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local filesystem storage
    let local_storage = LocalStorage::new("./data")?;
    local_storage.store("key1", b"some data")?;
    
    // AWS S3 storage
    let s3_storage = S3Storage::new(
        "your-bucket", 
        "access-key", 
        "secret-key"
    )?;
    s3_storage.store("key2", b"cloud data")?;
    
    Ok(())
}
```

## Error Handling

R-Squared uses Rust's `Result` type for robust error handling:

```rust
match some_operation() {
    Ok(result) => { /* Success */ },
    Err(error) => { 
        // Detailed error information
        println!("Error: {}", error);
    }
}
```

## Best Practices

1. Always handle potential errors
2. Use `?` operator for concise error propagation
3. Leverage Rust's type system
4. Use pattern matching for comprehensive error handling

## Performance Tips

- Reuse key pairs and storage backends when possible
- Use `&` for borrowing to reduce allocations
- Prefer stack-allocated types
- Use `async` for I/O-bound operations

## Debugging

- Use `RUST_BACKTRACE=1` for detailed error traces
- Leverage Rust's compile-time checks
- Use `cargo test` frequently

## Next Steps

- Explore module-specific documentation
- Review migration guide if coming from JavaScript
- Check out advanced examples in the documentation

## Community and Support

- [GitHub Repository](https://github.com/your-org/r-squared-rust)
- [Issue Tracker](https://github.com/your-org/r-squared-rust/issues)
- [Community Discord](https://discord.gg/your-community)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.