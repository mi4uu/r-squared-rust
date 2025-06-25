//! Performance benchmarks comparing Rust and JavaScript implementations
//! 
//! These benchmarks measure the performance of key operations to document
//! performance improvements in the Rust implementation.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use r_squared_rust::ecc::*;
use r_squared_rust::chain::*;
use r_squared_rust::serializer::*;

/// Benchmark ECC operations
fn bench_ecc_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecc_operations");
    
    // Benchmark private key generation
    group.bench_function("private_key_generation", |b| {
        b.iter(|| {
            let _private_key = PrivateKey::generate().unwrap();
        });
    });
    
    // Benchmark public key derivation
    let private_key = PrivateKey::generate().unwrap();
    group.bench_function("public_key_derivation", |b| {
        b.iter(|| {
            let _public_key = private_key.public_key().unwrap();
        });
    });
    
    // Benchmark brain key derivation
    let brain_key = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    group.bench_function("brain_key_derivation", |b| {
        b.iter(|| {
            let normalized = KeyUtils::normalize_brain_key(black_box(brain_key));
            let _brain_key_obj = BrainKey::from_words(&normalized).unwrap();
        });
    });
    
    // Benchmark address generation
    let public_key = private_key.public_key().unwrap();
    group.bench_function("address_generation", |b| {
        b.iter(|| {
            let _address = Address::from_public_key(black_box(&public_key), "RSQ").unwrap();
        });
    });
    
    // Benchmark signature creation
    let message = b"Hello, R-Squared benchmark!";
    let hash = sha256(message);
    group.bench_function("signature_creation", |b| {
        b.iter(|| {
            let _signature = private_key.sign(black_box(&hash)).unwrap();
        });
    });
    
    // Benchmark signature verification
    let signature = private_key.sign(&hash).unwrap();
    group.bench_function("signature_verification", |b| {
        b.iter(|| {
            let _valid = public_key.verify(black_box(&hash), black_box(&signature)).unwrap();
        });
    });
    
    group.finish();
}

/// Benchmark hash functions
fn bench_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_functions");
    
    let test_data = b"This is test data for hash function benchmarking. It should be long enough to provide meaningful results.";
    
    group.bench_function("sha256", |b| {
        b.iter(|| {
            let _hash = sha256(black_box(test_data));
        });
    });
    
    group.bench_function("sha256d", |b| {
        b.iter(|| {
            let _hash = sha256d(black_box(test_data));
        });
    });
    
    group.bench_function("ripemd160", |b| {
        b.iter(|| {
            let _hash = ripemd160(black_box(test_data));
        });
    });
    
    group.bench_function("hash160", |b| {
        b.iter(|| {
            let _hash = hash160(black_box(test_data));
        });
    });
    
    // Benchmark HMAC
    let key = b"secret_key_for_hmac_benchmarking";
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| {
            let _hmac = hmac_sha256(black_box(key), black_box(test_data));
        });
    });
    
    group.finish();
}

/// Benchmark AES encryption/decryption
fn bench_aes_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_operations");
    
    let key = b"32_byte_key_for_aes_benchmarking!";
    let plaintext = b"This is plaintext data for AES encryption benchmarking. It should be long enough to show performance characteristics.";
    
    group.bench_function("aes_encrypt", |b| {
        b.iter(|| {
            let _encrypted = Aes::encrypt(black_box(key), black_box(plaintext)).unwrap();
        });
    });
    
    let encrypted = Aes::encrypt(key, plaintext).unwrap();
    group.bench_function("aes_decrypt", |b| {
        b.iter(|| {
            let _decrypted = Aes::decrypt(black_box(key), black_box(&encrypted)).unwrap();
        });
    });
    
    // Benchmark memo encryption
    let sender_private = PrivateKey::generate().unwrap();
    let recipient_private = PrivateKey::generate().unwrap();
    let recipient_public = recipient_private.public_key().unwrap();
    let memo_text = "This is a memo for encryption benchmarking";
    
    group.bench_function("memo_encrypt", |b| {
        b.iter(|| {
            let _encrypted = Aes::encrypt_memo(
                black_box(memo_text),
                black_box(&sender_private.to_bytes()),
                black_box(&recipient_public.to_bytes())
            ).unwrap();
        });
    });
    
    let encrypted_memo = Aes::encrypt_memo(
        memo_text,
        &sender_private.to_bytes(),
        &recipient_public.to_bytes()
    ).unwrap();
    let sender_public = sender_private.public_key().unwrap();
    
    group.bench_function("memo_decrypt", |b| {
        b.iter(|| {
            let _decrypted = Aes::decrypt_memo(
                black_box(&encrypted_memo),
                black_box(&recipient_private.to_bytes()),
                black_box(&sender_public.to_bytes())
            ).unwrap();
        });
    });
    
    group.finish();
}

/// Benchmark chain operations
fn bench_chain_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_operations");
    
    // Benchmark object ID operations
    group.bench_function("object_id_parsing", |b| {
        b.iter(|| {
            let _object_id = ObjectId::from_string(black_box("1.2.100")).unwrap();
        });
    });
    
    let object_id = ObjectId::new(1, 2, 100).unwrap();
    group.bench_function("object_id_formatting", |b| {
        b.iter(|| {
            let _string = object_id.to_string();
        });
    });
    
    // Benchmark transaction building
    group.bench_function("transaction_building", |b| {
        b.iter(|| {
            let mut builder = TransactionBuilder::new();
            let from = ObjectId::new(1, 2, 1).unwrap();
            let to = ObjectId::new(1, 2, 2).unwrap();
            let amount = AssetAmount {
                amount: 100000,
                asset_id: ObjectId::new(1, 3, 0).unwrap(),
            };
            builder.add_transfer(from, to, amount, None).unwrap();
            builder.set_expiration(3600).unwrap();
            let _transaction = builder.build().unwrap();
        });
    });
    
    // Benchmark transaction signing
    let mut builder = TransactionBuilder::new();
    let from = ObjectId::new(1, 2, 1).unwrap();
    let to = ObjectId::new(1, 2, 2).unwrap();
    let amount = AssetAmount {
        amount: 100000,
        asset_id: ObjectId::new(1, 3, 0).unwrap(),
    };
    builder.add_transfer(from, to, amount, None).unwrap();
    builder.set_expiration(3600).unwrap();
    builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef01234567").unwrap();
    
    let private_key = PrivateKey::generate().unwrap();
    group.bench_function("transaction_signing", |b| {
        b.iter(|| {
            let mut builder_clone = builder.clone();
            let _signed = builder_clone.build_and_sign(black_box(&[private_key.clone()])).unwrap();
        });
    });
    
    // Benchmark number operations
    let num1 = PrecisionNumber::from_string("123.456", 3).unwrap();
    let num2 = PrecisionNumber::from_string("78.9", 3).unwrap();
    
    group.bench_function("precision_number_add", |b| {
        b.iter(|| {
            let _result = num1.add(black_box(&num2)).unwrap();
        });
    });
    
    group.bench_function("precision_number_multiply", |b| {
        b.iter(|| {
            let _result = num1.multiply(black_box(&num2)).unwrap();
        });
    });
    
    group.finish();
}

/// Benchmark serialization operations
fn bench_serialization_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization_operations");
    
    let serializer = Serializer::new();
    
    // Benchmark object ID serialization
    let object_id = ObjectId::new(1, 2, 100).unwrap();
    group.bench_function("object_id_serialize", |b| {
        b.iter(|| {
            let _data = serializer.serialize(black_box(&object_id)).unwrap();
        });
    });
    
    let object_id_data = serializer.serialize(&object_id).unwrap();
    group.bench_function("object_id_deserialize", |b| {
        b.iter(|| {
            let _object_id: ObjectId = serializer.deserialize(black_box(&object_id_data)).unwrap();
        });
    });
    
    // Benchmark transaction serialization
    let mut builder = TransactionBuilder::new();
    let from = ObjectId::new(1, 2, 1).unwrap();
    let to = ObjectId::new(1, 2, 2).unwrap();
    let amount = AssetAmount {
        amount: 100000,
        asset_id: ObjectId::new(1, 3, 0).unwrap(),
    };
    builder.add_transfer(from, to, amount, None).unwrap();
    builder.set_expiration(3600).unwrap();
    let transaction = builder.build().unwrap();
    
    group.bench_function("transaction_serialize", |b| {
        b.iter(|| {
            let _data = serializer.serialize(black_box(&transaction)).unwrap();
        });
    });
    
    let transaction_data = serializer.serialize(&transaction).unwrap();
    group.bench_function("transaction_deserialize", |b| {
        b.iter(|| {
            let _transaction: Transaction = serializer.deserialize(black_box(&transaction_data)).unwrap();
        });
    });
    
    // Benchmark varint encoding
    let test_values = [0u64, 127, 128, 16383, 16384, 65535, 65536];
    for value in &test_values {
        group.bench_with_input(
            BenchmarkId::new("varint_encode", value),
            value,
            |b, &value| {
                b.iter(|| {
                    let _encoded = SerializerUtils::encode_varint(black_box(value));
                });
            },
        );
    }
    
    // Benchmark string encoding
    let test_strings = ["", "Hello", "Hello, World!", "Very long string for benchmarking purposes"];
    for (i, string) in test_strings.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("string_encode", i),
            string,
            |b, &string| {
                b.iter(|| {
                    let _encoded = SerializerUtils::encode_string(black_box(string));
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark key derivation operations
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    
    let master_key = PrivateKey::generate().unwrap();
    
    // Benchmark child key derivation
    for count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("derive_keys", count),
            count,
            |b, &count| {
                b.iter(|| {
                    let _keys = KeyUtils::derive_keys(black_box(&master_key), black_box(count)).unwrap();
                });
            },
        );
    }
    
    // Benchmark address derivation
    for count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("derive_addresses", count),
            count,
            |b, &count| {
                b.iter(|| {
                    let _addresses = Ecc::derive_addresses(black_box(&master_key), "RSQ", black_box(*count)).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_ecc_operations,
    bench_hash_functions,
    bench_aes_operations,
    bench_chain_operations,
    bench_serialization_operations,
    bench_key_derivation
);
criterion_main!(benches);