//! Type definitions for serialization
//!
//! This module provides type definitions and structures used throughout
//! the serialization system for the R-Squared blockchain.

use crate::error::{SerializerError, SerializerResult};
use std::collections::HashMap;

#[cfg(feature = "serde_support")]
use serde::{Serialize, Deserialize};

/// Type definitions for serialization
pub struct SerializerTypes;

impl SerializerTypes {
    /// Get the type ID for a given type name
    pub fn get_type_id(type_name: &str) -> Option<u8> {
        match type_name {
            "Transaction" => Some(0x01),
            "Block" => Some(0x02),
            "Account" => Some(0x03),
            "Asset" => Some(0x04),
            "Operation" => Some(0x05),
            "Authority" => Some(0x06),
            "Memo" => Some(0x07),
            "Price" => Some(0x08),
            "AssetAmount" => Some(0x09),
            "ObjectId" => Some(0x0A),
            "String" => Some(0x10),
            "Vec" => Some(0x11),
            "HashMap" => Some(0x12),
            "Option" => Some(0x13),
            "Bool" => Some(0x20),
            "U8" => Some(0x21),
            "U16" => Some(0x22),
            "U32" => Some(0x23),
            "U64" => Some(0x24),
            "I8" => Some(0x25),
            "I16" => Some(0x26),
            "I32" => Some(0x27),
            "I64" => Some(0x28),
            "F32" => Some(0x29),
            "F64" => Some(0x2A),
            _ => None,
        }
    }

    /// Get the type name for a given type ID
    pub fn get_type_name(type_id: u8) -> Option<&'static str> {
        match type_id {
            0x01 => Some("Transaction"),
            0x02 => Some("Block"),
            0x03 => Some("Account"),
            0x04 => Some("Asset"),
            0x05 => Some("Operation"),
            0x06 => Some("Authority"),
            0x07 => Some("Memo"),
            0x08 => Some("Price"),
            0x09 => Some("AssetAmount"),
            0x0A => Some("ObjectId"),
            0x10 => Some("String"),
            0x11 => Some("Vec"),
            0x12 => Some("HashMap"),
            0x13 => Some("Option"),
            0x20 => Some("Bool"),
            0x21 => Some("U8"),
            0x22 => Some("U16"),
            0x23 => Some("U32"),
            0x24 => Some("U64"),
            0x25 => Some("I8"),
            0x26 => Some("I16"),
            0x27 => Some("I32"),
            0x28 => Some("I64"),
            0x29 => Some("F32"),
            0x2A => Some("F64"),
            _ => None,
        }
    }

    /// Check if a type is a primitive type
    pub fn is_primitive_type(type_id: u8) -> bool {
        matches!(type_id, 0x20..=0x2A)
    }

    /// Check if a type is a blockchain type
    pub fn is_blockchain_type(type_id: u8) -> bool {
        matches!(type_id, 0x01..=0x0A)
    }

    /// Check if a type is a container type
    pub fn is_container_type(type_id: u8) -> bool {
        matches!(type_id, 0x10..=0x13)
    }
}

/// Serializable data wrapper
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct SerializableData {
    /// Type identifier
    pub type_id: u8,
    /// Serialized data
    pub data: Vec<u8>,
    /// Optional metadata
    pub metadata: Option<HashMap<String, String>>,
}

impl SerializableData {
    /// Create new serializable data
    pub fn new(type_id: u8, data: Vec<u8>) -> Self {
        Self {
            type_id,
            data,
            metadata: None,
        }
    }

    /// Create new serializable data with metadata
    pub fn with_metadata(type_id: u8, data: Vec<u8>, metadata: HashMap<String, String>) -> Self {
        Self {
            type_id,
            data,
            metadata: Some(metadata),
        }
    }

    /// Get the type name
    pub fn type_name(&self) -> Option<&'static str> {
        SerializerTypes::get_type_name(self.type_id)
    }

    /// Check if this is a primitive type
    pub fn is_primitive(&self) -> bool {
        SerializerTypes::is_primitive_type(self.type_id)
    }

    /// Check if this is a blockchain type
    pub fn is_blockchain_type(&self) -> bool {
        SerializerTypes::is_blockchain_type(self.type_id)
    }

    /// Check if this is a container type
    pub fn is_container_type(&self) -> bool {
        SerializerTypes::is_container_type(self.type_id)
    }

    /// Get data size
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Validate the data structure
    pub fn validate(&self) -> SerializerResult<()> {
        if self.data.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty data".to_string(),
                actual: "Empty data".to_string(),
            });
        }

        if self.data.len() > super::constants::MAX_SERIALIZED_SIZE {
            return Err(SerializerError::BufferError {
                reason: format!("Data size {} exceeds maximum {}", self.data.len(), super::constants::MAX_SERIALIZED_SIZE),
            });
        }

        Ok(())
    }
}

/// Serialization context for maintaining state during serialization
#[derive(Debug, Clone)]
pub struct SerializationContext {
    /// Current depth in nested structures
    pub depth: usize,
    /// Maximum allowed depth
    pub max_depth: usize,
    /// Object reference map for circular reference detection
    pub object_refs: HashMap<usize, bool>,
    /// Type stack for debugging
    pub type_stack: Vec<String>,
}

impl SerializationContext {
    /// Create a new serialization context
    pub fn new() -> Self {
        Self {
            depth: 0,
            max_depth: 100,
            object_refs: HashMap::new(),
            type_stack: Vec::new(),
        }
    }

    /// Create a new context with custom max depth
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            depth: 0,
            max_depth,
            object_refs: HashMap::new(),
            type_stack: Vec::new(),
        }
    }

    /// Enter a new level (increment depth)
    pub fn enter(&mut self, type_name: &str) -> SerializerResult<()> {
        if self.depth >= self.max_depth {
            return Err(SerializerError::BufferError {
                reason: format!("Maximum serialization depth {} exceeded", self.max_depth),
            });
        }

        self.depth += 1;
        self.type_stack.push(type_name.to_string());
        Ok(())
    }

    /// Exit the current level (decrement depth)
    pub fn exit(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
            self.type_stack.pop();
        }
    }

    /// Check for circular references
    pub fn check_circular_ref(&mut self, object_ptr: usize) -> SerializerResult<()> {
        if self.object_refs.contains_key(&object_ptr) {
            return Err(SerializerError::SerializationFailed {
                reason: "Circular reference detected".to_string(),
            });
        }

        self.object_refs.insert(object_ptr, true);
        Ok(())
    }

    /// Remove object reference
    pub fn remove_ref(&mut self, object_ptr: usize) {
        self.object_refs.remove(&object_ptr);
    }

    /// Get current type path
    pub fn current_path(&self) -> String {
        self.type_stack.join("::")
    }

    /// Reset the context
    pub fn reset(&mut self) {
        self.depth = 0;
        self.object_refs.clear();
        self.type_stack.clear();
    }
}

impl Default for SerializationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Type registry for custom type serialization
#[derive(Debug)]
pub struct TypeRegistry {
    /// Map of type names to type IDs
    type_name_to_id: HashMap<String, u8>,
    /// Map of type IDs to type names
    type_id_to_name: HashMap<u8, String>,
    /// Next available custom type ID
    next_custom_id: u8,
}

impl TypeRegistry {
    /// Create a new type registry
    pub fn new() -> Self {
        let mut registry = Self {
            type_name_to_id: HashMap::new(),
            type_id_to_name: HashMap::new(),
            next_custom_id: 0x80, // Start custom types at 0x80
        };

        // Register built-in types
        registry.register_builtin_types();
        registry
    }

    /// Register built-in types
    fn register_builtin_types(&mut self) {
        let builtin_types = [
            ("Transaction", 0x01),
            ("Block", 0x02),
            ("Account", 0x03),
            ("Asset", 0x04),
            ("Operation", 0x05),
            ("Authority", 0x06),
            ("Memo", 0x07),
            ("Price", 0x08),
            ("AssetAmount", 0x09),
            ("ObjectId", 0x0A),
            ("String", 0x10),
            ("Vec", 0x11),
            ("HashMap", 0x12),
            ("Option", 0x13),
            ("Bool", 0x20),
            ("U8", 0x21),
            ("U16", 0x22),
            ("U32", 0x23),
            ("U64", 0x24),
            ("I8", 0x25),
            ("I16", 0x26),
            ("I32", 0x27),
            ("I64", 0x28),
            ("F32", 0x29),
            ("F64", 0x2A),
        ];

        for (name, id) in &builtin_types {
            self.type_name_to_id.insert(name.to_string(), *id);
            self.type_id_to_name.insert(*id, name.to_string());
        }
    }

    /// Register a custom type
    pub fn register_custom_type(&mut self, type_name: &str) -> SerializerResult<u8> {
        if self.type_name_to_id.contains_key(type_name) {
            return Err(SerializerError::TypeConversionError {
                from: "Custom type".to_string(),
                to: format!("Type {} already registered", type_name),
            });
        }

        if self.next_custom_id == 0xFF {
            return Err(SerializerError::BufferError {
                reason: "No more custom type IDs available".to_string(),
            });
        }

        let type_id = self.next_custom_id;
        self.next_custom_id += 1;

        self.type_name_to_id.insert(type_name.to_string(), type_id);
        self.type_id_to_name.insert(type_id, type_name.to_string());

        Ok(type_id)
    }

    /// Get type ID by name
    pub fn get_type_id(&self, type_name: &str) -> Option<u8> {
        self.type_name_to_id.get(type_name).copied()
    }

    /// Get type name by ID
    pub fn get_type_name(&self, type_id: u8) -> Option<&str> {
        self.type_id_to_name.get(&type_id).map(|s| s.as_str())
    }

    /// Check if a type is registered
    pub fn is_registered(&self, type_name: &str) -> bool {
        self.type_name_to_id.contains_key(type_name)
    }

    /// Get all registered types
    pub fn get_all_types(&self) -> Vec<(String, u8)> {
        self.type_name_to_id
            .iter()
            .map(|(name, id)| (name.clone(), *id))
            .collect()
    }
}

impl Default for TypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialization statistics
#[derive(Debug, Clone, Default)]
pub struct SerializationStats {
    /// Number of objects serialized
    pub objects_serialized: usize,
    /// Total bytes serialized
    pub bytes_serialized: usize,
    /// Number of objects deserialized
    pub objects_deserialized: usize,
    /// Total bytes deserialized
    pub bytes_deserialized: usize,
    /// Serialization time in microseconds
    pub serialization_time_us: u64,
    /// Deserialization time in microseconds
    pub deserialization_time_us: u64,
}

impl SerializationStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record serialization
    pub fn record_serialization(&mut self, bytes: usize, time_us: u64) {
        self.objects_serialized += 1;
        self.bytes_serialized += bytes;
        self.serialization_time_us += time_us;
    }

    /// Record deserialization
    pub fn record_deserialization(&mut self, bytes: usize, time_us: u64) {
        self.objects_deserialized += 1;
        self.bytes_deserialized += bytes;
        self.deserialization_time_us += time_us;
    }

    /// Get average serialization time
    pub fn avg_serialization_time_us(&self) -> f64 {
        if self.objects_serialized == 0 {
            0.0
        } else {
            self.serialization_time_us as f64 / self.objects_serialized as f64
        }
    }

    /// Get average deserialization time
    pub fn avg_deserialization_time_us(&self) -> f64 {
        if self.objects_deserialized == 0 {
            0.0
        } else {
            self.deserialization_time_us as f64 / self.objects_deserialized as f64
        }
    }

    /// Reset all statistics
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializer_types() {
        assert_eq!(SerializerTypes::get_type_id("Transaction"), Some(0x01));
        assert_eq!(SerializerTypes::get_type_name(0x01), Some("Transaction"));
        
        assert!(SerializerTypes::is_blockchain_type(0x01));
        assert!(SerializerTypes::is_primitive_type(0x20));
        assert!(SerializerTypes::is_container_type(0x10));
    }

    #[test]
    fn test_serializable_data() {
        let data = SerializableData::new(0x01, vec![1, 2, 3, 4]);
        assert_eq!(data.type_id, 0x01);
        assert_eq!(data.size(), 4);
        assert_eq!(data.type_name(), Some("Transaction"));
        assert!(data.is_blockchain_type());
        assert!(data.validate().is_ok());
    }

    #[test]
    fn test_serialization_context() {
        let mut ctx = SerializationContext::new();
        assert_eq!(ctx.depth, 0);
        
        ctx.enter("Test").unwrap();
        assert_eq!(ctx.depth, 1);
        assert_eq!(ctx.current_path(), "Test");
        
        ctx.exit();
        assert_eq!(ctx.depth, 0);
    }

    #[test]
    fn test_type_registry() {
        let mut registry = TypeRegistry::new();
        
        // Test built-in types
        assert_eq!(registry.get_type_id("Transaction"), Some(0x01));
        assert_eq!(registry.get_type_name(0x01), Some("Transaction"));
        
        // Test custom type registration
        let custom_id = registry.register_custom_type("CustomType").unwrap();
        assert!(custom_id >= 0x80);
        assert_eq!(registry.get_type_id("CustomType"), Some(custom_id));
        assert_eq!(registry.get_type_name(custom_id), Some("CustomType"));
    }

    #[test]
    fn test_serialization_stats() {
        let mut stats = SerializationStats::new();
        
        stats.record_serialization(100, 1000);
        stats.record_deserialization(100, 800);
        
        assert_eq!(stats.objects_serialized, 1);
        assert_eq!(stats.bytes_serialized, 100);
        assert_eq!(stats.avg_serialization_time_us(), 1000.0);
        assert_eq!(stats.avg_deserialization_time_us(), 800.0);
    }
}