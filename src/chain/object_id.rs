//! Object ID implementation for R-Squared blockchain objects
//!
//! This module provides functionality for handling blockchain object IDs
//! in the R-Squared format: space.type.instance (e.g., "1.2.0")

use crate::error::{ChainError, ChainResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Object ID for blockchain objects following R-Squared format
/// 
/// Format: space.type.instance
/// - space: Object space (usually 1 for protocol objects)
/// - type: Object type (e.g., 1=account, 2=asset, 3=force_settlement, etc.)
/// - instance: Unique instance number within the type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId {
    space: u8,
    type_id: u8,
    instance: u64,
}

impl ObjectId {
    /// Create a new ObjectId
    pub fn new(space: u8, type_id: u8, instance: u64) -> Self {
        Self {
            space,
            type_id,
            instance,
        }
    }

    /// Create ObjectId from string representation (e.g., "1.2.0")
    pub fn from_string(id_str: &str) -> ChainResult<Self> {
        let parts: Vec<&str> = id_str.split('.').collect();
        if parts.len() != 3 {
            return Err(ChainError::InvalidObjectId {
                id: id_str.to_string(),
            });
        }

        let space = parts[0].parse::<u8>().map_err(|_| ChainError::InvalidObjectId {
            id: id_str.to_string(),
        })?;

        let type_id = parts[1].parse::<u8>().map_err(|_| ChainError::InvalidObjectId {
            id: id_str.to_string(),
        })?;

        let instance = parts[2].parse::<u64>().map_err(|_| ChainError::InvalidObjectId {
            id: id_str.to_string(),
        })?;

        Ok(Self::new(space, type_id, instance))
    }

    /// Get the space component
    pub fn space(&self) -> u8 {
        self.space
    }

    /// Get the type component
    pub fn type_id(&self) -> u8 {
        self.type_id
    }

    /// Get the instance component
    pub fn instance(&self) -> u64 {
        self.instance
    }

    /// Check if this is an account object (type 1)
    pub fn is_account(&self) -> bool {
        self.type_id == 1
    }

    /// Check if this is an asset object (type 2)
    pub fn is_asset(&self) -> bool {
        self.type_id == 2
    }

    /// Check if this is a force settlement object (type 3)
    pub fn is_force_settlement(&self) -> bool {
        self.type_id == 3
    }

    /// Check if this is a committee member object (type 4)
    pub fn is_committee_member(&self) -> bool {
        self.type_id == 4
    }

    /// Check if this is a witness object (type 5)
    pub fn is_witness(&self) -> bool {
        self.type_id == 5
    }

    /// Check if this is a limit order object (type 6)
    pub fn is_limit_order(&self) -> bool {
        self.type_id == 6
    }

    /// Check if this is a call order object (type 7)
    pub fn is_call_order(&self) -> bool {
        self.type_id == 7
    }

    /// Check if this is a custom object (type 8)
    pub fn is_custom(&self) -> bool {
        self.type_id == 8
    }

    /// Check if this is a proposal object (type 9)
    pub fn is_proposal(&self) -> bool {
        self.type_id == 9
    }

    /// Check if this is an operation history object (type 10)
    pub fn is_operation_history(&self) -> bool {
        self.type_id == 10
    }

    /// Check if this is a withdraw permission object (type 11)
    pub fn is_withdraw_permission(&self) -> bool {
        self.type_id == 11
    }

    /// Check if this is a vesting balance object (type 12)
    pub fn is_vesting_balance(&self) -> bool {
        self.type_id == 12
    }

    /// Check if this is a worker object (type 13)
    pub fn is_worker(&self) -> bool {
        self.type_id == 13
    }

    /// Check if this is a balance object (type 14)
    pub fn is_balance(&self) -> bool {
        self.type_id == 14
    }

    /// Validate the ObjectId format and constraints
    pub fn validate(&self) -> ChainResult<()> {
        // Space should typically be 1 for protocol objects
        if self.space == 0 {
            return Err(ChainError::ValidationError {
                field: "space".to_string(),
                reason: "Space cannot be 0".to_string(),
            });
        }

        // Type should be within known range (1-14 for standard objects)
        if self.type_id == 0 || self.type_id > 20 {
            return Err(ChainError::ValidationError {
                field: "type_id".to_string(),
                reason: format!("Type ID {} is out of valid range", self.type_id),
            });
        }

        Ok(())
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.space);
        bytes.push(self.type_id);
        bytes.extend_from_slice(&self.instance.to_le_bytes());
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> ChainResult<Self> {
        if bytes.len() != 10 {
            return Err(ChainError::InvalidObjectId {
                id: format!("Invalid byte length: {}", bytes.len()),
            });
        }

        let space = bytes[0];
        let type_id = bytes[1];
        let instance_bytes: [u8; 8] = bytes[2..10].try_into().map_err(|_| {
            ChainError::InvalidObjectId {
                id: "Failed to parse instance bytes".to_string(),
            }
        })?;
        let instance = u64::from_le_bytes(instance_bytes);

        let obj_id = Self::new(space, type_id, instance);
        obj_id.validate()?;
        Ok(obj_id)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.space, self.type_id, self.instance)
    }
}

impl FromStr for ObjectId {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s)
    }
}

/// Common ObjectId constants for R-Squared blockchain
pub mod constants {
    use super::ObjectId;

    /// Null account (1.2.0)
    pub const NULL_ACCOUNT: ObjectId = ObjectId {
        space: 1,
        type_id: 2,
        instance: 0,
    };

    /// Committee account (1.2.0)
    pub const COMMITTEE_ACCOUNT: ObjectId = ObjectId {
        space: 1,
        type_id: 2,
        instance: 0,
    };

    /// Witness account (1.2.1)
    pub const WITNESS_ACCOUNT: ObjectId = ObjectId {
        space: 1,
        type_id: 2,
        instance: 1,
    };

    /// Relaxed committee account (1.2.2)
    pub const RELAXED_COMMITTEE_ACCOUNT: ObjectId = ObjectId {
        space: 1,
        type_id: 2,
        instance: 2,
    };

    /// Proxy to self account (1.2.3)
    pub const PROXY_TO_SELF_ACCOUNT: ObjectId = ObjectId {
        space: 1,
        type_id: 2,
        instance: 3,
    };

    /// Core asset (1.3.0)
    pub const CORE_ASSET: ObjectId = ObjectId {
        space: 1,
        type_id: 3,
        instance: 0,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_id_creation() {
        let obj_id = ObjectId::new(1, 2, 100);
        assert_eq!(obj_id.space(), 1);
        assert_eq!(obj_id.type_id(), 2);
        assert_eq!(obj_id.instance(), 100);
    }

    #[test]
    fn test_object_id_from_string() {
        let obj_id = ObjectId::from_string("1.2.100").unwrap();
        assert_eq!(obj_id.space(), 1);
        assert_eq!(obj_id.type_id(), 2);
        assert_eq!(obj_id.instance(), 100);
    }

    #[test]
    fn test_object_id_from_string_invalid() {
        assert!(ObjectId::from_string("1.2").is_err());
        assert!(ObjectId::from_string("1.2.3.4").is_err());
        assert!(ObjectId::from_string("a.b.c").is_err());
    }

    #[test]
    fn test_object_id_display() {
        let obj_id = ObjectId::new(1, 2, 100);
        assert_eq!(obj_id.to_string(), "1.2.100");
    }

    #[test]
    fn test_object_id_type_checks() {
        let account_id = ObjectId::new(1, 1, 0);
        assert!(account_id.is_account());
        assert!(!account_id.is_asset());

        let asset_id = ObjectId::new(1, 2, 0);
        assert!(asset_id.is_asset());
        assert!(!asset_id.is_account());
    }

    #[test]
    fn test_object_id_validation() {
        let valid_id = ObjectId::new(1, 2, 100);
        assert!(valid_id.validate().is_ok());

        let invalid_space = ObjectId::new(0, 2, 100);
        assert!(invalid_space.validate().is_err());

        let invalid_type = ObjectId::new(1, 0, 100);
        assert!(invalid_type.validate().is_err());
    }

    #[test]
    fn test_object_id_bytes_conversion() {
        let obj_id = ObjectId::new(1, 2, 100);
        let bytes = obj_id.to_bytes();
        let restored = ObjectId::from_bytes(&bytes).unwrap();
        assert_eq!(obj_id, restored);
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::NULL_ACCOUNT.to_string(), "1.2.0");
        assert_eq!(constants::CORE_ASSET.to_string(), "1.3.0");
        assert!(constants::NULL_ACCOUNT.is_account());
        assert!(constants::CORE_ASSET.is_asset());
    }

    #[test]
    fn test_from_str_trait() {
        let obj_id: ObjectId = "1.2.100".parse().unwrap();
        assert_eq!(obj_id.space(), 1);
        assert_eq!(obj_id.type_id(), 2);
        assert_eq!(obj_id.instance(), 100);
    }
}