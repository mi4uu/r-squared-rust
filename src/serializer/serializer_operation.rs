//! Operation serialization/deserialization
//!
//! This module provides functionality for serializing and deserializing
//! blockchain operations for the R-Squared blockchain.

use crate::error::{SerializerError, SerializerResult};
use crate::chain::{AssetAmount, ObjectId, Authority, Memo, Price};
use crate::chain::chain_types::{Operation, Transaction, Extension};
use crate::serializer::serializer_types::SerializationContext;
use std::collections::HashMap;

#[cfg(feature = "serde_support")]
use serde::{Serialize, Deserialize};

/// Operation serialization and deserialization
pub struct SerializerOperation;

impl SerializerOperation {
    /// Serialize an operation to bytes
    pub fn serialize_operation(operation: &Operation) -> SerializerResult<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut context = SerializationContext::new();
        
        Self::serialize_operation_with_context(operation, &mut buffer, &mut context)?;
        Ok(buffer)
    }

    /// Deserialize an operation from bytes
    pub fn deserialize_operation(data: &[u8]) -> SerializerResult<Operation> {
        let mut context = SerializationContext::new();
        let mut offset = 0;
        
        Self::deserialize_operation_with_context(data, &mut offset, &mut context)
    }

    /// Serialize operation with context
    fn serialize_operation_with_context(
        operation: &Operation,
        buffer: &mut Vec<u8>,
        context: &mut SerializationContext,
    ) -> SerializerResult<()> {
        context.enter("Operation")?;

        // Write operation type
        let type_id = Self::get_operation_type_id(operation)?;
        buffer.push(type_id);

        // Serialize operation data based on type
        match operation {
            Operation::Transfer { fee, from, to, amount, memo, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(from, buffer)?;
                Self::serialize_object_id(to, buffer)?;
                Self::serialize_asset_amount(amount, buffer)?;
                Self::serialize_optional_memo(memo, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::LimitOrderCreate { fee, seller, amount_to_sell, min_to_receive, expiration, fill_or_kill, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(seller, buffer)?;
                Self::serialize_asset_amount(amount_to_sell, buffer)?;
                Self::serialize_asset_amount(min_to_receive, buffer)?;
                Self::serialize_u32(*expiration, buffer)?;
                Self::serialize_bool(*fill_or_kill, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::LimitOrderCancel { fee, fee_paying_account, order, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(fee_paying_account, buffer)?;
                Self::serialize_object_id(order, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::AccountCreate { fee, registrar, referrer, referrer_percent, name, owner, active, options, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(registrar, buffer)?;
                Self::serialize_object_id(referrer, buffer)?;
                Self::serialize_u16(*referrer_percent, buffer)?;
                Self::serialize_string(name, buffer)?;
                Self::serialize_authority(owner, buffer)?;
                Self::serialize_authority(active, buffer)?;
                Self::serialize_account_options(options, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::AccountUpdate { fee, account, owner, active, new_options, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(account, buffer)?;
                Self::serialize_optional_authority(owner, buffer)?;
                Self::serialize_optional_authority(active, buffer)?;
                Self::serialize_optional_account_options(new_options, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::AssetCreate { fee, issuer, symbol, precision, common_options, bitasset_opts, is_prediction_market, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(issuer, buffer)?;
                Self::serialize_string(symbol, buffer)?;
                Self::serialize_u8(*precision, buffer)?;
                Self::serialize_asset_options(common_options, buffer)?;
                Self::serialize_optional_bitasset_options(bitasset_opts, buffer)?;
                Self::serialize_bool(*is_prediction_market, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::AssetUpdate { fee, issuer, asset_to_update, new_options, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(issuer, buffer)?;
                Self::serialize_object_id(asset_to_update, buffer)?;
                Self::serialize_optional_asset_options(new_options, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::AssetIssue { fee, issuer, asset_to_issue, issue_to_account, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_object_id(issuer, buffer)?;
                Self::serialize_asset_amount(asset_to_issue, buffer)?;
                Self::serialize_object_id(issue_to_account, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
            Operation::Custom { fee, id, payer, required_auths, data, extensions } => {
                Self::serialize_asset_amount(fee, buffer)?;
                Self::serialize_u16(*id, buffer)?;
                Self::serialize_object_id(payer, buffer)?;
                Self::serialize_varint(required_auths.len() as u64, buffer)?;
                for auth in required_auths {
                    Self::serialize_object_id(auth, buffer)?;
                }
                Self::serialize_bytes(data, buffer)?;
                Self::serialize_extensions(extensions, buffer)?;
            }
        }

        context.exit();
        Ok(())
    }

    /// Deserialize operation with context
    fn deserialize_operation_with_context(
        data: &[u8],
        offset: &mut usize,
        context: &mut SerializationContext,
    ) -> SerializerResult<Operation> {
        context.enter("Operation")?;

        if *offset >= data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for operation type".to_string(),
            });
        }

        let type_id = data[*offset];
        *offset += 1;

        let operation = match type_id {
            0x00 => { // Transfer
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let from = Self::deserialize_object_id(data, offset)?;
                let to = Self::deserialize_object_id(data, offset)?;
                let amount = Self::deserialize_asset_amount(data, offset)?;
                let memo = Self::deserialize_optional_memo(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::Transfer { fee, from, to, amount, memo, extensions }
            }
            0x01 => { // LimitOrderCreate
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let seller = Self::deserialize_object_id(data, offset)?;
                let amount_to_sell = Self::deserialize_asset_amount(data, offset)?;
                let min_to_receive = Self::deserialize_asset_amount(data, offset)?;
                let expiration = Self::deserialize_u32(data, offset)?;
                let fill_or_kill = Self::deserialize_bool(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::LimitOrderCreate { fee, seller, amount_to_sell, min_to_receive, expiration, fill_or_kill, extensions }
            }
            0x02 => { // LimitOrderCancel
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let fee_paying_account = Self::deserialize_object_id(data, offset)?;
                let order = Self::deserialize_object_id(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::LimitOrderCancel { fee, fee_paying_account, order, extensions }
            }
            0x05 => { // AccountCreate
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let registrar = Self::deserialize_object_id(data, offset)?;
                let referrer = Self::deserialize_object_id(data, offset)?;
                let referrer_percent = Self::deserialize_u16(data, offset)?;
                let name = Self::deserialize_string(data, offset)?;
                let owner = Self::deserialize_authority(data, offset)?;
                let active = Self::deserialize_authority(data, offset)?;
                let options = Self::deserialize_account_options(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::AccountCreate { fee, registrar, referrer, referrer_percent, name, owner, active, options, extensions }
            }
            0x06 => { // AccountUpdate
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let account = Self::deserialize_object_id(data, offset)?;
                let owner = Self::deserialize_optional_authority(data, offset)?;
                let active = Self::deserialize_optional_authority(data, offset)?;
                let new_options = Self::deserialize_optional_account_options(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::AccountUpdate { fee, account, owner, active, new_options, extensions }
            }
            0x0A => { // AssetCreate (using 0x0A to match the only available variant)
                let fee = Self::deserialize_asset_amount(data, offset)?;
                let issuer = Self::deserialize_object_id(data, offset)?;
                let symbol = Self::deserialize_string(data, offset)?;
                let precision = Self::deserialize_u8(data, offset)?;
                let common_options = Self::deserialize_asset_options(data, offset)?;
                let bitasset_opts = Self::deserialize_optional_bitasset_options(data, offset)?;
                let is_prediction_market = Self::deserialize_bool(data, offset)?;
                let extensions = Self::deserialize_extensions(data, offset)?;
                Operation::AssetCreate { fee, issuer, symbol, precision, common_options, bitasset_opts, is_prediction_market, extensions }
            }
            _ => {
                return Err(SerializerError::DeserializationFailed {
                    reason: format!("Unknown operation type: {}", type_id),
                });
            }
        };

        context.exit();
        Ok(operation)
    }

    /// Get operation type ID
    fn get_operation_type_id(operation: &Operation) -> SerializerResult<u8> {
        match operation {
            Operation::Transfer { .. } => Ok(0x00),
            Operation::LimitOrderCreate { .. } => Ok(0x01),
            Operation::LimitOrderCancel { .. } => Ok(0x02),
            Operation::AccountCreate { .. } => Ok(0x05),
            Operation::AccountUpdate { .. } => Ok(0x06),
            Operation::AssetCreate { .. } => Ok(0x0A),
            Operation::AssetUpdate { .. } => Ok(0x0B),
            Operation::AssetIssue { .. } => Ok(0x0C),
            Operation::Custom { .. } => Ok(0x23),
        }
    }

    /// Serialize transaction
    pub fn serialize_transaction(transaction: &Transaction) -> SerializerResult<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut context = SerializationContext::new();
        
        context.enter("Transaction")?;

        // Serialize transaction header
        Self::serialize_u16(transaction.ref_block_num, &mut buffer)?;
        Self::serialize_u32(transaction.ref_block_prefix, &mut buffer)?;
        Self::serialize_u32(transaction.expiration, &mut buffer)?;

        // Serialize operations
        Self::serialize_u16(transaction.operations.len() as u16, &mut buffer)?;
        for operation in &transaction.operations {
            Self::serialize_operation_with_context(operation, &mut buffer, &mut context)?;
        }

        // Serialize extensions
        Self::serialize_u16(transaction.extensions.len() as u16, &mut buffer)?;
        for extension in &transaction.extensions {
            Self::serialize_u8(extension.type_id, &mut buffer)?;
            Self::serialize_bytes(&extension.data, &mut buffer)?;
        }

        context.exit();
        Ok(buffer)
    }

    /// Deserialize transaction
    pub fn deserialize_transaction(data: &[u8]) -> SerializerResult<Transaction> {
        let mut context = SerializationContext::new();
        let mut offset = 0;

        context.enter("Transaction")?;

        // Deserialize transaction header
        let ref_block_num = Self::deserialize_u16(data, &mut offset)?;
        let ref_block_prefix = Self::deserialize_u32(data, &mut offset)?;
        let expiration = Self::deserialize_u32(data, &mut offset)?;

        // Deserialize operations
        let operations_count = Self::deserialize_u16(data, &mut offset)?;
        let mut operations = Vec::new();
        for _ in 0..operations_count {
            let operation = Self::deserialize_operation_with_context(data, &mut offset, &mut context)?;
            operations.push(operation);
        }

        // Deserialize extensions
        let extensions_count = Self::deserialize_u16(data, &mut offset)?;
        let mut extensions = Vec::new();
        for _ in 0..extensions_count {
            let type_id = Self::deserialize_u8(data, &mut offset)?;
            let extension_data = Self::deserialize_bytes(data, &mut offset)?;
            extensions.push(Extension {
                type_id,
                data: extension_data,
            });
        }

        context.exit();

        Ok(Transaction {
            ref_block_num,
            ref_block_prefix,
            expiration,
            operations,
            extensions,
            signatures: vec![], // Empty signatures for deserialized transaction
        })
    }

    // Helper serialization methods
    fn serialize_object_id(id: &ObjectId, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        let bytes = id.to_bytes();
        buffer.extend_from_slice(&bytes);
        Ok(())
    }

    fn serialize_asset_amount(amount: &AssetAmount, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_i64(amount.amount, buffer)?;
        Self::serialize_object_id(&amount.asset_id, buffer)?;
        Ok(())
    }

    fn serialize_optional_memo(memo: &Option<Memo>, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        match memo {
            Some(memo) => {
                buffer.push(1); // Present
                Self::serialize_memo(memo, buffer)?;
            }
            None => {
                buffer.push(0); // Not present
            }
        }
        Ok(())
    }

    fn serialize_memo(memo: &Memo, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_string(&memo.from, buffer)?;
        Self::serialize_string(&memo.to, buffer)?;
        Self::serialize_u64(memo.nonce, buffer)?;
        Self::serialize_bytes(&memo.message, buffer)?;
        Ok(())
    }

    fn serialize_authority(authority: &Authority, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_u32(authority.weight_threshold, buffer)?;
        
        // Serialize account auths
        Self::serialize_u16(authority.account_auths.len() as u16, buffer)?;
        for (account_id, weight) in &authority.account_auths {
            Self::serialize_object_id(account_id, buffer)?;
            Self::serialize_u16(*weight, buffer)?;
        }

        // Serialize key auths
        Self::serialize_u16(authority.key_auths.len() as u16, buffer)?;
        for (public_key, weight) in &authority.key_auths {
            Self::serialize_string(public_key, buffer)?;
            Self::serialize_u16(*weight, buffer)?;
        }

        // Serialize address auths
        Self::serialize_u16(authority.address_auths.len() as u16, buffer)?;
        for (address, weight) in &authority.address_auths {
            Self::serialize_string(address, buffer)?;
            Self::serialize_u16(*weight, buffer)?;
        }

        Ok(())
    }

    fn serialize_optional_authority(authority: &Option<Authority>, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        match authority {
            Some(auth) => {
                buffer.push(1);
                Self::serialize_authority(auth, buffer)?;
            }
            None => {
                buffer.push(0);
            }
        }
        Ok(())
    }

    // Placeholder serialization methods for complex types
    fn serialize_account_options(_options: &crate::chain::AccountOptions, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        // Placeholder implementation
        buffer.extend_from_slice(&[0u8; 32]);
        Ok(())
    }

    fn serialize_optional_account_options(_options: &Option<crate::chain::AccountOptions>, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.push(0); // Not present for now
        Ok(())
    }

    fn serialize_asset_options(_options: &crate::chain::AssetOptions, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        // Placeholder implementation
        buffer.extend_from_slice(&[0u8; 64]);
        Ok(())
    }

    fn serialize_optional_asset_options(options: &Option<crate::chain::AssetOptions>, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        match options {
            Some(opts) => {
                buffer.push(1); // Present
                Self::serialize_asset_options(opts, buffer)?;
            }
            None => {
                buffer.push(0); // Not present
            }
        }
        Ok(())
    }

    fn serialize_optional_bitasset_options(_options: &Option<crate::chain::BitassetOptions>, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.push(0); // Not present for now
        Ok(())
    }

    fn serialize_varint(value: u64, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        let mut val = value;
        while val >= 0x80 {
            buffer.push((val & 0x7F) as u8 | 0x80);
            val >>= 7;
        }
        buffer.push(val as u8);
        Ok(())
    }

    // Basic type serialization
    fn serialize_u8(value: u8, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.push(value);
        Ok(())
    }

    fn serialize_u16(value: u16, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn serialize_u32(value: u32, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn serialize_u64(value: u64, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn serialize_i64(value: i64, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn serialize_bool(value: bool, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        buffer.push(if value { 1 } else { 0 });
        Ok(())
    }

    fn serialize_string(value: &str, buffer: &mut Vec<u8>) -> SerializerResult<()> {
        let bytes = value.as_bytes();
        Self::serialize_u16(bytes.len() as u16, buffer)?;
        buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn serialize_bytes(value: &[u8], buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_u32(value.len() as u32, buffer)?;
        buffer.extend_from_slice(value);
        Ok(())
    }

    fn serialize_object_id_vec(value: &[ObjectId], buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_u16(value.len() as u16, buffer)?;
        for id in value {
            Self::serialize_object_id(id, buffer)?;
        }
        Ok(())
    }

    fn serialize_extensions(extensions: &[Extension], buffer: &mut Vec<u8>) -> SerializerResult<()> {
        Self::serialize_u16(extensions.len() as u16, buffer)?;
        for extension in extensions {
            Self::serialize_u8(extension.type_id, buffer)?;
            Self::serialize_bytes(&extension.data, buffer)?;
        }
        Ok(())
    }

    // Helper deserialization methods
    fn deserialize_object_id(data: &[u8], offset: &mut usize) -> SerializerResult<ObjectId> {
        if *offset + 8 > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for ObjectId".to_string(),
            });
        }

        let bytes = &data[*offset..*offset + 8];
        *offset += 8;
        
        ObjectId::from_bytes(bytes).map_err(|e| SerializerError::DeserializationFailed {
            reason: format!("Invalid ObjectId: {:?}", e),
        })
    }

    fn deserialize_asset_amount(data: &[u8], offset: &mut usize) -> SerializerResult<AssetAmount> {
        let amount = Self::deserialize_i64(data, offset)?;
        let asset_id = Self::deserialize_object_id(data, offset)?;
        Ok(AssetAmount { amount, asset_id })
    }

    fn deserialize_optional_memo(data: &[u8], offset: &mut usize) -> SerializerResult<Option<Memo>> {
        let present = Self::deserialize_u8(data, offset)?;
        if present == 1 {
            Ok(Some(Self::deserialize_memo(data, offset)?))
        } else {
            Ok(None)
        }
    }

    fn deserialize_memo(data: &[u8], offset: &mut usize) -> SerializerResult<Memo> {
        let from = Self::deserialize_string(data, offset)?;
        let to = Self::deserialize_string(data, offset)?;
        let nonce = Self::deserialize_u64(data, offset)?;
        let message = Self::deserialize_bytes(data, offset)?;
        Ok(Memo { from, to, nonce, message })
    }

    fn deserialize_authority(data: &[u8], offset: &mut usize) -> SerializerResult<Authority> {
        let weight_threshold = Self::deserialize_u32(data, offset)?;
        
        // Deserialize account auths
        let account_auths_count = Self::deserialize_u16(data, offset)?;
        let mut account_auths = HashMap::new();
        for _ in 0..account_auths_count {
            let account_id = Self::deserialize_object_id(data, offset)?;
            let weight = Self::deserialize_u16(data, offset)?;
            account_auths.insert(account_id, weight);
        }

        // Deserialize key auths
        let key_auths_count = Self::deserialize_u16(data, offset)?;
        let mut key_auths = HashMap::new();
        for _ in 0..key_auths_count {
            let public_key = Self::deserialize_string(data, offset)?;
            let weight = Self::deserialize_u16(data, offset)?;
            key_auths.insert(public_key, weight);
        }

        // Deserialize address auths
        let address_auths_count = Self::deserialize_u16(data, offset)?;
        let mut address_auths = HashMap::new();
        for _ in 0..address_auths_count {
            let address = Self::deserialize_string(data, offset)?;
            let weight = Self::deserialize_u16(data, offset)?;
            address_auths.insert(address, weight);
        }

        Ok(Authority {
            weight_threshold,
            account_auths,
            key_auths,
            address_auths,
        })
    }

    fn deserialize_optional_authority(data: &[u8], offset: &mut usize) -> SerializerResult<Option<Authority>> {
        let present = Self::deserialize_u8(data, offset)?;
        if present == 1 {
            Ok(Some(Self::deserialize_authority(data, offset)?))
        } else {
            Ok(None)
        }
    }

    // Placeholder deserialization methods for complex types
    fn deserialize_account_options(data: &[u8], offset: &mut usize) -> SerializerResult<crate::chain::AccountOptions> {
        // Skip placeholder data
        *offset += 32;
        Ok(crate::chain::AccountOptions::default())
    }

    fn deserialize_optional_account_options(data: &[u8], offset: &mut usize) -> SerializerResult<Option<crate::chain::AccountOptions>> {
        let present = Self::deserialize_u8(data, offset)?;
        if present == 1 {
            Ok(Some(Self::deserialize_account_options(data, offset)?))
        } else {
            Ok(None)
        }
    }

    fn deserialize_asset_options(data: &[u8], offset: &mut usize) -> SerializerResult<crate::chain::AssetOptions> {
        // Skip placeholder data
        *offset += 64;
        Ok(crate::chain::AssetOptions::default())
    }

    fn deserialize_optional_bitasset_options(data: &[u8], offset: &mut usize) -> SerializerResult<Option<crate::chain::BitassetOptions>> {
        let present = Self::deserialize_u8(data, offset)?;
        if present == 1 {
            // Skip placeholder data
            *offset += 32;
            Ok(Some(crate::chain::BitassetOptions::default()))
        } else {
            Ok(None)
        }
    }

    // Basic type deserialization
    fn deserialize_u8(data: &[u8], offset: &mut usize) -> SerializerResult<u8> {
        if *offset >= data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for u8".to_string(),
            });
        }
        let value = data[*offset];
        *offset += 1;
        Ok(value)
    }

    fn deserialize_u16(data: &[u8], offset: &mut usize) -> SerializerResult<u16> {
        if *offset + 2 > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for u16".to_string(),
            });
        }
        let bytes = &data[*offset..*offset + 2];
        *offset += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn deserialize_u32(data: &[u8], offset: &mut usize) -> SerializerResult<u32> {
        if *offset + 4 > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for u32".to_string(),
            });
        }
        let bytes = &data[*offset..*offset + 4];
        *offset += 4;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn deserialize_u64(data: &[u8], offset: &mut usize) -> SerializerResult<u64> {
        if *offset + 8 > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for u64".to_string(),
            });
        }
        let bytes = &data[*offset..*offset + 8];
        *offset += 8;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn deserialize_i64(data: &[u8], offset: &mut usize) -> SerializerResult<i64> {
        if *offset + 8 > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for i64".to_string(),
            });
        }
        let bytes = &data[*offset..*offset + 8];
        *offset += 8;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn deserialize_bool(data: &[u8], offset: &mut usize) -> SerializerResult<bool> {
        let value = Self::deserialize_u8(data, offset)?;
        Ok(value != 0)
    }

    fn deserialize_string(data: &[u8], offset: &mut usize) -> SerializerResult<String> {
        let length = Self::deserialize_u16(data, offset)? as usize;
        if *offset + length > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for string".to_string(),
            });
        }
        let bytes = &data[*offset..*offset + length];
        *offset += length;
        String::from_utf8(bytes.to_vec()).map_err(|_| SerializerError::DeserializationFailed {
            reason: "Invalid UTF-8 in string".to_string(),
        })
    }

    fn deserialize_bytes(data: &[u8], offset: &mut usize) -> SerializerResult<Vec<u8>> {
        let length = Self::deserialize_u32(data, offset)? as usize;
        if *offset + length > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for bytes".to_string(),
            });
        }
        let bytes = data[*offset..*offset + length].to_vec();
        *offset += length;
        Ok(bytes)
    }

    fn deserialize_object_id_vec(data: &[u8], offset: &mut usize) -> SerializerResult<Vec<ObjectId>> {
        let count = Self::deserialize_u16(data, offset)?;
        let mut result = Vec::new();
        for _ in 0..count {
            result.push(Self::deserialize_object_id(data, offset)?);
        }
        Ok(result)
    }

    fn deserialize_extensions(data: &[u8], offset: &mut usize) -> SerializerResult<Vec<Extension>> {
        let count = Self::deserialize_u16(data, offset)?;
        let mut result = Vec::new();
        for _ in 0..count {
            let type_id = Self::deserialize_u8(data, offset)?;
            let extension_data = Self::deserialize_bytes(data, offset)?;
            result.push(Extension {
                type_id,
                data: extension_data,
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ObjectId;

    #[test]
    fn test_basic_serialization() {
        let mut buffer = Vec::new();
        
        SerializerOperation::serialize_u32(0x12345678, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x78, 0x56, 0x34, 0x12]);
        
        let mut offset = 0;
        let value = SerializerOperation::deserialize_u32(&buffer, &mut offset).unwrap();
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_string_serialization() {
        let mut buffer = Vec::new();
        let test_string = "Hello, R-Squared!";
        
        SerializerOperation::serialize_string(test_string, &mut buffer).unwrap();
        
        let mut offset = 0;
        let deserialized = SerializerOperation::deserialize_string(&buffer, &mut offset).unwrap();
        assert_eq!(deserialized, test_string);
    }

    #[test]
    fn test_operation_type_id() {
        // Test basic type ID retrieval
        assert_eq!(SerializerOperation::get_operation_type_id(&Operation::Transfer {
            from: ObjectId::from_string("1.2.1").unwrap(),
            to: ObjectId::from_string("1.2.2").unwrap(),
            amount: AssetAmount {
                amount: 1000,
                asset_id: ObjectId::from_string("1.3.0").unwrap(),
            },
            fee: AssetAmount {
                amount: 10,
                asset_id: ObjectId::from_string("1.3.0").unwrap(),
            },
            memo: None,
            extensions: vec![],
        }).unwrap(), 0x00);
    }
}