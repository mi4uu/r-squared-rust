//! Transaction builder implementation

use crate::error::{ChainError, ChainResult};

/// Transaction builder for creating blockchain transactions
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    operations: Vec<Operation>,
}

/// Placeholder operation type
#[derive(Debug, Clone)]
pub struct Operation {
    pub op_type: String,
    pub data: Vec<u8>,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an operation to the transaction
    pub fn add_operation(&mut self, operation: Operation) -> ChainResult<()> {
        self.operations.push(operation);
        Ok(())
    }

    /// Build the transaction
    pub fn build(&self) -> ChainResult<Transaction> {
        Ok(Transaction {
            operations: self.operations.clone(),
        })
    }
}

/// Placeholder transaction type
#[derive(Debug, Clone)]
pub struct Transaction {
    pub operations: Vec<Operation>,
}