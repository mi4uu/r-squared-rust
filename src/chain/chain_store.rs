//! Chain store implementation

/// Chain store for managing blockchain state
#[derive(Debug, Default)]
pub struct ChainStore;

impl ChainStore {
    /// Create a new chain store
    pub fn new() -> Self {
        Self::default()
    }
}