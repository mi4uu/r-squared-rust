//! Object ID implementation

/// Object ID for blockchain objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectId(String);

impl ObjectId {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}