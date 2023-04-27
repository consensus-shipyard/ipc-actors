mod submission;
mod voting;

use fvm_ipld_encoding::serde_bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use crate::vote::submission::EpochVoteSubmissions;
pub use crate::vote::voting::Voting;

/// The vote trait that requires each vote to be unique by `unique_key`.
pub trait UniqueVote: PartialEq + Clone {
    /// Outputs the unique bytes key of the vote
    fn unique_key(&self) -> anyhow::Result<UniqueBytesKey>;
}

// pub type UniqueBytesKey = Vec<u8>;
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct UniqueBytesKey(pub Vec<u8>);

impl UniqueBytesKey {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq<Vec<u8>> for UniqueBytesKey {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

impl PartialEq<UniqueBytesKey> for Vec<u8> {
    fn eq(&self, other: &UniqueBytesKey) -> bool {
        self.as_slice() == other.0.as_slice()
    }
}

impl Serialize for UniqueBytesKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for UniqueBytesKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(UniqueBytesKey(bytes))
    }
}
