mod submission;
mod voting;

pub use crate::vote::submission::EpochVoteSubmissions;
pub use crate::vote::voting::Voting;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref RATIO_NUMERATOR: u64 = 2;
    pub static ref RATIO_DENOMINATOR: u64 = 3;
}

pub type UniqueBytesKey = Vec<u8>;

/// The vote trait that requires each vote to be unique by `unique_key`.
pub trait UniqueVote: PartialEq + Clone {
    /// Outputs the unique bytes key of the vote
    fn unique_key(&self) -> anyhow::Result<UniqueBytesKey>;
}
