mod submission;
mod voting;

pub use crate::vote::submission::EpochVoteSubmissions;
pub use crate::vote::voting::Voting;

pub type UniqueBytesKey = Vec<u8>;

/// The vote trait that requires each vote to be unique by `unique_key`.
pub trait UniqueVote: PartialEq + Clone {
    /// Outputs the unique bytes key of the vote
    fn unique_key(&self) -> anyhow::Result<UniqueBytesKey>;
}
