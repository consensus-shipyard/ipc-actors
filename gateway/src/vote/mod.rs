mod submission;
mod voting;

use crate::vote::voting::VotingInner;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use lazy_static::lazy_static;
use primitives::{TCid, THamt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use submission::{EpochVoteSubmissionsInner, VoteExecutionStatus};

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

/// Handle the epoch voting
#[derive(PartialEq, Eq, Clone)]
pub struct Voting<Vote> {
    inner: VotingInner<Vote>,
}

impl<Vote: UniqueVote + DeserializeOwned + Serialize> Voting<Vote> {
    pub fn new<BS: Blockstore>(
        store: &BS,
        genesis_epoch: ChainEpoch,
        period: ChainEpoch,
    ) -> anyhow::Result<Voting<Vote>> {
        Ok(Self {
            inner: VotingInner::new(store, genesis_epoch, period)?,
        })
    }

    pub fn submission_period(&self) -> ChainEpoch {
        self.inner.submission_period
    }

    pub fn epoch_vote_submissions(&self) -> TCid<THamt<ChainEpoch, EpochVoteSubmissions<Vote>>> {
        self.inner.epoch_vote_submissions.clone()
    }

    pub fn last_voting_executed_epoch(&self) -> ChainEpoch {
        self.inner.last_voting_executed_epoch
    }

    pub fn executable_epoch_queue(&self) -> &Option<BTreeSet<ChainEpoch>> {
        &self.inner.executable_epoch_queue
    }

    pub fn genesis_epoch(&self) -> ChainEpoch {
        self.inner.genesis_epoch
    }

    /// Checks if the current epoch is votable
    pub fn epoch_can_vote(&self, epoch: ChainEpoch) -> bool {
        (epoch - self.inner.genesis_epoch) % self.inner.submission_period == 0
    }

    /// Checks if the epoch has already executed
    pub fn is_epoch_executed(&self, epoch: ChainEpoch) -> bool {
        self.inner.last_voting_executed_epoch >= epoch
    }

    pub fn dump_next_executable_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
    ) -> anyhow::Result<Option<Vote>> {
        self.inner.dump_next_executable_vote(store)
    }

    pub fn submit_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
        vote: Vote,
        epoch: ChainEpoch,
        submitter: Address,
        submitter_weight: TokenAmount,
        total_weight: TokenAmount,
    ) -> anyhow::Result<Option<Vote>> {
        self.inner.submit_vote(
            store,
            vote,
            epoch,
            submitter,
            submitter_weight,
            total_weight,
        )
    }
}

/// Track all the vote submissions of an epoch
#[derive(PartialEq, Eq, Clone)]
pub struct EpochVoteSubmissions<Vote> {
    inner: EpochVoteSubmissionsInner<Vote>,
}

impl<Vote: UniqueVote + DeserializeOwned + Serialize> EpochVoteSubmissions<Vote> {
    pub fn new<BS: Blockstore>(store: &BS) -> anyhow::Result<Self> {
        Ok(Self {
            inner: EpochVoteSubmissionsInner::new(store)?,
        })
    }

    /// Abort the current round and reset the submission data.
    pub fn abort<BS: Blockstore>(&mut self, store: &BS) -> anyhow::Result<()> {
        self.inner.abort(store)
    }

    /// Submit a cron checkpoint as the submitter.
    pub fn submit<BS: Blockstore>(
        &mut self,
        store: &BS,
        submitter: Address,
        submitter_weight: TokenAmount,
        vote: Vote,
    ) -> anyhow::Result<TokenAmount> {
        self.inner.submit(&store, submitter, submitter_weight, vote)
    }

    pub fn load_most_voted_submission<BS: Blockstore>(
        &self,
        store: &BS,
    ) -> anyhow::Result<Option<Vote>> {
        self.inner.load_most_voted_submission(&store)
    }

    pub fn most_voted_weight<BS: Blockstore>(&self, store: &BS) -> anyhow::Result<TokenAmount> {
        self.inner.most_voted_weight(&store)
    }

    pub fn get_submission<BS: Blockstore>(
        &self,
        store: &BS,
        unique_key: &UniqueBytesKey,
    ) -> anyhow::Result<Option<Vote>> {
        self.inner.get_submission(&store, unique_key)
    }

    pub fn derive_execution_status(
        &self,
        total_weight: TokenAmount,
        most_voted_weight: TokenAmount,
    ) -> VoteExecutionStatus {
        self.inner
            .derive_execution_status(total_weight, most_voted_weight)
    }

    /// Checks if the submitter has already submitted the checkpoint.
    pub fn has_submitted<BS: Blockstore>(
        &self,
        store: &BS,
        submitter: &Address,
    ) -> anyhow::Result<bool> {
        self.inner.has_submitted(store, submitter)
    }
}

// TODO: need manually impl the serialization because Serialize_tuple and Deserialize_tuple is causing
// TODO: generic type constraint not picking up. Directly impl serialize and deserialize without using
// TODO: inner types.

impl<V: Serialize> Serialize for EpochVoteSubmissions<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serde_tuple::Serializer(serializer))
    }
}

impl<'de, V: DeserializeOwned> Deserialize<'de> for EpochVoteSubmissions<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner =
            <EpochVoteSubmissionsInner<V>>::deserialize(serde_tuple::Deserializer(deserializer))?;
        Ok(EpochVoteSubmissions { inner })
    }
}

impl<V: Serialize> Serialize for Voting<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serde_tuple::Serializer(serializer))
    }
}

impl<'de, V: DeserializeOwned> Deserialize<'de> for Voting<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = <VotingInner<V>>::deserialize(serde_tuple::Deserializer(deserializer))?;
        Ok(Voting { inner })
    }
}
