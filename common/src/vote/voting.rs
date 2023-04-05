use crate::vote::submission::{EpochVoteSubmissions, Ratio, VoteExecutionStatus};
use crate::vote::UniqueVote;
use anyhow::anyhow;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::epoch_key;
use primitives::{TCid, THamt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet; // numerator and denominator

const DEFAULT_THRESHOLD_RATIO: Ratio = (2, 3);

/// Handle the epoch voting
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Voting<T> {
    /// The epoch that the voting started
    pub genesis_epoch: ChainEpoch,
    /// How often the voting should be submitted by validators
    pub submission_period: ChainEpoch,
    /// The last voting epoch that was executed
    pub last_voting_executed_epoch: ChainEpoch,
    /// Contains the executable epochs that are ready to be executed, but has yet to be executed.
    /// This usually happens when previous submission epoch has not executed, but the next submission
    /// epoch is ready to be executed. Most of the time this should be empty, we are wrapping with
    /// Option instead of empty BTreeSet just to save some storage space.
    pub executable_epoch_queue: Option<BTreeSet<ChainEpoch>>,
    pub epoch_vote_submissions: TCid<THamt<ChainEpoch, EpochVoteSubmissions<T>>>,
    /// The voting execution threshold
    pub threshold_ratio: Ratio,
}

impl<T: UniqueVote + DeserializeOwned + Serialize> Default for Voting<T> {
    fn default() -> Self {
        Voting {
            genesis_epoch: 0,
            submission_period: 0,
            last_voting_executed_epoch: 0,
            executable_epoch_queue: None,
            epoch_vote_submissions: TCid::default(),
            threshold_ratio: DEFAULT_THRESHOLD_RATIO,
        }
    }
}

impl<T: UniqueVote + DeserializeOwned + Serialize> Voting<T> {
    pub fn new<BS: Blockstore>(
        store: &BS,
        genesis_epoch: ChainEpoch,
        period: ChainEpoch,
    ) -> anyhow::Result<Voting<T>> {
        Self::new_with_ratio(
            store,
            genesis_epoch,
            period,
            DEFAULT_THRESHOLD_RATIO.0,
            DEFAULT_THRESHOLD_RATIO.1,
        )
    }

    pub fn new_with_ratio<BS: Blockstore>(
        store: &BS,
        genesis_epoch: ChainEpoch,
        period: ChainEpoch,
        ratio_numerator: u64,
        ratio_denominator: u64,
    ) -> anyhow::Result<Voting<T>> {
        Ok(Self {
            genesis_epoch,
            submission_period: period,
            last_voting_executed_epoch: genesis_epoch,
            executable_epoch_queue: None,
            epoch_vote_submissions: TCid::new_hamt(store)?,
            threshold_ratio: (ratio_numerator, ratio_denominator),
        })
    }

    /// Submit a vote at a specific epoch. If the validator threshold is reached, this method would
    /// return the most voted vote, else it returns None.
    ///
    /// Note that this struct does not track the weight, it needs to be managed by external caller.
    pub fn submit_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
        vote: T,
        epoch: ChainEpoch,
        submitter: Address,
        submitter_weight: TokenAmount,
        total_weight: TokenAmount,
    ) -> anyhow::Result<Option<T>> {
        // first we check the epoch is the correct one, we process only it's multiple
        // of topdown_check_period since genesis_epoch
        if !self.epoch_can_vote(epoch) {
            return Err(anyhow!("epoch not allowed"));
        }

        if self.is_epoch_executed(epoch) {
            return Err(anyhow!("epoch already executed"));
        }

        // We are doing this manually because we have to modify `state` while processing the `hamt`.
        // The current `self.epoch_vote_submissions.modify(...)` does not allow us to modify state in the
        // function closure passed to modify.
        let mut hamt = self.epoch_vote_submissions.load(store)?;

        let epoch_key = epoch_key(epoch);
        let mut submission = match hamt.get(&epoch_key)? {
            Some(s) => s.clone(),
            None => EpochVoteSubmissions::<T>::new(store)?,
        };

        let most_voted_weight = submission.submit(store, submitter, submitter_weight, vote)?;
        let execution_status = submission.derive_execution_status(
            total_weight,
            most_voted_weight,
            &self.threshold_ratio,
        );

        let messages = match execution_status {
            VoteExecutionStatus::ThresholdNotReached | VoteExecutionStatus::ReachingConsensus => {
                // threshold or consensus not reached, store submission and return
                hamt.set(epoch_key, submission)?;
                None
            }
            VoteExecutionStatus::RoundAbort => {
                submission.abort(store)?;
                hamt.set(epoch_key, submission)?;
                None
            }
            VoteExecutionStatus::ConsensusReached => {
                if self.last_voting_executed_epoch + self.submission_period != epoch {
                    // there are pending epochs to be executed,
                    // just store the submission and skip execution
                    hamt.set(epoch_key, submission)?;
                    self.insert_executable_epoch(epoch);
                    None
                } else {
                    let msgs = submission.load_most_voted_submission(store)?.unwrap();
                    Some(msgs)
                }
            }
        };

        // don't forget to flush
        self.epoch_vote_submissions = TCid::from(hamt.flush()?);

        Ok(messages)
    }

    /// Checks the `epoch` is the next executable epoch.
    pub fn is_next_executable_epoch(&self, epoch: ChainEpoch) -> bool {
        self.last_voting_executed_epoch + self.submission_period == epoch
    }

    /// Abort a specific epoch.
    pub fn abort_epoch<BS: Blockstore>(
        &mut self,
        store: &BS,
        epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        self.remove_epoch_from_queue(epoch);

        let epoch_key = epoch_key(epoch);
        self.epoch_vote_submissions.modify(store, |hamt| {
            let mut submission = match hamt.get(&epoch_key)? {
                Some(s) => s.clone(),
                None => return Ok(()),
            };

            submission.abort(store)?;
            hamt.set(epoch_key, submission)?;

            Ok(())
        })
    }

    /// Marks the epoch executed, removes the epoch from the `self.executable_epoch_queue` and clears all
    /// the submissions in `self.epoch_vote_submissions`.
    pub fn mark_epoch_executed<BS: Blockstore>(
        &mut self,
        store: &BS,
        epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        if !self.is_next_executable_epoch(epoch) {
            return Err(anyhow!("epoch not the next executable epoch"));
        }

        if let Some(queue) = &self.executable_epoch_queue {
            if queue.contains(&epoch) && queue.first() != Some(&epoch) {
                return Err(anyhow!("epoch not the next executable epoch queue"));
            }
        }

        self.last_voting_executed_epoch = epoch;
        self.remove_epoch_from_queue(epoch);

        let epoch_key = epoch_key(epoch);
        self.epoch_vote_submissions.modify(store, |hamt| {
            hamt.delete(&epoch_key)?;
            Ok(())
        })
    }

    /// Load the next executable epoch and the content to be executed.
    /// This ensures none of the epochs will be stuck. Consider the following example:
    ///
    /// Epoch 10 and 20 are two epochs to be executed. However, all the validators have submitted
    /// epoch 20, and the status is to be executed. However, epoch 10 has yet to be executed. Now,
    /// epoch 10 has reached consensus and executed, but epoch 20 cannot be executed because every
    /// validator has already voted, no one can vote again to trigger the execution. Epoch 20 is stuck.
    ///
    /// This method lets one check if the next epoch can be executed, returns Some(T) if executable.
    pub fn get_next_executable_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
    ) -> anyhow::Result<Option<T>> {
        let epoch_queue = match self.executable_epoch_queue.as_mut() {
            None => return Ok(None),
            Some(queue) => queue,
        };

        let epoch = match epoch_queue.first() {
            None => {
                unreachable!("`epoch_queue` is not None, it should not be empty, report bug")
            }
            Some(epoch) => {
                if *epoch > self.last_voting_executed_epoch + self.submission_period {
                    log::debug!("earliest executable epoch not the same checkpoint period");
                    return Ok(None);
                }
                *epoch
            }
        };

        let hamt = self.epoch_vote_submissions.load(store)?;

        let epoch_key = epoch_key(epoch);
        let submission = match hamt.get(&epoch_key)? {
            Some(s) => s,
            None => unreachable!("Submission in epoch not found, report bug"),
        };

        let vote = submission.load_most_voted_submission(store)?.unwrap();

        Ok(Some(vote))
    }

    pub fn submission_period(&self) -> ChainEpoch {
        self.submission_period
    }

    pub fn epoch_vote_submissions(&self) -> TCid<THamt<ChainEpoch, EpochVoteSubmissions<T>>> {
        self.epoch_vote_submissions.clone()
    }

    pub fn last_voting_executed_epoch(&self) -> ChainEpoch {
        self.last_voting_executed_epoch
    }

    pub fn executable_epoch_queue(&self) -> &Option<BTreeSet<ChainEpoch>> {
        &self.executable_epoch_queue
    }

    pub fn genesis_epoch(&self) -> ChainEpoch {
        self.genesis_epoch
    }

    /// Checks if the current epoch is votable
    pub fn epoch_can_vote(&self, epoch: ChainEpoch) -> bool {
        (epoch - self.genesis_epoch) % self.submission_period == 0
    }

    /// Checks if the epoch has already executed
    pub fn is_epoch_executed(&self, epoch: ChainEpoch) -> bool {
        self.last_voting_executed_epoch >= epoch
    }

    /// Load the most voted submission at a specific epoch
    pub fn load_most_voted_submission(
        &self,
        store: &impl Blockstore,
        epoch: ChainEpoch,
    ) -> anyhow::Result<Option<T>> {
        let hamt = self.epoch_vote_submissions.load(store)?;

        let epoch_key = epoch_key(epoch);

        if let Some(submission) = hamt.get(&epoch_key)? {
            submission.load_most_voted_submission(store)
        } else {
            Ok(None)
        }
    }

    /// Load the most voted weight at a specific epoch
    pub fn load_most_voted_weight(
        &self,
        store: &impl Blockstore,
        epoch: ChainEpoch,
    ) -> anyhow::Result<Option<TokenAmount>> {
        let hamt = self.epoch_vote_submissions.load(store)?;

        let epoch_key = epoch_key(epoch);

        if let Some(submission) = hamt.get(&epoch_key)? {
            submission.load_most_voted_weight(store)
        } else {
            Ok(None)
        }
    }

    fn remove_epoch_from_queue(&mut self, epoch: ChainEpoch) {
        if let Some(queue) = self.executable_epoch_queue.as_mut() {
            queue.remove(&epoch);
            if queue.is_empty() {
                self.executable_epoch_queue = None;
            }
        }
    }

    fn insert_executable_epoch(&mut self, epoch: ChainEpoch) {
        match self.executable_epoch_queue.as_mut() {
            None => self.executable_epoch_queue = Some(BTreeSet::from([epoch])),
            Some(queue) => {
                queue.insert(epoch);
            }
        }
    }
}

impl<T: Serialize> Serialize for Voting<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let inner = (
            &self.genesis_epoch,
            &self.submission_period,
            &self.last_voting_executed_epoch,
            &self.executable_epoch_queue,
            &self.epoch_vote_submissions,
            &self.threshold_ratio,
        );
        inner.serialize(serde_tuple::Serializer(serializer))
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Voting<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Inner<V> = (
            ChainEpoch,
            ChainEpoch,
            ChainEpoch,
            Option<BTreeSet<ChainEpoch>>,
            TCid<THamt<ChainEpoch, EpochVoteSubmissions<V>>>,
            Ratio,
        );
        let inner = <Inner<T>>::deserialize(serde_tuple::Deserializer(deserializer))?;
        Ok(Voting {
            genesis_epoch: inner.0,
            submission_period: inner.1,
            last_voting_executed_epoch: inner.2,
            executable_epoch_queue: inner.3,
            epoch_vote_submissions: inner.4,
            threshold_ratio: inner.5,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vote::submission::Ratio;
    use crate::vote::{EpochVoteSubmissions, UniqueBytesKey, UniqueVote, Voting};
    use fil_actors_runtime::builtin::HAMT_BIT_WIDTH;
    use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
    use fil_actors_runtime::make_empty_map;
    use fvm_ipld_blockstore::MemoryBlockstore;
    use fvm_shared::clock::ChainEpoch;
    use primitives::{TCid, THamt};
    use serde_tuple::{Deserialize_tuple, Serialize_tuple};
    use std::collections::BTreeSet;

    #[derive(PartialEq, Clone, Deserialize_tuple, Serialize_tuple, Debug)]
    struct DummyVote {
        key: UniqueBytesKey,
    }

    impl UniqueVote for DummyVote {
        fn unique_key(&self) -> anyhow::Result<UniqueBytesKey> {
            Ok(self.key.clone())
        }
    }

    #[test]
    fn test_serialization() {
        #[derive(Deserialize_tuple, Serialize_tuple, PartialEq, Clone, Debug)]
        struct DummyVoting {
            genesis_epoch: ChainEpoch,
            submission_period: ChainEpoch,
            last_voting_executed_epoch: ChainEpoch,
            executable_epoch_queue: Option<BTreeSet<ChainEpoch>>,
            epoch_vote_submissions: TCid<THamt<ChainEpoch, EpochVoteSubmissions<DummyVote>>>,
            threshold_ratio: Ratio,
        }

        let dummy_voting = DummyVoting {
            genesis_epoch: 1,
            submission_period: 2,
            last_voting_executed_epoch: 3,
            executable_epoch_queue: Some(BTreeSet::from([1])),
            epoch_vote_submissions: Default::default(),
            threshold_ratio: (2, 3),
        };

        let voting = Voting::<DummyVote> {
            genesis_epoch: 1,
            submission_period: 2,
            last_voting_executed_epoch: 3,
            executable_epoch_queue: Some(BTreeSet::from([1])),
            epoch_vote_submissions: Default::default(),
            threshold_ratio: (2, 3),
        };

        let json1 = serde_json::to_string(&dummy_voting).unwrap();
        let json2 = serde_json::to_string(&voting).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_storage() {
        let store = MemoryBlockstore::new();
        let mut hamt = make_empty_map(&store, HAMT_BIT_WIDTH);

        let voting = Voting::<DummyVote> {
            genesis_epoch: 1,
            submission_period: 2,
            last_voting_executed_epoch: 3,
            executable_epoch_queue: Some(BTreeSet::from([1])),
            epoch_vote_submissions: Default::default(),
            threshold_ratio: (2, 3),
        };

        let key = BytesKey::from("1");
        hamt.set(key.clone(), voting.clone()).unwrap();
        let fetched = hamt.get(&key).unwrap().unwrap();
        assert_eq!(fetched.genesis_epoch, voting.genesis_epoch);
        assert_eq!(fetched.submission_period, voting.submission_period);
        assert_eq!(
            fetched.last_voting_executed_epoch,
            voting.last_voting_executed_epoch
        );
        assert_eq!(
            fetched.executable_epoch_queue,
            voting.executable_epoch_queue
        );
        assert_eq!(
            fetched.epoch_vote_submissions,
            voting.epoch_vote_submissions
        );
    }
}
