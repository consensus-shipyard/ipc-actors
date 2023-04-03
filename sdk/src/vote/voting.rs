use crate::vote::submission::VoteExecutionStatus;
use crate::vote::{EpochVoteSubmissions, UniqueVote};
use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use primitives::{TCid, THamt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

/// Handle the epoch voting
#[derive(PartialEq, Eq, Clone)]
pub struct Voting<Vote> {
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
    pub epoch_vote_submissions: TCid<THamt<ChainEpoch, EpochVoteSubmissions<Vote>>>,
}

impl<Vote: UniqueVote + DeserializeOwned + Serialize> Voting<Vote> {
    pub fn new<BS: Blockstore>(
        store: &BS,
        genesis_epoch: ChainEpoch,
        period: ChainEpoch,
    ) -> anyhow::Result<Voting<Vote>> {
        Ok(Self {
            genesis_epoch,
            submission_period: period,
            last_voting_executed_epoch: genesis_epoch,
            executable_epoch_queue: None,
            epoch_vote_submissions: TCid::new_hamt(store)?,
        })
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
        // We are doing this manually because we have to modify `state` while processing the `hamt`.
        // The current `self.epoch_vote_submissions.modify(...)` does not allow us to modify state in the
        // function closure passed to modify.
        let mut hamt = self.epoch_vote_submissions.load(store)?;

        let epoch_key = BytesKey::from(epoch.to_be_bytes().as_slice());
        let mut submission = match hamt.get(&epoch_key)? {
            Some(s) => s.clone(),
            None => EpochVoteSubmissions::<Vote>::new(store)?,
        };

        let most_voted_weight = submission.submit(store, submitter, submitter_weight, vote)?;
        let execution_status = submission.derive_execution_status(total_weight, most_voted_weight);

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
                    return Ok(None);
                }

                // we reach consensus in the checkpoints submission
                self.last_voting_executed_epoch = epoch;

                let msgs = submission.load_most_voted_submission(store)?.unwrap();
                hamt.delete(&epoch_key)?;

                Some(msgs)
            }
        };

        // don't forget to flush
        self.epoch_vote_submissions = TCid::from(hamt.flush()?);

        Ok(messages)
    }

    pub fn dump_next_executable_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
    ) -> anyhow::Result<Option<Vote>> {
        let epoch_queue = match self.executable_epoch_queue.as_mut() {
            None => return Ok(None),
            Some(queue) => queue,
        };

        match epoch_queue.first() {
            None => {
                unreachable!("`epoch_queue` is not None, it should not be empty, report bug")
            }
            Some(epoch) => {
                if *epoch > self.last_voting_executed_epoch + self.submission_period {
                    log::debug!("earliest executable epoch not the same cron period");
                    return Ok(None);
                }
            }
        }

        let epoch = epoch_queue.pop_first().unwrap();

        if epoch_queue.is_empty() {
            self.executable_epoch_queue = None;
        }

        self.epoch_vote_submissions.modify(store, |hamt| {
            let epoch_key = BytesKey::from(epoch.to_be_bytes().as_slice());
            let submission = match hamt.get(&epoch_key)? {
                Some(s) => s,
                None => unreachable!("Submission in epoch not found, report bug"),
            };

            self.last_voting_executed_epoch = epoch;

            let vote = submission.load_most_voted_submission(store)?.unwrap();
            hamt.delete(&epoch_key)?;

            Ok(Some(vote))
        })
    }

    pub fn submission_period(&self) -> ChainEpoch {
        self.submission_period
    }

    pub fn epoch_vote_submissions(&self) -> TCid<THamt<ChainEpoch, EpochVoteSubmissions<Vote>>> {
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

    fn insert_executable_epoch(&mut self, epoch: ChainEpoch) {
        match self.executable_epoch_queue.as_mut() {
            None => self.executable_epoch_queue = Some(BTreeSet::from([epoch])),
            Some(queue) => {
                queue.insert(epoch);
            }
        }
    }
}

impl<V: Serialize> Serialize for Voting<V> {
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
        );
        inner.serialize(serde_tuple::Serializer(serializer))
    }
}

impl<'de, V: DeserializeOwned> Deserialize<'de> for Voting<V> {
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
        );
        let inner = <Inner<V>>::deserialize(serde_tuple::Deserializer(deserializer))?;
        Ok(Voting {
            genesis_epoch: inner.0,
            submission_period: inner.1,
            last_voting_executed_epoch: inner.2,
            executable_epoch_queue: inner.3,
            epoch_vote_submissions: inner.4,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vote::voting::Voting;
    use crate::vote::EpochVoteSubmissions;
    use crate::vote::{UniqueBytesKey, UniqueVote};
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
        }

        let dummy_voting = DummyVoting {
            genesis_epoch: 1,
            submission_period: 2,
            last_voting_executed_epoch: 3,
            executable_epoch_queue: Some(BTreeSet::from([1])),
            epoch_vote_submissions: Default::default(),
        };

        let voting = Voting::<DummyVote> {
            genesis_epoch: 1,
            submission_period: 2,
            last_voting_executed_epoch: 3,
            executable_epoch_queue: Some(BTreeSet::from([1])),
            epoch_vote_submissions: Default::default(),
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
