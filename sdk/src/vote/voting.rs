use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use primitives::{TCid, THamt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use crate::vote::{EpochVoteSubmissions, UniqueVote};
use crate::vote::submission::VoteExecutionStatus;

/// Handle the epoch voting
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VotingInner<Vote> {
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

impl<Vote: UniqueVote + DeserializeOwned + Serialize> VotingInner<Vote> {
    pub fn new<BS: Blockstore>(
        store: &BS,
        genesis_epoch: ChainEpoch,
        period: ChainEpoch,
    ) -> anyhow::Result<VotingInner<Vote>> {
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

    fn insert_executable_epoch(&mut self, epoch: ChainEpoch) {
        match self.executable_epoch_queue.as_mut() {
            None => self.executable_epoch_queue = Some(BTreeSet::from([epoch])),
            Some(queue) => {
                queue.insert(epoch);
            }
        }
    }
}
