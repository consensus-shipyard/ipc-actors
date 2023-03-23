use crate::{ensure_message_sorted, StorableMsg};
use anyhow::anyhow;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::to_vec;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::ValidatorSet;
use lazy_static::lazy_static;
use num_traits::Zero;
use primitives::{TCid, THamt};
use std::ops::Mul;

pub type HashOutput = Vec<u8>;

lazy_static! {
    pub static ref RATIO_NUMERATOR: u64 = 2;
    pub static ref RATIO_DENOMINATOR: u64 = 3;
}

/// Validators tracks all the validator in the subnet. It is useful in handling cron checkpoints.
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct Validators {
    /// The validator set that holds all the validators
    pub validators: ValidatorSet,
    /// Tracks the total weight of the validators
    pub total_weight: TokenAmount,
}

impl Validators {
    pub fn new(validators: ValidatorSet) -> Self {
        let mut weight = TokenAmount::zero();
        for v in validators.validators() {
            weight += v.weight.clone();
        }
        Self {
            validators,
            total_weight: weight,
        }
    }

    /// Get the weight of a validator
    pub fn get_validator_weight(&self, addr: &Address) -> Option<TokenAmount> {
        self.validators
            .validators()
            .iter()
            .find(|x| x.addr == *addr)
            .map(|v| v.weight.clone())
    }
}

/// Checkpoints propagated from parent to child to signal the "final view" of the parent chain
/// from the different validators in the subnet.
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct CronCheckpoint {
    pub epoch: ChainEpoch,
    pub top_down_msgs: Vec<StorableMsg>,
}

impl CronCheckpoint {
    /// Hash the checkpoint.
    ///
    /// To compare the cron checkpoint and ensure they are the same, we need to make sure the
    /// top_down_msgs are the same. However, the top_down_msgs are vec, they may contain the same
    /// content, but their orders are different. In this case, we need to ensure the same order is
    /// maintained in the cron checkpoint submission.
    ///
    /// To ensure we have the same consistent output for different submissions, we require:
    ///     - top down messages are sorted by `nonce` in descending order
    ///
    /// Actor will not perform sorting to save gas. Client should do it, actor just check.
    pub fn hash(&self) -> anyhow::Result<HashOutput> {
        ensure_message_sorted(&self.top_down_msgs)?;

        let mh_code = Code::Blake2b256;
        // TODO: to avoid serialization again, maybe we should perform deserialization in the actor
        // TODO: dispatch call to save gas? The actor dispatching contains the raw serialized data,
        // TODO: which we dont have to serialize here again
        Ok(mh_code.digest(&to_vec(self).unwrap()).to_bytes())
    }
}

/// Track all the cron checkpoint submissions of an epoch
#[derive(Serialize_tuple, Deserialize_tuple, PartialEq, Eq, Clone)]
pub struct CronSubmission {
    /// The summation of the weights from all validator submissions
    total_submission_weight: TokenAmount,
    /// The most submitted hash.
    most_voted_hash: Option<HashOutput>,
    /// The addresses of all the submitters
    submitters: TCid<THamt<Address, ()>>,
    /// The map to track the submission weight of each hash
    submission_weights: TCid<THamt<HashOutput, TokenAmount>>,
    /// The different cron checkpoints, with cron checkpoint hash as key
    submissions: TCid<THamt<HashOutput, CronCheckpoint>>,
}

impl CronSubmission {
    pub fn new<BS: Blockstore>(store: &BS) -> anyhow::Result<Self> {
        Ok(CronSubmission {
            total_submission_weight: TokenAmount::zero(),
            submitters: TCid::new_hamt(store)?,
            most_voted_hash: None,
            submission_weights: TCid::new_hamt(store)?,
            submissions: TCid::new_hamt(store)?,
        })
    }

    /// Abort the current round and reset the submission data.
    pub fn abort<BS: Blockstore>(&mut self, store: &BS) -> anyhow::Result<()> {
        self.total_submission_weight = TokenAmount::zero();
        self.submitters = TCid::new_hamt(store)?;
        self.most_voted_hash = None;
        self.submission_weights = TCid::new_hamt(store)?;

        // no need reset `self.submissions`, we can still reuse the previous self.submissions
        // new submissions will be inserted, old submission will not be inserted to save
        // gas.

        Ok(())
    }

    /// Submit a cron checkpoint as the submitter.
    pub fn submit<BS: Blockstore>(
        &mut self,
        store: &BS,
        submitter: Address,
        submitter_weight: TokenAmount,
        checkpoint: CronCheckpoint,
    ) -> anyhow::Result<TokenAmount> {
        self.update_submitters(store, submitter)?;
        self.total_submission_weight += &submitter_weight;
        let checkpoint_hash = self.insert_checkpoint(store, checkpoint)?;
        self.update_submission_weight(store, checkpoint_hash, submitter_weight)
    }

    pub fn load_most_submitted_checkpoint<BS: Blockstore>(
        &self,
        store: &BS,
    ) -> anyhow::Result<Option<CronCheckpoint>> {
        // we will only have one entry in the `most_submitted` set if more than 2/3 has reached
        if let Some(hash) = &self.most_voted_hash {
            self.get_submission(store, hash)
        } else {
            Ok(None)
        }
    }

    pub fn most_voted_weight<BS: Blockstore>(&self, store: &BS) -> anyhow::Result<TokenAmount> {
        // we will only have one entry in the `most_submitted` set if more than 2/3 has reached
        if let Some(hash) = &self.most_voted_hash {
            Ok(self
                .get_submission_weight(store, hash)?
                .unwrap_or_else(TokenAmount::zero))
        } else {
            Ok(TokenAmount::zero())
        }
    }

    pub fn get_submission<BS: Blockstore>(
        &self,
        store: &BS,
        hash: &HashOutput,
    ) -> anyhow::Result<Option<CronCheckpoint>> {
        let hamt = self.submissions.load(store)?;
        let key = BytesKey::from(hash.as_slice());
        Ok(hamt.get(&key)?.cloned())
    }

    pub fn derive_execution_status(
        &self,
        total_weight: TokenAmount,
        most_voted_weight: TokenAmount,
    ) -> VoteExecutionStatus {
        let threshold = total_weight
            .clone()
            .mul(*RATIO_NUMERATOR)
            .div_floor(*RATIO_DENOMINATOR);

        // note that we require THRESHOLD to be surpassed, equality is not enough!
        if self.total_submission_weight <= threshold {
            return VoteExecutionStatus::ThresholdNotReached;
        }

        // now we have reached the threshold

        // consensus reached
        if most_voted_weight > threshold {
            return VoteExecutionStatus::ConsensusReached;
        }

        // now the total submissions has reached the threshold, but the most submitted vote
        // has yet to reach the threshold, that means consensus has not reached.

        // we do a early termination check, to see if consensus will ever be reached.
        //
        // consider an example that consensus will never be reached:
        //
        // -------- | -------------------------|--------------- | ------------- |
        //     MOST_VOTED                 THRESHOLD     TOTAL_SUBMISSIONS  TOTAL_WEIGHT
        //
        // we see MOST_VOTED is smaller than THRESHOLD, TOTAL_SUBMISSIONS and TOTAL_WEIGHT, if
        // the potential extra votes any vote can obtain, i.e. TOTAL_WEIGHT - TOTAL_SUBMISSIONS,
        // is smaller than or equal to the potential extra vote the most voted can obtain, i.e.
        // THRESHOLD - MOST_VOTED, then consensus will never be reached, no point voting, just abort.
        if threshold - most_voted_weight >= total_weight - &self.total_submission_weight {
            VoteExecutionStatus::RoundAbort
        } else {
            VoteExecutionStatus::ReachingConsensus
        }
    }

    /// Checks if the submitter has already submitted the checkpoint.
    pub fn has_submitted<BS: Blockstore>(
        &self,
        store: &BS,
        submitter: &Address,
    ) -> anyhow::Result<bool> {
        let addr_byte_key = BytesKey::from(submitter.to_bytes());
        let hamt = self.submitters.load(store)?;
        Ok(hamt.contains_key(&addr_byte_key)?)
    }
}

/// The status indicating if the voting should be executed
#[derive(Eq, PartialEq, Debug)]
pub enum VoteExecutionStatus {
    /// The execution threshold has yet to be reached
    ThresholdNotReached,
    /// The voting threshold has reached, but consensus has yet to be reached, needs more
    /// voting to reach consensus
    ReachingConsensus,
    /// Consensus cannot be reached in this round
    RoundAbort,
    /// Execution threshold reached
    ConsensusReached,
}

impl CronSubmission {
    /// Update the total submitters, returns the latest total number of submitters
    fn update_submitters<BS: Blockstore>(
        &mut self,
        store: &BS,
        submitter: Address,
    ) -> anyhow::Result<()> {
        let addr_byte_key = BytesKey::from(submitter.to_bytes());
        self.submitters.modify(store, |hamt| {
            // check the submitter has not submitted before
            if hamt.contains_key(&addr_byte_key)? {
                return Err(anyhow!("already submitted"));
            }

            // now the submitter has not submitted before, mark as submitted
            hamt.set(addr_byte_key, ())?;

            Ok(())
        })
    }

    /// Insert the checkpoint to store if it has not been submitted before. Returns the hash of the checkpoint.
    fn insert_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        checkpoint: CronCheckpoint,
    ) -> anyhow::Result<HashOutput> {
        let hash = checkpoint.hash()?;
        let hash_key = BytesKey::from(hash.as_slice());

        let hamt = self.submissions.load(store)?;
        if hamt.contains_key(&hash_key)? {
            return Ok(hash);
        }

        // checkpoint has not submitted before
        self.submissions.modify(store, |hamt| {
            hamt.set(hash_key, checkpoint)?;
            Ok(())
        })?;

        Ok(hash)
    }

    /// Update submission weight of the hash. Returns the currently most submitted submission count.
    fn update_submission_weight<BS: Blockstore>(
        &mut self,
        store: &BS,
        hash: HashOutput,
        weight: TokenAmount,
    ) -> anyhow::Result<TokenAmount> {
        let hash_byte_key = BytesKey::from(hash.as_slice());

        self.submission_weights.modify(store, |hamt| {
            let new_weight = hamt
                .get(&hash_byte_key)?
                .cloned()
                .unwrap_or_else(TokenAmount::zero)
                + weight;

            // update the new count
            hamt.set(hash_byte_key, new_weight.clone())?;

            // now we compare with the most submitted hash or cron checkpoint
            if self.most_voted_hash.is_none() {
                // no most submitted hash set yet, set to current
                self.most_voted_hash = Some(hash);
                return Ok(new_weight);
            }

            let most_submitted_hash = self.most_voted_hash.as_mut().unwrap();

            // the current submission is already one of the most submitted entries
            if most_submitted_hash == &hash {
                // the current submission is already the only one submission, no need update

                // return the current checkpoint's count as the current most submitted checkpoint
                return Ok(new_weight);
            }

            // the current submission is not part of the most submitted entries, need to check
            // the most submitted entry to compare if the current submission is exceeding

            let most_submitted_key = BytesKey::from(most_submitted_hash.as_slice());

            // safe to unwrap as the hamt must contain the key
            let most_submitted_count = hamt.get(&most_submitted_key)?.unwrap();

            // current submission is not the most voted checkpoints
            // if new_count < *most_submitted_count, we do nothing as the new count is not close to the most submitted
            if new_weight > *most_submitted_count {
                *most_submitted_hash = hash;
                Ok(new_weight)
            } else {
                Ok(most_submitted_count.clone())
            }
        })
    }

    /// Checks if the checkpoint hash has already inserted in the store
    fn get_submission_weight<BS: Blockstore>(
        &self,
        store: &BS,
        hash: &HashOutput,
    ) -> anyhow::Result<Option<TokenAmount>> {
        let hamt = self.submission_weights.load(store)?;
        let r = hamt.get(&BytesKey::from(hash.as_slice()))?;
        Ok(r.cloned())
    }

    /// Checks if the checkpoint hash has already inserted in the store
    #[cfg(test)]
    fn has_checkpoint_inserted<BS: Blockstore>(
        &self,
        store: &BS,
        hash: &HashOutput,
    ) -> anyhow::Result<bool> {
        let hamt = self.submissions.load(store)?;
        Ok(hamt.contains_key(&BytesKey::from(hash.as_slice()))?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{CronCheckpoint, CronSubmission, VoteExecutionStatus};
    use fvm_ipld_blockstore::MemoryBlockstore;
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;

    #[test]
    fn test_new_works() {
        let store = MemoryBlockstore::new();
        let r = CronSubmission::new(&store);
        assert!(r.is_ok());
    }

    #[test]
    fn test_update_submitters() {
        let store = MemoryBlockstore::new();
        let mut submission = CronSubmission::new(&store).unwrap();

        let submitter = Address::new_id(0);
        submission.update_submitters(&store, submitter).unwrap();
        assert!(submission.has_submitted(&store, &submitter).unwrap());

        // now submit again, but should fail
        assert!(submission.update_submitters(&store, submitter).is_err());
    }

    #[test]
    fn test_insert_checkpoint() {
        let store = MemoryBlockstore::new();
        let mut submission = CronSubmission::new(&store).unwrap();

        let checkpoint = CronCheckpoint {
            epoch: 100,
            top_down_msgs: vec![],
        };

        let hash = checkpoint.hash().unwrap();

        submission
            .insert_checkpoint(&store, checkpoint.clone())
            .unwrap();
        assert!(submission.has_checkpoint_inserted(&store, &hash).unwrap());

        // insert again should not have caused any error
        submission
            .insert_checkpoint(&store, checkpoint.clone())
            .unwrap();

        let inserted_checkpoint = submission.get_submission(&store, &hash).unwrap().unwrap();
        assert_eq!(inserted_checkpoint, checkpoint);
    }

    #[test]
    fn test_update_submission_count() {
        let store = MemoryBlockstore::new();
        let mut submission = CronSubmission::new(&store).unwrap();

        let hash1 = vec![1, 2, 1];
        let hash2 = vec![1, 2, 2];

        // insert hash1, should have only one item
        assert_eq!(submission.most_voted_hash, None);
        assert_eq!(
            submission
                .update_submission_weight(&store, hash1.clone(), TokenAmount::from_atto(1))
                .unwrap(),
            TokenAmount::from_atto(1)
        );
        assert_eq!(
            submission
                .get_submission_weight(&store, &hash1)
                .unwrap()
                .unwrap(),
            TokenAmount::from_atto(1)
        );
        assert_eq!(submission.most_voted_hash, Some(hash1.clone()));

        // insert hash2, we should have two items, and there is a tie, hash1 still the most voted
        assert_eq!(
            submission
                .update_submission_weight(&store, hash2.clone(), TokenAmount::from_atto(1))
                .unwrap(),
            TokenAmount::from_atto(1)
        );
        assert_eq!(
            submission
                .get_submission_weight(&store, &hash2)
                .unwrap()
                .unwrap(),
            TokenAmount::from_atto(1)
        );
        assert_eq!(
            submission
                .get_submission_weight(&store, &hash1)
                .unwrap()
                .unwrap(),
            TokenAmount::from_atto(1)
        );
        assert_eq!(submission.most_voted_hash, Some(hash1.clone()));

        // insert hash2 again, we should have only 1 most submitted hash
        assert_eq!(
            submission
                .update_submission_weight(&store, hash2.clone(), TokenAmount::from_atto(1))
                .unwrap(),
            TokenAmount::from_atto(2)
        );
        assert_eq!(
            submission
                .get_submission_weight(&store, &hash2)
                .unwrap()
                .unwrap(),
            TokenAmount::from_atto(2)
        );
        assert_eq!(submission.most_voted_hash, Some(hash2.clone()));

        // insert hash2 again, we should have only 1 most submitted hash, but count incr by 1
        assert_eq!(
            submission
                .update_submission_weight(&store, hash2.clone(), TokenAmount::from_atto(1))
                .unwrap(),
            TokenAmount::from_atto(3)
        );
        assert_eq!(
            submission
                .get_submission_weight(&store, &hash2)
                .unwrap()
                .unwrap(),
            TokenAmount::from_atto(3)
        );
        assert_eq!(submission.most_voted_hash, Some(hash2.clone()));
    }

    #[test]
    fn test_derive_execution_status() {
        let store = MemoryBlockstore::new();
        let mut s = CronSubmission::new(&store).unwrap();

        let total_validators = TokenAmount::from_atto(35);
        let total_submissions = TokenAmount::from_atto(10);
        let most_voted_count = TokenAmount::from_atto(5);

        s.total_submission_weight = total_submissions;
        assert_eq!(
            s.derive_execution_status(total_validators, most_voted_count),
            VoteExecutionStatus::ThresholdNotReached,
        );

        // We could have 3 submissions: A, B, C
        // Current submissions and their counts are: A - 2, B - 2.
        // If the threshold is 1 / 2, we could have:
        //      If the last vote is C, then we should abort.
        //      If the last vote is any of A or B, we can execute.
        // If the threshold is 2 / 3, we have to abort.
        let total_validators = TokenAmount::from_atto(5);
        let total_submissions = TokenAmount::from_atto(4);
        let most_voted_count = TokenAmount::from_atto(2);
        s.total_submission_weight = total_submissions.clone();
        assert_eq!(
            s.derive_execution_status(total_submissions.clone(), most_voted_count),
            VoteExecutionStatus::RoundAbort,
        );

        // We could have 1 submission: A
        // Current submissions and their counts are: A - 4.
        let total_submissions = TokenAmount::from_atto(4);
        let most_voted_count = TokenAmount::from_atto(4);
        s.total_submission_weight = total_submissions;
        assert_eq!(
            s.derive_execution_status(total_validators.clone(), most_voted_count),
            VoteExecutionStatus::ConsensusReached,
        );

        // We could have 2 submission: A, B
        // Current submissions and their counts are: A - 3, B - 1.
        // Say the threshold is 2 / 3. If the last vote is B, we should abort, if the last vote is
        // A, then we have reached consensus. The current votes are in conclusive.
        let total_submissions = TokenAmount::from_atto(4);
        let most_voted_count = TokenAmount::from_atto(3);
        s.total_submission_weight = total_submissions;
        assert_eq!(
            s.derive_execution_status(total_validators, most_voted_count),
            VoteExecutionStatus::ReachingConsensus,
        );
    }
}
