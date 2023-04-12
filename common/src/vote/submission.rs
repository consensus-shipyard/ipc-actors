//! Contains the inner implementation of the voting process

use crate::vote::{UniqueBytesKey, UniqueVote};
use anyhow::anyhow;
use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use num_traits::Zero;
use primitives::{TCid, THamt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Mul;

pub type Ratio = (u64, u64);

/// Track all the vote submissions of an epoch
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EpochVoteSubmissions<T> {
    /// The summation of the weights from all validator submissions
    pub total_submission_weight: TokenAmount,
    /// The most submitted unique key.
    pub most_voted_key: Option<UniqueBytesKey>,
    /// The addresses of all the submitters
    pub submitters: TCid<THamt<Address, ()>>,
    /// The map to track the submission weight of each unique key
    pub submission_weights: TCid<THamt<UniqueBytesKey, TokenAmount>>,
    /// The different checkpoints, with vote's unique key as key
    pub submissions: TCid<THamt<UniqueBytesKey, T>>,
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

impl<T: UniqueVote + DeserializeOwned + Serialize> EpochVoteSubmissions<T> {
    pub fn new<BS: Blockstore>(store: &BS) -> anyhow::Result<Self> {
        Ok(EpochVoteSubmissions {
            total_submission_weight: TokenAmount::zero(),
            submitters: TCid::new_hamt(store)?,
            most_voted_key: None,
            submission_weights: TCid::new_hamt(store)?,
            submissions: TCid::new_hamt(store)?,
        })
    }

    /// Abort the current round and reset the submission data.
    pub fn abort<BS: Blockstore>(&mut self, store: &BS) -> anyhow::Result<()> {
        self.total_submission_weight = TokenAmount::zero();
        self.submitters = TCid::new_hamt(store)?;
        self.most_voted_key = None;
        self.submission_weights = TCid::new_hamt(store)?;

        // no need reset `self.submissions`, we can still reuse the previous self.submissions
        // new submissions will be inserted, old submission will not be inserted to save
        // gas.

        Ok(())
    }

    /// Submit a vote as the submitter.
    pub fn submit<BS: Blockstore>(
        &mut self,
        store: &BS,
        submitter: Address,
        submitter_weight: TokenAmount,
        vote: T,
    ) -> anyhow::Result<TokenAmount> {
        self.update_submitters(store, submitter)?;
        self.total_submission_weight += &submitter_weight;
        let checkpoint_hash = self.insert_vote(store, vote)?;
        self.update_submission_weight(store, checkpoint_hash, submitter_weight)
    }

    pub fn load_most_voted_submission<BS: Blockstore>(
        &self,
        store: &BS,
    ) -> anyhow::Result<Option<T>> {
        // we will only have one entry in the `most_submitted` set if more than 2/3 has reached
        if let Some(unique_key) = &self.most_voted_key {
            self.get_submission(store, unique_key)
        } else {
            Ok(None)
        }
    }

    pub fn load_most_voted_weight<BS: Blockstore>(
        &self,
        store: &BS,
    ) -> anyhow::Result<Option<TokenAmount>> {
        // we will only have one entry in the `most_submitted` set if more than 2/3 has reached
        if let Some(unique_key) = &self.most_voted_key {
            self.get_submission_weight(store, unique_key)
        } else {
            Ok(None)
        }
    }

    pub fn get_submission<BS: Blockstore>(
        &self,
        store: &BS,
        unique_key: &UniqueBytesKey,
    ) -> anyhow::Result<Option<T>> {
        let hamt = self.submissions.load(store)?;
        let key = BytesKey::from(unique_key.as_slice());
        Ok(hamt.get(&key)?.cloned())
    }

    pub fn derive_execution_status(
        &self,
        total_weight: TokenAmount,
        most_voted_weight: TokenAmount,
        ratio: &Ratio,
    ) -> VoteExecutionStatus {
        // threshold keeps track of the weight of validators that have already
        // voted for the checkpoint
        let threshold = total_weight.clone().mul(ratio.0).div_floor(ratio.1);

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

// Private and internal implementations
impl<T: UniqueVote + DeserializeOwned + Serialize> EpochVoteSubmissions<T> {
    /// Checks if the checkpoint unique key has already inserted in the store
    fn get_submission_weight<BS: Blockstore>(
        &self,
        store: &BS,
        unique_key: &UniqueBytesKey,
    ) -> anyhow::Result<Option<TokenAmount>> {
        let hamt = self.submission_weights.load(store)?;
        let r = hamt.get(&BytesKey::from(unique_key.as_slice()))?;
        Ok(r.cloned())
    }

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

    /// Insert the vote to store if it has not been submitted before. Returns the unique of the checkpoint.
    fn insert_vote<BS: Blockstore>(
        &mut self,
        store: &BS,
        vote: T,
    ) -> anyhow::Result<UniqueBytesKey> {
        let unique_key = vote.unique_key()?;
        let hash_key = BytesKey::from(unique_key.as_slice());

        let hamt = self.submissions.load(store)?;
        if hamt.contains_key(&hash_key)? {
            return Ok(unique_key);
        }

        // checkpoint has not been submitted before
        self.submissions.modify(store, |hamt| {
            hamt.set(hash_key, vote)?;
            Ok(())
        })?;

        Ok(unique_key)
    }

    /// Update submission weight of the unique key. Returns the currently most submitted submission count.
    fn update_submission_weight<BS: Blockstore>(
        &mut self,
        store: &BS,
        unique_key: UniqueBytesKey,
        weight: TokenAmount,
    ) -> anyhow::Result<TokenAmount> {
        let hash_byte_key = BytesKey::from(unique_key.as_slice());

        self.submission_weights.modify(store, |hamt| {
            let new_weight = hamt
                .get(&hash_byte_key)?
                .cloned()
                .unwrap_or_else(TokenAmount::zero)
                + weight;

            // update the new count
            hamt.set(hash_byte_key, new_weight.clone())?;

            // now we compare with the most submitted unique key or vote
            if self.most_voted_key.is_none() {
                // no most submitted unique_key set yet, set to current
                self.most_voted_key = Some(unique_key);
                return Ok(new_weight);
            }

            let most_voted_key = self.most_voted_key.as_mut().unwrap();

            // the current submission is already one of the most submitted entries
            if most_voted_key == &unique_key {
                // the current submission is already the only one submission, no need update

                // return the current checkpoint's count as the current most submitted checkpoint
                return Ok(new_weight);
            }

            // the current submission is not part of the most submitted entries, need to check
            // the most submitted entry to compare if the current submission is exceeding

            let most_submitted_key = BytesKey::from(most_voted_key.as_slice());

            // safe to unwrap as the hamt must contain the key
            let most_submitted_weight = hamt.get(&most_submitted_key)?.unwrap();
            // current submission is not the most voted checkpoints
            // if new_count < *most_submitted_count, we do nothing as the new count is not close to the most submitted
            if new_weight > *most_submitted_weight {
                *most_voted_key = unique_key;
                Ok(new_weight)
            } else {
                Ok(most_submitted_weight.clone())
            }
        })
    }

    /// Checks if the checkpoint unique key has already inserted in the store
    #[cfg(test)]
    fn is_vote_inserted<BS: Blockstore>(
        &self,
        store: &BS,
        unique_key: &UniqueBytesKey,
    ) -> anyhow::Result<bool> {
        let hamt = self.submissions.load(store)?;
        Ok(hamt.contains_key(&BytesKey::from(unique_key.as_slice()))?)
    }
}

impl<T: Serialize> Serialize for EpochVoteSubmissions<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(key) = &self.most_voted_key {
            let inner = (
                &self.total_submission_weight,
                &key,
                &self.submitters,
                &self.submission_weights,
                &self.submissions,
            );
            serde::Serialize::serialize(&inner, serde_tuple::Serializer(serializer))
        } else {
            let inner = (
                &self.total_submission_weight,
                &UniqueBytesKey::new(),
                &self.submitters,
                &self.submission_weights,
                &self.submissions,
            );
            serde::Serialize::serialize(&inner, serde_tuple::Serializer(serializer))
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for EpochVoteSubmissions<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Inner<V> = (
            TokenAmount,
            UniqueBytesKey,
            TCid<THamt<Address, ()>>,
            TCid<THamt<UniqueBytesKey, TokenAmount>>,
            TCid<THamt<UniqueBytesKey, V>>,
        );
        let inner = <Inner<T>>::deserialize(serde_tuple::Deserializer(deserializer))?;

        let most_voted_key = if inner.1.is_empty() { None} else { Some(inner.1) };
        Ok(EpochVoteSubmissions {
            total_submission_weight: inner.0,
            most_voted_key,
            submitters: inner.2,
            submission_weights: inner.3,
            submissions: inner.4,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vote::submission::VoteExecutionStatus;
    use crate::vote::{EpochVoteSubmissions, UniqueBytesKey, UniqueVote};
    use fil_actors_runtime::builtin::HAMT_BIT_WIDTH;
    use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
    use fil_actors_runtime::make_empty_map;
    use fvm_ipld_blockstore::MemoryBlockstore;
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;
    use primitives::{TCid, THamt};
    use serde_tuple::{Deserialize_tuple, Serialize_tuple};

    #[derive(PartialEq, Eq, Clone, Deserialize_tuple, Serialize_tuple, Debug)]
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
        #[derive(Deserialize_tuple, Serialize_tuple, PartialEq, Eq, Clone, Debug)]
        struct DummySubmissions {
            total_submission_weight: TokenAmount,
            most_voted_key: UniqueBytesKey,
            submitters: TCid<THamt<Address, ()>>,
            submission_weights: TCid<THamt<UniqueBytesKey, TokenAmount>>,
            submissions: TCid<THamt<UniqueBytesKey, DummyVote>>,
        }

        let dummy_submissions = DummySubmissions {
            total_submission_weight: TokenAmount::from_atto(100),
            most_voted_key: vec![1, 2, 3],
            submitters: Default::default(),
            submission_weights: Default::default(),
            submissions: Default::default(),
        };

        let submissions = EpochVoteSubmissions::<DummyVote> {
            total_submission_weight: TokenAmount::from_atto(100),
            most_voted_key: Some(vec![1, 2, 3]),
            submitters: Default::default(),
            submission_weights: Default::default(),
            submissions: Default::default(),
        };

        let json1 = serde_json::to_string(&dummy_submissions).unwrap();
        let json2 = serde_json::to_string(&submissions).unwrap();
        assert_eq!(json1, json2);

        let dummy_submissions = DummySubmissions {
            total_submission_weight: TokenAmount::from_atto(100),
            most_voted_key: vec![],
            submitters: Default::default(),
            submission_weights: Default::default(),
            submissions: Default::default(),
        };

        let submissions = EpochVoteSubmissions::<DummyVote> {
            total_submission_weight: TokenAmount::from_atto(100),
            most_voted_key: None,
            submitters: Default::default(),
            submission_weights: Default::default(),
            submissions: Default::default(),
        };

        let json1 = serde_json::to_string(&dummy_submissions).unwrap();
        let json2 = serde_json::to_string(&submissions).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_storage() {
        let store = MemoryBlockstore::new();
        let mut hamt = make_empty_map(&store, HAMT_BIT_WIDTH);

        let submissions = EpochVoteSubmissions::<DummyVote> {
            total_submission_weight: TokenAmount::from_atto(100),
            most_voted_key: Some(vec![1, 2, 3, 4]),
            submitters: Default::default(),
            submission_weights: Default::default(),
            submissions: Default::default(),
        };

        let key = BytesKey::from("1");
        hamt.set(key.clone(), submissions.clone()).unwrap();
        let fetched = hamt.get(&key).unwrap().unwrap();
        assert_eq!(
            fetched.total_submission_weight,
            submissions.total_submission_weight
        );
        assert_eq!(fetched.most_voted_key, submissions.most_voted_key);
        assert_eq!(fetched.submitters, submissions.submitters);
        assert_eq!(fetched.submission_weights, submissions.submission_weights);
        assert_eq!(fetched.submissions, submissions.submissions);
    }

    #[test]
    fn test_new_works() {
        let store = MemoryBlockstore::new();
        let r = EpochVoteSubmissions::<DummyVote>::new(&store);
        assert!(r.is_ok());
    }

    #[test]
    fn test_update_submitters() {
        let store = MemoryBlockstore::new();
        let mut submission = EpochVoteSubmissions::<DummyVote>::new(&store).unwrap();

        let submitter = Address::new_id(0);
        submission.update_submitters(&store, submitter).unwrap();
        assert!(submission.has_submitted(&store, &submitter).unwrap());

        // now submit again, but should fail
        assert!(submission.update_submitters(&store, submitter).is_err());
    }

    #[test]
    fn test_insert_checkpoint() {
        let store = MemoryBlockstore::new();
        let mut submission = EpochVoteSubmissions::<DummyVote>::new(&store).unwrap();

        let checkpoint = DummyVote { key: vec![0] };

        let hash = checkpoint.unique_key().unwrap();

        submission.insert_vote(&store, checkpoint.clone()).unwrap();
        assert!(submission.is_vote_inserted(&store, &hash).unwrap());

        // insert again should not have caused any error
        submission.insert_vote(&store, checkpoint.clone()).unwrap();

        let inserted_checkpoint = submission.get_submission(&store, &hash).unwrap().unwrap();
        assert_eq!(inserted_checkpoint, checkpoint);
    }

    #[test]
    fn test_update_submission_count() {
        let store = MemoryBlockstore::new();
        let mut submission = EpochVoteSubmissions::<DummyVote>::new(&store).unwrap();

        let hash1 = vec![1, 2, 1];
        let hash2 = vec![1, 2, 2];

        // insert hash1, should have only one item
        assert_eq!(submission.most_voted_key, None);
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
        assert_eq!(submission.most_voted_key, Some(hash1.clone()));

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
        assert_eq!(submission.most_voted_key, Some(hash1.clone()));

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
        assert_eq!(submission.most_voted_key, Some(hash2.clone()));

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
        assert_eq!(submission.most_voted_key, Some(hash2.clone()));
    }

    #[test]
    fn test_derive_execution_status() {
        let store = MemoryBlockstore::new();
        let mut s = EpochVoteSubmissions::<DummyVote>::new(&store).unwrap();

        let total_validators = TokenAmount::from_atto(35);
        let total_submissions = TokenAmount::from_atto(10);
        let most_voted_count = TokenAmount::from_atto(5);

        s.total_submission_weight = total_submissions;
        assert_eq!(
            s.derive_execution_status(total_validators, most_voted_count, &(2, 3)),
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
            s.derive_execution_status(total_submissions.clone(), most_voted_count, &(2, 3)),
            VoteExecutionStatus::RoundAbort,
        );

        // We could have 1 submission: A
        // Current submissions and their counts are: A - 4.
        let total_submissions = TokenAmount::from_atto(4);
        let most_voted_count = TokenAmount::from_atto(4);
        s.total_submission_weight = total_submissions;
        assert_eq!(
            s.derive_execution_status(total_validators.clone(), most_voted_count, &(2, 3)),
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
            s.derive_execution_status(total_validators, most_voted_count, &(2, 3)),
            VoteExecutionStatus::ReachingConsensus,
        );
    }
}
