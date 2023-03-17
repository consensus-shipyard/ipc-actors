use crate::StorableMsg;
use anyhow::anyhow;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::to_vec;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use ipc_sdk::ValidatorSet;
use primitives::{TCid, THamt};
use std::cmp::Ordering;
use std::collections::HashSet;

pub type HashOutput = Vec<u8>;
const RATIO_NUMERATOR: u16 = 2;
const RATIO_DENOMINATOR: u16 = 3;

/// Checkpoints propagated from parent to child to signal the "final view" of the parent chain
/// from the different validators in the subnet.
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct CronCheckpoint {
    pub epoch: ChainEpoch,
    pub validators: ValidatorSet,
    pub top_down_msgs: Vec<StorableMsg>,
}

impl CronCheckpoint {
    /// Hash the checkpoint.
    ///
    /// To compare the cron checkpoint and ensure they are the same, we need to make sure the
    /// validators and top_down_msgs are the same. However, the top_down_msgs and validators are vec,
    /// they may contain the same content, but their orders are different. In this case, we need to
    /// ensure the same order is maintained in the cron checkpoint submission.
    ///
    /// To ensure we have the same consistent output for different submissions, we require:
    ///     - validators are sorted by `net_addr` in string ascending order
    ///     - top down messages are sorted by (from, to, nonce) in descending order
    ///
    /// Actor will not perform sorting to save gas. Client should do it, actor just check.
    fn hash(&self) -> anyhow::Result<HashOutput> {
        // check validators
        let validators = self.validators.validators();
        for i in 1..validators.len() {
            match validators[i - 1].net_addr.cmp(&validators[i].net_addr) {
                Ordering::Less => {}
                Ordering::Equal => return Err(anyhow!("validators not unique")),
                Ordering::Greater => return Err(anyhow!("validators not sorted")),
            };
        }

        // check top down msgs
        for i in 1..self.top_down_msgs.len() {
            match compare_top_down_msg(&self.top_down_msgs[i - 1], &self.top_down_msgs[i])? {
                Ordering::Less => {}
                Ordering::Equal => return Err(anyhow!("top down messages not distinct")),
                Ordering::Greater => return Err(anyhow!("top down messages not sorted")),
            };
        }

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
    /// All the submitters
    submitters: TCid<THamt<Address, ()>>,
    /// The most submitted hash. Using set because there might be a tie
    most_submitted_hashes: Option<HashSet<HashOutput>>,
    /// The map to track the max submitted
    submission_counts: TCid<THamt<HashOutput, u16>>,
    /// The different cron checkpoints, with cron checkpoint hash as key
    submissions: TCid<THamt<HashOutput, CronCheckpoint>>,
}

impl CronSubmission {
    pub fn new<BS: Blockstore>(store: &BS) -> anyhow::Result<CronSubmission> {
        Ok(CronSubmission {
            submitters: TCid::new_hamt(store)?,
            most_submitted_hashes: None,
            submission_counts: Default::default(),
            submissions: TCid::new_hamt(store)?,
        })
    }

    /// Submit a cron checkpoint as the submitter. Returns `true` if the submission threshold
    /// is reached, else `false`.
    pub fn submit<BS: Blockstore>(
        &mut self,
        store: &BS,
        submitter: Address,
        checkpoint: CronCheckpoint,
    ) -> anyhow::Result<bool> {
        // TODO: Add validation of validator set logic so that we know the set of validators is correct
        let total_validators = checkpoint.validators.validators().len();

        self.update_submitters(store, submitter)?;

        let checkpoint_hash = self.insert_checkpoint(store, checkpoint)?;
        let most_submitted_count = self.update_submission_count(store, checkpoint_hash)?;

        // use u16 numerator and denominator to avoid floating point calculation and external crate
        // total validators should be within u16::MAX.
        if total_validators as u16 * RATIO_NUMERATOR / RATIO_DENOMINATOR > most_submitted_count {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn load_most_submitted_checkpoint<BS: Blockstore>(
        &self,
        store: &BS,
    ) -> anyhow::Result<Option<CronCheckpoint>> {
        if let Some(most_submitted_hashes) = &self.most_submitted_hashes {
            // we will only have one entry in the `most_submitted` set if more than 2/3 has reached
            let hash = most_submitted_hashes.iter().next().unwrap();
            self.get_submission(store, hash)
        } else {
            Ok(None)
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

    /// Update submission count of the hash. Returns the currently most submitted submission count.
    fn update_submission_count<BS: Blockstore>(
        &mut self,
        store: &BS,
        hash: HashOutput,
    ) -> anyhow::Result<u16> {
        let hash_byte_key = BytesKey::from(hash.as_slice());

        self.submission_counts.modify(store, |hamt| {
            let new_count = hamt.get(&hash_byte_key)?.map(|v| v + 1).unwrap_or(1);

            // update the new count
            hamt.set(hash_byte_key, new_count)?;

            // now we compare with the most submitted hash or cron checkpoint
            if self.most_submitted_hashes.is_none() {
                // no most submitted hash set yet, set to current
                let mut set = HashSet::new();
                set.insert(hash);
                self.most_submitted_hashes = Some(set);
                return Ok(new_count);
            }

            let most_submitted_hashes = self.most_submitted_hashes.as_mut().unwrap();

            // the current submission is already one of the most submitted entries
            if most_submitted_hashes.contains(&hash) {
                if most_submitted_hashes.len() != 1 {
                    // we have more than 1 checkpoint with most number of submissions
                    // now, with the new submission, the current checkpoint will be the most
                    // submitted checkpoint, remove other submissions.
                    most_submitted_hashes.clear();
                    most_submitted_hashes.insert(hash);
                }

                // the current submission is already the only one submission, no need update

                // return the current checkpoint's count as the current most submitted checkpoint
                return Ok(new_count);
            }

            // the current submission is not part of the most submitted entries, need to check
            // the most submitted entry to compare if the current submission is exceeding

            // save to unwrap at the set cannot be empty
            let most_submitted_hash = most_submitted_hashes.iter().next().unwrap();
            let most_submitted_key = BytesKey::from(most_submitted_hash.as_slice());

            // safe to unwrap as the hamt must contain the key
            let most_submitted_count = hamt.get(&most_submitted_key)?.unwrap();

            // current submission was not found in the most submitted checkpoints, the count gas is
            // at least 1, new_count > *most_submitted_count will not happen
            // if new_count < *most_submitted_count, we do nothing as the new count is not close to the most submitted
            if new_count == *most_submitted_count {
                most_submitted_hashes.insert(hash);
            }

            Ok(*most_submitted_count)
        })
    }

    /// Checks if the submitter has already submitted the checkpoint. Currently used only in
    /// tests, but can be used in prod as well.
    #[cfg(test)]
    fn has_submitted<BS: Blockstore>(
        &self,
        store: &BS,
        submitter: &Address,
    ) -> anyhow::Result<bool> {
        let addr_byte_key = BytesKey::from(submitter.to_bytes());
        let hamt = self.submitters.load(store)?;
        Ok(hamt.contains_key(&addr_byte_key)?)
    }

    /// Checks if the checkpoint hash has already inserted in the store
    #[cfg(test)]
    fn has_checkpoint_inserted<BS: Blockstore>(
        &self,
        store: &BS,
        hash: &HashOutput
    ) -> anyhow::Result<bool> {
        let hamt = self.submissions.load(store)?;
        Ok(hamt.contains_key(&BytesKey::from(hash.as_slice()))?)
    }

    /// Checks if the checkpoint hash has already inserted in the store
    #[cfg(test)]
    fn get_submission_count<BS: Blockstore>(
        &self,
        store: &BS,
        hash: &HashOutput
    ) -> anyhow::Result<Option<u16>> {
        let hamt = self.submission_counts.load(store)?;
        let r = hamt.get(&BytesKey::from(hash.as_slice()))?;
        Ok(r.cloned())
    }
}

/// Compare the ordering of two storable messages.
fn compare_top_down_msg(a: &StorableMsg, b: &StorableMsg) -> anyhow::Result<Ordering> {
    let ordering = a.from.raw_addr()?.cmp(&b.from.raw_addr()?);
    if ordering != Ordering::Equal {
        return Ok(ordering);
    }

    let ordering = a.to.raw_addr()?.cmp(&b.to.raw_addr()?);
    if ordering != Ordering::Equal {
        return Ok(ordering);
    }

    Ok(a.nonce.cmp(&b.nonce))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use fvm_ipld_blockstore::MemoryBlockstore;
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;
    use ipc_sdk::address::IPCAddress;
    use ipc_sdk::subnet_id::ROOTNET_ID;
    use crate::{CronCheckpoint, CronSubmission, StorableMsg};
    use crate::cron::compare_top_down_msg;

    macro_rules! some_hashset {
        ($($x:expr),*) => {
            {
                let mut h = std::collections::HashSet::new();
                $(
                h.insert($x);
                )*
                Some(h)
            }
        }
    }

    #[test]
    fn test_new_works() {
        let store = MemoryBlockstore::new();
        let r = CronSubmission::new(&store);
        assert!(r.is_ok());
    }

    #[test]
    fn test_compare_top_down_msg() {
        let a = StorableMsg{
            from: IPCAddress::new(&ROOTNET_ID, &Address::new_id(0)).unwrap(),
            to: IPCAddress::new(&ROOTNET_ID, &Address::new_id(1)).unwrap(),
            method: 0,
            params: RawBytes::default(),
            value: TokenAmount::from_whole(1),
            nonce: 0,
        };

        let b = StorableMsg{
            from: IPCAddress::new(&ROOTNET_ID, &Address::new_id(0)).unwrap(),
            to: IPCAddress::new(&ROOTNET_ID, &Address::new_id(1)).unwrap(),
            method: 0,
            params: RawBytes::default(),
            value: TokenAmount::from_whole(1),
            nonce: 2,
        };

        assert_eq!(compare_top_down_msg(&a, &b).unwrap(), Ordering::Less);
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

        let checkpoint = CronCheckpoint{
            epoch: 100,
            validators: Default::default(),
            top_down_msgs: vec![]
        };

        let hash = checkpoint.hash().unwrap();

        submission.insert_checkpoint(&store, checkpoint.clone()).unwrap();
        assert!(submission.has_checkpoint_inserted(&store, &hash).unwrap());

        // insert again should not have caused any error
        submission.insert_checkpoint(&store, checkpoint.clone()).unwrap();

        let inserted_checkpoint = submission.get_submission(&store, &hash).unwrap().unwrap();
        assert_eq!(inserted_checkpoint, checkpoint);
    }

    #[test]
    fn test_update_submission_count() {
        let store = MemoryBlockstore::new();
        let mut submission = CronSubmission::new(&store).unwrap();

        let hash1 = vec![1, 2, 1];
        let hash2 = vec![1, 2, 2];
        let hash3 = vec![1, 2, 3];

        // insert hash1, should have only one item
        assert_eq!(submission.most_submitted_hashes, None);
        assert_eq!(submission.update_submission_count(&store, hash1.clone()).unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash1).unwrap().unwrap(), 1);
        assert_eq!(submission.most_submitted_hashes, some_hashset!(hash1.clone()));

        // insert hash2, we should have two items, and there is a tie
        assert_eq!(submission.update_submission_count(&store, hash2.clone()).unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash2).unwrap().unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash1).unwrap().unwrap(), 1);
        assert_eq!(submission.most_submitted_hashes, some_hashset!(hash1.clone(), hash2.clone()));

        // insert hash3, we should have three items, and there is still a tie
        assert_eq!(submission.update_submission_count(&store, hash3.clone()).unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash3).unwrap().unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash2).unwrap().unwrap(), 1);
        assert_eq!(submission.get_submission_count(&store, &hash1).unwrap().unwrap(), 1);
        assert_eq!(submission.most_submitted_hashes, some_hashset!(hash3.clone(), hash1.clone(), hash2.clone()));

        // insert hash1 again, we should have only 1 most submitted hash
        assert_eq!(submission.update_submission_count(&store, hash1.clone()).unwrap(), 2);
        assert_eq!(submission.get_submission_count(&store, &hash1).unwrap().unwrap(), 2);
        assert_eq!(submission.most_submitted_hashes, some_hashset!(hash1.clone()));

        // insert hash1 again, we should have only 1 most submitted hash, but count incr by 1
        assert_eq!(submission.update_submission_count(&store, hash1.clone()).unwrap(), 3);
        assert_eq!(submission.get_submission_count(&store, &hash1).unwrap().unwrap(), 3);
        assert_eq!(submission.most_submitted_hashes, some_hashset!(hash1.clone()));
        assert_eq!(submission.most_submitted_hashes.unwrap().len(), 1);
    }
}