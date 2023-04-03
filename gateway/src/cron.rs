use ipc_sdk::vote::{UniqueBytesKey, UniqueVote};
use crate::{ensure_message_sorted, StorableMsg};
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use fvm_ipld_encoding::to_vec;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::ValidatorSet;
use num_traits::Zero;

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

impl UniqueVote for CronCheckpoint {
    /// Derive the unique key of the checkpoint using hash function.
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
    fn unique_key(&self) -> anyhow::Result<UniqueBytesKey> {
        ensure_message_sorted(&self.top_down_msgs)?;

        let mh_code = Code::Blake2b256;
        // TODO: to avoid serialization again, maybe we should perform deserialization in the actor
        // TODO: dispatch call to save gas? The actor dispatching contains the raw serialized data,
        // TODO: which we dont have to serialize here again
        Ok(mh_code.digest(&to_vec(self).unwrap()).to_bytes())
    }
}
