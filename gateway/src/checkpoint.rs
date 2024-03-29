use crate::ensure_message_sorted;
use anyhow::anyhow;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fil_actors_runtime::runtime::Runtime;
use fvm_ipld_encoding::DAG_CBOR;
use fvm_ipld_encoding::{serde_bytes, to_vec};
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_actor_common::vote::{UniqueBytesKey, UniqueVote};
use ipc_sdk::cross::CrossMsg;
use ipc_sdk::subnet_id::SubnetID;
use ipc_sdk::ValidatorSet;
use lazy_static::lazy_static;
use num_traits::Zero;
use primitives::{TCid, TLink};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

lazy_static! {
    // Default CID used for the genesis checkpoint. Using
    // TCid::default() leads to corrupting the fvm datastore
    // for storing the cid of an inaccessible HAMT.
    pub static ref CHECKPOINT_GENESIS_CID: Cid =
        Cid::new_v1(DAG_CBOR, Code::Blake2b256.digest("genesis".as_bytes()));
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct BottomUpCheckpoint {
    pub data: CheckData,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl UniqueVote for BottomUpCheckpoint {
    fn unique_key(&self) -> anyhow::Result<UniqueBytesKey> {
        Ok(UniqueBytesKey(self.cid().to_bytes()))
    }
}

impl BottomUpCheckpoint {
    pub fn new(id: SubnetID, epoch: ChainEpoch) -> Self {
        Self {
            data: CheckData::new(id, epoch),
            sig: Vec::new(),
        }
    }

    /// return cid for the checkpoint
    pub fn cid(&self) -> Cid {
        let mh_code = Code::Blake2b256;
        // we only use the data of the checkpoint to compute the cid, the signature
        // can change according to the source. We are only interested in the data.
        Cid::new_v1(
            fvm_ipld_encoding::DAG_CBOR,
            mh_code.digest(&to_vec(&self.data).unwrap()),
        )
    }

    /// return checkpoint epoch
    pub fn epoch(&self) -> ChainEpoch {
        self.data.epoch
    }

    /// return signature
    pub fn signature(&self) -> &Vec<u8> {
        &self.sig
    }

    /// set signature of checkpoint
    pub fn set_signature(&mut self, sig: Vec<u8>) {
        self.sig = sig;
    }

    /// return checkpoint source
    pub fn source(&self) -> &SubnetID {
        &self.data.source
    }

    /// return the cid of the previous checkpoint this checkpoint points to.
    pub fn prev_check(&self) -> &TCid<TLink<BottomUpCheckpoint>> {
        &self.data.prev_check
    }

    /// Take the cross messages out of the checkpoint. This will empty the `self.data.cross_msgs`
    /// and replace with None.
    pub fn cross_msgs(&mut self) -> Option<Vec<CrossMsg>> {
        self.data.cross_msgs.cross_msgs.clone()
    }

    pub fn ensure_cross_msgs_sorted(&self) -> anyhow::Result<()> {
        match self.data.cross_msgs.cross_msgs.as_ref() {
            None => Ok(()),
            Some(v) => ensure_message_sorted(v),
        }
    }

    /// Agents may set the source of a checkpoint using f2-based subnetIDs, \
    /// but actors are expected to use f0-based subnetIDs, thus the need to enforce
    /// that the source is a f0-based subnetID.
    pub fn enforce_f0_source(&mut self, rt: &mut impl Runtime) -> anyhow::Result<()> {
        self.data.source = self.source().f0_id(rt);
        Ok(())
    }

    /// Get the sum of values in cross messages
    pub fn total_value(&self) -> TokenAmount {
        match &self.data.cross_msgs.cross_msgs {
            None => TokenAmount::zero(),
            Some(cross_msgs) => {
                let mut value = TokenAmount::zero();
                cross_msgs.iter().for_each(|cross_msg| {
                    value += &cross_msg.msg.value;
                });
                value
            }
        }
    }

    /// Get the total fee of the cross messages
    pub fn total_fee(&self) -> &TokenAmount {
        &self.data.cross_msgs.fee
    }

    pub fn push_cross_msgs(&mut self, cross_msg: CrossMsg, fee: &TokenAmount) {
        self.data.cross_msgs.fee += fee;
        match self.data.cross_msgs.cross_msgs.as_mut() {
            None => self.data.cross_msgs.cross_msgs = Some(vec![cross_msg]),
            Some(v) => v.push(cross_msg),
        };
    }

    /// Add the cid of a checkpoint from a child subnet for further propagation
    /// to the upper layerse of the hierarchy.
    pub fn add_child_check(&mut self, commit: &BottomUpCheckpoint) -> anyhow::Result<()> {
        let cid = TCid::from(commit.cid());
        match self
            .data
            .children
            .iter_mut()
            .find(|m| commit.source() == &m.source)
        {
            // if there is already a structure for that child
            Some(ck) => {
                // check if the cid already exists
                if ck.checks.iter().any(|c| c == &cid) {
                    return Err(anyhow!(
                        "child checkpoint being committed already exists for source {}",
                        commit.source()
                    ));
                }
                // and if not append to list of child checkpoints.
                ck.checks.push(cid);
            }
            None => {
                // if none, new structure for source
                self.data.children.push(ChildCheck {
                    source: commit.data.source.clone(),
                    checks: vec![cid],
                });
            }
        };
        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct CheckData {
    pub source: SubnetID,
    // subnet-specific proof propagated as part of the checkpoint (initially we propagate)
    // a pointer to the tipset at the specific epoch of  the checkpoint.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    pub epoch: ChainEpoch,
    pub prev_check: TCid<TLink<BottomUpCheckpoint>>,
    pub children: Vec<ChildCheck>,
    pub cross_msgs: BatchCrossMsgs,
}

#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub struct BatchCrossMsgs {
    pub cross_msgs: Option<Vec<CrossMsg>>,
    pub fee: TokenAmount,
}

impl CheckData {
    pub fn new(id: SubnetID, epoch: ChainEpoch) -> Self {
        Self {
            source: id,
            proof: Vec::new(),
            epoch,
            prev_check: (*CHECKPOINT_GENESIS_CID).into(),
            children: Vec::new(),
            cross_msgs: BatchCrossMsgs::default(),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ChildCheck {
    pub source: SubnetID,
    pub checks: Vec<TCid<TLink<BottomUpCheckpoint>>>,
}

/// CheckpointEpoch returns the epoch of the next checkpoint
/// that needs to be signed
///
/// Return the template of the checkpoint template that has been
/// frozen and that is ready for signing and commitment in the
/// current window.
pub fn checkpoint_epoch(epoch: ChainEpoch, period: ChainEpoch) -> ChainEpoch {
    // TODO: Once we consider different genesis_epoch different to zero
    // we should account for this here.
    (epoch / period) * period
}

/// WindowEpoch returns the epoch of the active checkpoint window
///
/// Determines the epoch to which new checkpoints and cross-net transactions need
/// to be assigned (i.e. the next checkpoint to be committed)
pub fn window_epoch(epoch: ChainEpoch, period: ChainEpoch) -> ChainEpoch {
    // TODO: Once we consider different genesis_epoch different to zero
    // we should account for this here.
    let ind = epoch / period;
    period * (ind + 1)
}

/// Validators tracks all the validator in the subnet. It is useful in handling top-down checkpoints.
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
    /// It expects ID addresses as an input
    pub fn get_validator_weight(&self, rt: &impl Runtime, addr: &Address) -> Option<TokenAmount> {
        self.validators
            .validators()
            .iter()
            .find(|x| match rt.resolve_address(&x.addr) {
                Some(id) => id == *addr,
                None => false,
            })
            .map(|v| v.weight.clone())
    }
}

/// Checkpoints propagated from parent to child to signal the "final view" of the parent chain
/// from the different validators in the subnet.
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct TopDownCheckpoint {
    pub epoch: ChainEpoch,
    pub top_down_msgs: Vec<CrossMsg>,
}

impl UniqueVote for TopDownCheckpoint {
    /// Derive the unique key of the checkpoint using hash function.
    ///
    /// To compare the top-down checkpoint and ensure they are the same, we need to make sure the
    /// top_down_msgs are the same. However, the top_down_msgs are vec, they may contain the same
    /// content, but their orders are different. In this case, we need to ensure the same order is
    /// maintained in the top-down checkpoint submission.
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
        Ok(UniqueBytesKey(
            mh_code.digest(&to_vec(self).unwrap()).to_bytes(),
        ))
    }
}

impl Serialize for BatchCrossMsgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(v) = self.cross_msgs.as_ref() {
            let inner = (v, &self.fee);
            serde::Serialize::serialize(&inner, serde_tuple::Serializer(serializer))
        } else {
            let inner: (&Vec<CrossMsg>, &TokenAmount) = (&vec![], &self.fee);
            serde::Serialize::serialize(&inner, serde_tuple::Serializer(serializer))
        }
    }
}

impl<'de> Deserialize<'de> for BatchCrossMsgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Inner = (Vec<CrossMsg>, TokenAmount);
        let inner = Inner::deserialize(serde_tuple::Deserializer(deserializer))?;
        Ok(BatchCrossMsgs {
            cross_msgs: if inner.0.is_empty() {
                None
            } else {
                Some(inner.0)
            },
            fee: inner.1,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::BottomUpCheckpoint;
    use cid::Cid;
    use fil_actors_runtime::cbor;
    use ipc_sdk::subnet_id::SubnetID;
    use primitives::TCid;
    use std::str::FromStr;

    #[test]
    fn test_serialization() {
        let mut checkpoint = BottomUpCheckpoint::new(SubnetID::from_str("/r123").unwrap(), 10);
        checkpoint.data.prev_check = TCid::from(
            Cid::from_str("bafy2bzacecnamqgqmifpluoeldx7zzglxcljo6oja4vrmtj7432rphldpdmm2")
                .unwrap(),
        );

        let raw_bytes = cbor::serialize(&checkpoint, "").unwrap();
        let de = cbor::deserialize(&raw_bytes, "").unwrap();
        assert_eq!(checkpoint, de);
    }
}
