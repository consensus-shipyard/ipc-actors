use anyhow::anyhow;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fvm_ipld_encoding::DAG_CBOR;
use fvm_ipld_encoding::{serde_bytes, to_vec};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::subnet_id::SubnetID;
use lazy_static::lazy_static;
use primitives::{TCid, TLink};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::CrossMsgs;

lazy_static! {
    // Default CID used for the genesis checkpoint. Using
    // TCid::default() leads to corrupting the fvm datastore
    // for storing the cid of an inaccessible HAMT.
    pub static ref CHECKPOINT_GENESIS_CID: Cid =
        Cid::new_v1(DAG_CBOR, Code::Blake2b256.digest("genesis".as_bytes()));
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct Checkpoint {
    pub data: CheckData,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl Checkpoint {
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
    pub fn prev_check(&self) -> &TCid<TLink<Checkpoint>> {
        &self.data.prev_check
    }

    /// return cross_msg included in the checkpoint.
    pub fn cross_msgs(&self) -> Option<&CrossMsgMeta> {
        self.data.cross_msgs.as_ref()
    }

    /// set cross_msg included in the checkpoint.
    pub fn set_cross_msgs(&mut self, cm: CrossMsgMeta) {
        self.data.cross_msgs = Some(cm)
    }

    /// return cross_msg included in the checkpoint as mutable reference
    pub fn cross_msgs_mut(&mut self) -> Option<&mut CrossMsgMeta> {
        self.data.cross_msgs.as_mut()
    }

    /// Add the cid of a checkpoint from a child subnet for further propagation
    /// to the upper layerse of the hierarchy.
    pub fn add_child_check(&mut self, commit: &Checkpoint) -> anyhow::Result<()> {
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
    pub prev_check: TCid<TLink<Checkpoint>>,
    pub children: Vec<ChildCheck>,
    pub cross_msgs: Option<CrossMsgMeta>,
}
impl CheckData {
    pub fn new(id: SubnetID, epoch: ChainEpoch) -> Self {
        Self {
            source: id,
            proof: Vec::new(),
            epoch,
            prev_check: CHECKPOINT_GENESIS_CID.clone().into(),
            children: Vec::new(),
            cross_msgs: None,
        }
    }
}

// CrossMsgMeta sends an aggregate of all messages being propagated up in
// the checkpoint.
#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize_tuple, Deserialize_tuple)]
pub struct CrossMsgMeta {
    pub msgs_cid: TCid<TLink<CrossMsgs>>,
    pub nonce: u64,
    pub value: TokenAmount,
    pub fee: TokenAmount,
}

impl CrossMsgMeta {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ChildCheck {
    pub source: SubnetID,
    pub checks: Vec<TCid<TLink<Checkpoint>>>,
}

/// CheckpointEpoch returns the epoch of the next checkpoint
/// that needs to be signed
///
/// Return the template of the checkpoint template that has been
/// frozen and that is ready for signing and commitment in the
/// current window.
pub fn checkpoint_epoch(epoch: ChainEpoch, period: ChainEpoch) -> ChainEpoch {
    (epoch / period) * period
}

/// WindowEpoch returns the epoch of the active checkpoint window
///
/// Determines the epoch to which new checkpoints and xshard transactions need
/// to be assigned.
pub fn window_epoch(epoch: ChainEpoch, period: ChainEpoch) -> ChainEpoch {
    let ind = epoch / period;
    period * (ind + 1)
}
