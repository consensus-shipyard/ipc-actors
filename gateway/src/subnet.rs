use anyhow::anyhow;
use fil_actors_runtime::runtime::Runtime;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::repr::{Deserialize_repr, Serialize_repr};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use primitives::{TAmt, TCid};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::{State, CROSSMSG_AMT_BITWIDTH};
use ipc_sdk::subnet_id::SubnetID;

use super::checkpoint::*;
use super::cross::CrossMsg;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Deserialize_repr, Serialize_repr)]
#[repr(i32)]
pub enum Status {
    Active,
    Inactive,
    Killed,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct Subnet {
    pub id: SubnetID,
    pub stake: TokenAmount,
    pub top_down_msgs: TCid<TAmt<CrossMsg, CROSSMSG_AMT_BITWIDTH>>,
    pub topdown_nonce: u64,
    pub circ_supply: TokenAmount,
    pub status: Status,
    pub prev_checkpoint: Option<BottomUpCheckpoint>,
    pub applied_bottomup_nonce: u64,
    // genesis_epoch determines the epoch from which the subnet
    // was registered. This signals the epoch from which
    // the top-down checkpoint can be started.
    pub genesis_epoch: ChainEpoch,
}

impl Subnet {
    pub(crate) fn add_stake(
        &mut self,
        rt: &impl Runtime,
        st: &mut State,
        value: &TokenAmount,
    ) -> anyhow::Result<()> {
        self.stake += value;
        if self.stake < st.min_stake {
            self.status = Status::Inactive;
        }
        st.flush_subnet(rt.store(), self)?;
        Ok(())
    }

    /// Increase the applied bottom-up nonce after an execution.
    pub(crate) fn increase_applied_bottomup(
        &mut self,
        rt: &mut impl Runtime,
        st: &mut State,
    ) -> anyhow::Result<()> {
        self.applied_bottomup_nonce += 1;
        st.flush_subnet(rt.store(), self)?;
        Ok(())
    }

    /// store topdown messages for their execution in the subnet
    pub(crate) fn store_topdown_msg<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &CrossMsg,
    ) -> anyhow::Result<()> {
        let msg = &cross_msg.msg;
        self.top_down_msgs.update(store, |crossmsgs| {
            crossmsgs
                .set(msg.nonce, cross_msg.clone())
                .map_err(|e| anyhow!("failed to set crossmsg meta array: {:?}", e))
        })
    }

    pub(crate) fn release_supply(&mut self, value: &TokenAmount) -> anyhow::Result<()> {
        if &self.circ_supply < value {
            return Err(anyhow!(
                "funds can't be released over the circulating supply of the subnet. You may be releasing tokens that haven't been injected to the subnet yet"
            ));
        }
        self.circ_supply -= value;
        Ok(())
    }
}
