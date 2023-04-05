use anyhow::anyhow;
use fil_actors_runtime::runtime::Runtime;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::repr::{Deserialize_repr, Serialize_repr};
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
                "wtf! we can't release funds below circ, supply. something went really wrong"
            ));
        }
        self.circ_supply -= value;
        Ok(())
    }
}
