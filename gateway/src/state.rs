// Copyright: ConsensusLab

use anyhow::anyhow;
use cid::Cid;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{actor_error, ActorDowncast, ActorError, Map};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use ipc_sdk::epoch_key;
use lazy_static::lazy_static;
use num_traits::Zero;
use primitives::{TCid, THamt};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use std::str::FromStr;

use crate::checkpoint::Validators;
use crate::TopDownCheckpoint;
use ipc_actor_common::vote::Voting;
use ipc_sdk::subnet_id::SubnetID;
use ipc_sdk::ValidatorSet;

use super::checkpoint::*;
use super::cross::*;
use super::subnet::*;
use super::types::*;

/// We are using a HAMT to track the cid of `PostboxItem`, the hamt
/// is really a indicator of whether is cid is already processed.
/// TODO: maybe cid is not the best way to be used as the key.
type PostBox = TCid<THamt<Cid, Vec<u8>>>;

/// Storage power actor state
#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct State {
    pub network_name: SubnetID,
    pub total_subnets: u64,
    pub min_stake: TokenAmount,
    pub subnets: TCid<THamt<SubnetID, Subnet>>,
    pub bottomup_check_period: ChainEpoch,
    pub topdown_check_period: ChainEpoch,
    // FIXME: Consider making checkpoints a HAMT instead of an AMT so we use
    // the AMT index instead of and epoch k for object indexing.
    pub bottomup_checkpoints: TCid<THamt<ChainEpoch, BottomUpCheckpoint>>,
    /// `postbox` keeps track for an EOA of all the cross-net messages triggered by
    /// an actor that need to be propagated further through the hierarchy.
    pub postbox: PostBox,
    pub bottomup_nonce: u64,
    pub applied_topdown_nonce: u64,
    pub topdown_checkpoint_voting: Voting<TopDownCheckpoint>,
    pub validators: Validators,
    /// `initialized` determines if validators have initialized the subnet
    /// to start accepting top-down checkpoints and messages. No cross-net messages
    /// and checkpoints can be triggered if the subnet is not initialized yet.
    pub initialized: bool,
}

lazy_static! {
    static ref MIN_SUBNET_COLLATERAL: TokenAmount = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
}

impl State {
    pub fn new<BS: Blockstore>(store: &BS, params: ConstructorParams) -> anyhow::Result<State> {
        Ok(State {
            network_name: SubnetID::from_str(&params.network_name)?,
            total_subnets: Default::default(),
            min_stake: MIN_SUBNET_COLLATERAL.clone(),
            subnets: TCid::new_hamt(store)?,
            bottomup_check_period: match params.bottomup_check_period > DEFAULT_CHECKPOINT_PERIOD {
                true => params.bottomup_check_period,
                false => DEFAULT_CHECKPOINT_PERIOD,
            },
            topdown_check_period: match params.topdown_check_period > DEFAULT_CHECKPOINT_PERIOD {
                true => params.topdown_check_period,
                false => DEFAULT_CHECKPOINT_PERIOD,
            },
            bottomup_checkpoints: TCid::new_hamt(store)?,
            postbox: TCid::new_hamt(store)?,
            bottomup_nonce: Default::default(),
            // This way we ensure that the first message to execute has nonce= 0, if not it would expect 1 and fail for the first nonce
            // We first increase to the subsequent and then execute for bottom-up messages
            applied_topdown_nonce: Default::default(),
            // initializing any voting to avoid TCid::default() inside the voting
            // from corrupting the actor state.
            topdown_checkpoint_voting: Voting::<TopDownCheckpoint>::new(
                store,
                0,
                params.topdown_check_period,
            )?,
            validators: Validators::new(ValidatorSet::default()),
            initialized: false,
        })
    }

    /// Initializes the gateway of the subnet actor and initializates
    /// the top-down voting
    pub(crate) fn init_gateway<BS: Blockstore>(
        &mut self,
        store: &BS,
        genesis_epoch: ChainEpoch,
    ) -> Result<(), ActorError> {
        self.topdown_checkpoint_voting =
            Voting::<TopDownCheckpoint>::new(store, genesis_epoch, self.topdown_check_period)
                .map_err(|e| actor_error!(illegal_state, e.to_string()))?;
        self.initialized = true;
        Ok(())
    }

    /// requires that the subnet is initialized before continuing
    pub(crate) fn require_initialized(&self) -> Result<(), ActorError> {
        if !self.initialized {
            return Err(actor_error!(
                illegal_state,
                "require subnet initialized failed"
            ));
        }
        Ok(())
    }

    /// Get content for a child subnet as mut.
    pub fn get_subnet(
        &mut self,
        rt: &impl Runtime,
        id: &SubnetID,
    ) -> anyhow::Result<Option<Subnet>> {
        let subnets = self.subnets.load(rt.store())?;
        let subnet = get_subnet(&subnets, &id.f0_id(rt))?;
        Ok(subnet.cloned())
    }

    /// Register a subnet in the map of subnets and flush.
    pub(crate) fn register_subnet(
        &mut self,
        rt: &impl Runtime,
        id: &SubnetID,
    ) -> anyhow::Result<()> {
        let val = rt.message().value_received();
        if val < self.min_stake {
            return Err(anyhow!("call to register doesn't include enough funds"));
        }

        let inserted = self.subnets.modify(rt.store(), |subnets| {
            if get_subnet(subnets, id)?.is_some() {
                Ok(false)
            } else {
                let subnet = Subnet {
                    id: id.clone(),
                    stake: val,
                    top_down_msgs: TCid::new_amt(rt.store())?,
                    circ_supply: TokenAmount::zero(),
                    status: Status::Active,
                    topdown_nonce: 0,
                    prev_checkpoint: None,
                    applied_bottomup_nonce: 0,
                    genesis_epoch: rt.curr_epoch(),
                };
                set_subnet(subnets, id, subnet)?;
                Ok(true)
            }
        })?;

        if inserted {
            self.total_subnets += 1;
        }
        Ok(())
    }

    /// Remove a subnet from the map of subnets and flush.
    pub(crate) fn rm_subnet<BS: Blockstore>(
        &mut self,
        store: &BS,
        id: &SubnetID,
    ) -> anyhow::Result<()> {
        let deleted = self.subnets.modify(store, |subnets| {
            subnets
                .delete(&id.to_bytes())
                .map_err(|e| e.downcast_wrap(format!("failed to delete subnet for id {}", id)))
                .map(|x| x.is_some())
        })?;
        if deleted {
            self.total_subnets -= 1;
        }
        Ok(())
    }

    /// flush a subnet
    pub(crate) fn flush_subnet<BS: Blockstore>(
        &mut self,
        store: &BS,
        sub: &Subnet,
    ) -> anyhow::Result<()> {
        self.subnets
            .update(store, |subnets| set_subnet(subnets, &sub.id, sub.clone()))
    }

    /// flush a checkpoint
    pub(crate) fn flush_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        ch: &BottomUpCheckpoint,
    ) -> anyhow::Result<()> {
        self.bottomup_checkpoints
            .update(store, |checkpoints| set_checkpoint(checkpoints, ch.clone()))
    }

    /// get checkpoint being populated in the current window.
    pub fn get_window_checkpoint<BS: Blockstore>(
        &self,
        store: &BS,
        epoch: ChainEpoch,
    ) -> anyhow::Result<BottomUpCheckpoint> {
        if epoch < 0 {
            return Err(anyhow!("epoch can't be negative"));
        }
        let ch_epoch = window_epoch(epoch, self.bottomup_check_period);
        let checkpoints = self.bottomup_checkpoints.load(store)?;

        Ok(match get_checkpoint(&checkpoints, ch_epoch)? {
            Some(ch) => ch.clone(),
            None => BottomUpCheckpoint::new(self.network_name.clone(), ch_epoch),
        })
    }

    /// store a cross-message in a checkpoint
    pub(crate) fn store_msg_in_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &CrossMsg,
        curr_epoch: ChainEpoch,
        fee: &TokenAmount,
    ) -> anyhow::Result<()> {
        let mut ch = self.get_window_checkpoint(store, curr_epoch)?;

        let mut cross_msg = cross_msg.clone();
        cross_msg.msg.nonce = self.bottomup_nonce;

        ch.push_cross_msgs(cross_msg, fee);

        // increment nonce
        self.bottomup_nonce += 1;

        // flush checkpoint
        self.flush_checkpoint(store, &ch).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing checkpoint")
        })?;

        Ok(())
    }

    /// commit topdown messages for their execution in the subnet
    pub(crate) fn commit_topdown_msg(
        &mut self,
        rt: &impl Runtime,
        cross_msg: &mut CrossMsg,
    ) -> anyhow::Result<()> {
        let msg = &cross_msg.msg;
        let sto = msg.to.subnet()?;

        let sub = self
            .get_subnet(
                rt,
                match &sto.down(&self.network_name) {
                    Some(sub) => sub,
                    None => return Err(anyhow!("couldn't compute the next subnet in route")),
                },
            )
            .map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
        match sub {
            Some(mut sub) => {
                cross_msg.msg.nonce = sub.topdown_nonce;
                sub.store_topdown_msg(rt.store(), cross_msg)?;
                sub.topdown_nonce += 1;
                sub.circ_supply += &cross_msg.msg.value;
                self.flush_subnet(rt.store(), &sub)?;
            }
            None => {
                return Err(anyhow!(
                    "can't direct top-down message to destination subnet"
                ));
            }
        }
        Ok(())
    }

    /// commit bottomup messages for their execution in the subnet
    pub(crate) fn commit_bottomup_msg<BS: Blockstore>(
        &mut self,
        store: &BS,
        msg: &CrossMsg,
        curr_epoch: ChainEpoch,
        fee: &TokenAmount,
    ) -> anyhow::Result<()> {
        // store bottom-up msg and fee in checkpoint for propagation
        self.store_msg_in_checkpoint(store, msg, curr_epoch, fee)?;
        Ok(())
    }

    /// Insert a cross message to the `postbox` before propagate can be called for the
    /// message to be propagated upwards or downwards.
    ///
    /// # Arguments
    /// * `st` - The blockstore
    /// * `owners` - The owners of the message that started the cross message. If None means
    ///              anyone can propagate this message. Allows multiple owners.
    /// * `gas` - The gas needed to propagate this message
    /// * `msg` - The actual cross msg to store in `postbox`
    pub fn insert_postbox<BS: Blockstore>(
        &mut self,
        st: &BS,
        owners: Option<Vec<Address>>,
        msg: CrossMsg,
    ) -> anyhow::Result<Cid> {
        let item = PostBoxItem::new(msg, owners);
        let (cid, bytes) = item
            .serialize_with_cid()
            .map_err(|_| anyhow!("cannot serialize postbox item"))?;
        self.postbox.update(st, |postbox| {
            let key = BytesKey::from(cid.to_bytes());
            postbox.set(key, bytes)?;
            Ok(())
        })?;
        Ok(cid)
    }

    pub fn load_from_postbox<BS: Blockstore>(
        &self,
        st: &BS,
        cid: Cid,
    ) -> anyhow::Result<PostBoxItem> {
        let postbox = self.postbox.load(st)?;
        let optional = postbox.get(&BytesKey::from(cid.to_bytes()))?;
        if optional.is_none() {
            return Err(anyhow!("cid not found in postbox"));
        }

        let raw_bytes = optional.unwrap();
        PostBoxItem::deserialize(raw_bytes.to_vec())
            .map_err(|_| anyhow!("cannot parse postbox item"))
    }

    pub fn swap_postbox_item<BS: Blockstore>(
        &mut self,
        st: &BS,
        cid: Cid,
        item: PostBoxItem,
    ) -> anyhow::Result<()> {
        self.postbox.modify(st, |postbox| {
            let previous = postbox.delete(&BytesKey::from(cid.to_bytes()))?;
            if previous.is_none() {
                return Err(anyhow!("cid not found in postbox"));
            }
            let (cid, bytes) = item
                .serialize_with_cid()
                .map_err(|_| anyhow!("cannot serialize postbox item"))?;
            let key = BytesKey::from(cid.to_bytes());
            postbox.set(key, bytes)?;

            Ok(())
        })?;

        Ok(())
    }

    /// Removes the cid for postbox.
    ///
    /// Note that caller should have checked the msg caller has the permissions to perform the
    /// deletion, this method does not check.
    pub fn remove_from_postbox<BS: Blockstore>(
        &mut self,
        st: &BS,
        cid: Cid,
    ) -> Result<(), ActorError> {
        self.postbox
            .modify(st, |postbox| {
                postbox.delete(&BytesKey::from(cid.to_bytes()))?;
                Ok(())
            })
            .map_err(|e| {
                log::error!("encountered error deleting from postbox: {:?}", e);
                actor_error!(unhandled_message, "cannot delete from postbox")
            })?;
        Ok(())
    }

    /// Collects cross-fee and reduces the corresponding
    /// balances from which the fee is collected.
    pub fn collect_cross_fee(
        &mut self,
        balance: &mut TokenAmount,
        fee: &TokenAmount,
    ) -> Result<(), ActorError> {
        // check if the message can pay for the fees
        if balance < &mut fee.clone() {
            return Err(actor_error!(
                illegal_state,
                "not enough gas to pay cross-message"
            ));
        }

        // update balance after collecting the fee
        *balance -= fee;
        Ok(())
    }

    pub fn set_membership(&mut self, validator_set: ValidatorSet) {
        self.validators = Validators::new(validator_set);
    }
}

pub fn set_subnet<BS: Blockstore>(
    subnets: &mut Map<BS, Subnet>,
    id: &SubnetID,
    subnet: Subnet,
) -> anyhow::Result<()> {
    subnets
        .set(id.to_bytes().into(), subnet)
        .map_err(|e| e.downcast_wrap(format!("failed to set subnet for id {}", id)))?;
    Ok(())
}

fn get_subnet<'m, BS: Blockstore>(
    subnets: &'m Map<BS, Subnet>,
    id: &SubnetID,
) -> anyhow::Result<Option<&'m Subnet>> {
    subnets
        .get(&id.to_bytes())
        .map_err(|e| e.downcast_wrap(format!("failed to get subnet for id {}", id)))
}

pub fn set_checkpoint<BS: Blockstore>(
    checkpoints: &mut Map<BS, BottomUpCheckpoint>,
    ch: BottomUpCheckpoint,
) -> anyhow::Result<()> {
    let epoch = ch.epoch();
    checkpoints
        .set(epoch_key(epoch), ch)
        .map_err(|e| e.downcast_wrap(format!("failed to set checkpoint for epoch {}", epoch)))?;
    Ok(())
}

pub fn get_checkpoint<'m, BS: Blockstore>(
    checkpoints: &'m Map<BS, BottomUpCheckpoint>,
    epoch: ChainEpoch,
) -> anyhow::Result<Option<&'m BottomUpCheckpoint>> {
    checkpoints
        .get(&epoch_key(epoch))
        .map_err(|e| e.downcast_wrap(format!("failed to get checkpoint for id {}", epoch)))
}

pub fn get_topdown_msg<'m, BS: Blockstore>(
    crossmsgs: &'m CrossMsgArray<BS>,
    nonce: u64,
) -> anyhow::Result<Option<&'m StorableMsg>> {
    let r = crossmsgs
        .get(nonce)
        .map_err(|e| anyhow!("failed to get msg by nonce: {:?}", e))?
        .map(|c| &c.msg);
    Ok(r)
}
