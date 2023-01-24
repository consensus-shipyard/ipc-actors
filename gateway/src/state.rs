// Copyright: ConsensusLab

use anyhow::anyhow;
use cid::Cid;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{actor_error, ActorDowncast, ActorError, Map};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use lazy_static::lazy_static;
use num_traits::Zero;
use primitives::{TAmt, TCid, THamt, TLink};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use ipc_sdk::subnet_id::{self, SubnetID};

use super::checkpoint::*;
use super::cross::*;
use super::subnet::*;
use super::types::*;

/// We are using a HAMT to track the cid of `PostboxItem`, the hamt
/// is really a indicator of whether is cid is already processed.
/// TODO: maybe cid is not the best way to be used as the key.
type PostBox = TCid<THamt<Cid, Vec<u8>>>;

/// Storage power actor state
#[derive(Serialize, Deserialize)]
pub struct State {
    pub network_name: SubnetID,
    pub total_subnets: u64,
    pub min_stake: TokenAmount,
    pub subnets: TCid<THamt<Cid, Subnet>>,
    pub check_period: ChainEpoch,
    pub checkpoints: TCid<THamt<ChainEpoch, Checkpoint>>,
    pub check_msg_registry: TCid<THamt<TCid<TLink<CrossMsgs>>, CrossMsgs>>,
    /// `postbox` keeps track for an EOA of all the cross-net messages triggered by
    /// an actor that need to be propagated further through the hierarchy.
    pub postbox: PostBox,
    pub nonce: u64,
    pub bottomup_nonce: u64,
    pub bottomup_msg_meta: TCid<TAmt<CrossMsgMeta, CROSSMSG_AMT_BITWIDTH>>,
    pub applied_bottomup_nonce: u64,
    pub applied_topdown_nonce: u64,
}

lazy_static! {
    static ref MIN_SUBNET_COLLATERAL: TokenAmount = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
}

impl Cbor for State {}

impl State {
    pub fn new<BS: Blockstore>(store: &BS, params: ConstructorParams) -> anyhow::Result<State> {
        Ok(State {
            network_name: SubnetID::from_str(&params.network_name)?,
            total_subnets: Default::default(),
            min_stake: MIN_SUBNET_COLLATERAL.clone(),
            subnets: TCid::new_hamt(store)?,
            check_period: match params.checkpoint_period > DEFAULT_CHECKPOINT_PERIOD {
                true => params.checkpoint_period,
                false => DEFAULT_CHECKPOINT_PERIOD,
            },
            checkpoints: TCid::new_hamt(store)?,
            check_msg_registry: TCid::new_hamt(store)?,
            postbox: TCid::new_hamt(store)?,
            nonce: Default::default(),
            bottomup_nonce: Default::default(),
            bottomup_msg_meta: TCid::new_amt(store)?,
            // This way we ensure that the first message to execute has nonce= 0, if not it would expect 1 and fail for the first nonce
            // We first increase to the subsequent and then execute for bottom-up messages
            applied_bottomup_nonce: MAX_NONCE,
            applied_topdown_nonce: Default::default(),
        })
    }

    /// Get content for a child subnet.
    pub fn get_subnet<BS: Blockstore>(
        &self,
        store: &BS,
        id: &SubnetID,
    ) -> anyhow::Result<Option<Subnet>> {
        let subnets = self.subnets.load(store)?;
        let subnet = get_subnet(&subnets, id)?;
        Ok(subnet.cloned())
    }

    /// Register a subnet in the map of subnets and flush.
    pub(crate) fn register_subnet<BS, RT>(&mut self, rt: &RT, id: &SubnetID) -> anyhow::Result<()>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
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
                    nonce: 0,
                    prev_checkpoint: None,
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
        ch: &Checkpoint,
    ) -> anyhow::Result<()> {
        self.checkpoints
            .update(store, |checkpoints| set_checkpoint(checkpoints, ch.clone()))
    }

    /// get checkpoint being populated in the current window.
    pub fn get_window_checkpoint<BS: Blockstore>(
        &self,
        store: &BS,
        epoch: ChainEpoch,
    ) -> anyhow::Result<Checkpoint> {
        if epoch < 0 {
            return Err(anyhow!("epoch can't be negative"));
        }
        let ch_epoch = checkpoint_epoch(epoch, self.check_period);
        let checkpoints = self.checkpoints.load(store)?;

        Ok(match get_checkpoint(&checkpoints, &ch_epoch)? {
            Some(ch) => ch.clone(),
            None => Checkpoint::new(self.network_name.clone(), ch_epoch),
        })
    }

    /// store a cross-message in a checkpoint
    pub(crate) fn store_msg_in_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &CrossMsg,
        fee: &TokenAmount,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        let mut ch = self.get_window_checkpoint(store, curr_epoch)?;

        match ch.cross_msgs_mut() {
            Some(msgmeta) => {
                let prev_cid = &msgmeta.msgs_cid;
                let m_cid = self.append_msg_to_meta(store, prev_cid, cross_msg)?;
                msgmeta.msgs_cid = m_cid;
                msgmeta.value += &cross_msg.msg.value + fee;
                msgmeta.fee += fee;
            }
            None => self.check_msg_registry.modify(store, |cross_reg| {
                let mut msgmeta = CrossMsgMeta::default();
                let mut crossmsgs = CrossMsgs::new();
                let _ = crossmsgs.add_msg(cross_msg);
                let m_cid = put_msgmeta(cross_reg, crossmsgs)?;
                msgmeta.msgs_cid = m_cid;
                msgmeta.value += &cross_msg.msg.value + fee;
                msgmeta.fee += fee;
                ch.set_cross_msgs(msgmeta);
                Ok(())
            })?,
        };

        // flush checkpoint
        self.flush_checkpoint(store, &ch).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing checkpoint")
        })?;

        Ok(())
    }

    /// store a cross-fee in a checkpoint
    pub(crate) fn store_fee_in_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        fee: &TokenAmount,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        let mut ch = self.get_window_checkpoint(store, curr_epoch)?;

        match ch.cross_msgs_mut() {
            Some(msgmeta) => {
                msgmeta.value += fee;
                msgmeta.fee += fee;
            }
            None => {
                let mut msgmeta = CrossMsgMeta::default();
                msgmeta.value += fee;
                msgmeta.fee += fee;
                ch.set_cross_msgs(msgmeta);
            }
        };

        // flush checkpoint
        self.flush_checkpoint(store, &ch).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing checkpoint")
        })?;

        Ok(())
    }

    /// append cross-msg and/or fee reward to a specific message meta.
    pub(crate) fn append_msg_to_meta<BS: Blockstore>(
        &mut self,
        store: &BS,
        meta_cid: &TCid<TLink<CrossMsgs>>,
        cross_msg: &CrossMsg,
    ) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
        self.check_msg_registry.modify(store, |cross_reg| {
            // get previous meta stored
            let mut prev_crossmsgs = match cross_reg.get(&meta_cid.cid().to_bytes())? {
                Some(m) => m.clone(),
                None => {
                    // double-check that is not find because there were no messages
                    // in meta and not because we messed-up something.
                    if meta_cid.cid() != Cid::default() {
                        return Err(anyhow!("no msgmeta found for cid"));
                    }
                    // return empty messages
                    CrossMsgs::new()
                }
            };
            let added = prev_crossmsgs.add_msg(cross_msg);
            if !added {
                return Ok(meta_cid.clone());
            }
            replace_msgmeta(cross_reg, meta_cid, prev_crossmsgs)
        })
    }

    /// release circulating supply from a subent
    ///
    /// This is triggered through bottom-up messages sending subnet tokens
    /// to some other subnet in the hierarchy.
    /// store bottomup messages for their execution in the subnet
    pub(crate) fn store_bottomup_msg<BS: Blockstore>(
        &mut self,
        store: &BS,
        meta: &CrossMsgMeta,
    ) -> anyhow::Result<()> {
        let mut new_meta = meta.clone();
        new_meta.nonce = self.bottomup_nonce;
        self.bottomup_nonce += 1;
        self.bottomup_msg_meta.update(store, |crossmsgs| {
            crossmsgs
                .set(new_meta.nonce, new_meta)
                .map_err(|e| anyhow!("failed to set crossmsg meta array: {:?}", e))
        })
    }

    /// commit topdown messages for their execution in the subnet
    pub(crate) fn commit_topdown_msg<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &mut CrossMsg,
        fee: &TokenAmount,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        let msg = &cross_msg.msg;
        let sto = msg.to.subnet()?;

        let sub = self
            .get_subnet(
                store,
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
                cross_msg.msg.nonce = sub.nonce;
                sub.store_topdown_msg(store, cross_msg)?;
                sub.nonce += 1;
                sub.circ_supply += &cross_msg.msg.value;
                self.flush_subnet(store, &sub)?;

                // store fee in checkpoint as long as we are not the root
                // (the root should distribute the reward immediately to
                // all validators)
                if self.network_name != *subnet_id::ROOTNET_ID {
                    self.store_fee_in_checkpoint(store, fee, curr_epoch)?;
                }
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
        fee: &TokenAmount,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        // store bottom-up msg and fee in checkpoint for propagation
        self.store_msg_in_checkpoint(store, msg, fee, curr_epoch)?;
        // increment nonce
        self.nonce += 1;

        Ok(())
    }

    /// commits a cross-msg for propagation
    pub(crate) fn send_cross<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &mut CrossMsg,
        fee: &TokenAmount,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<IPCMsgType> {
        let msg = &cross_msg.msg;
        let tp = msg.ipc_type()?;
        match tp {
            IPCMsgType::TopDown => self.commit_topdown_msg(store, cross_msg, fee, curr_epoch)?,
            IPCMsgType::BottomUp => self.commit_bottomup_msg(store, cross_msg, fee, curr_epoch)?,
        };
        Ok(tp)
    }

    pub fn bottomup_state_transition(&mut self, msg: &StorableMsg) -> anyhow::Result<()> {
        // Bottom-up messages include the nonce of their message meta. Several messages
        // will include the same nonce. They need to be applied in order of nonce.

        // As soon as we see a message with the next msgMeta nonce, we increment the nonce
        // and start accepting the one for the next nonce.
        if self.applied_bottomup_nonce == u64::MAX && msg.nonce == 0 {
            self.applied_bottomup_nonce = 0;
        } else if self.applied_bottomup_nonce.wrapping_add(1) == msg.nonce {
            // wrapping add is used to prevent overflow.
            self.applied_bottomup_nonce = self.applied_bottomup_nonce.wrapping_add(1);
        };

        if self.applied_bottomup_nonce != msg.nonce {
            return Err(anyhow!(
                "the bottom-up message being applied doesn't hold the subsequent nonce: nonce={} applied={}",
                msg.nonce,
                self.applied_bottomup_nonce,
            ));
        }
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
    checkpoints: &mut Map<BS, Checkpoint>,
    ch: Checkpoint,
) -> anyhow::Result<()> {
    let epoch = ch.epoch();
    checkpoints
        .set(BytesKey::from(epoch.to_ne_bytes().to_vec()), ch)
        .map_err(|e| e.downcast_wrap(format!("failed to set checkpoint for epoch {}", epoch)))?;
    Ok(())
}

fn get_checkpoint<'m, BS: Blockstore>(
    checkpoints: &'m Map<BS, Checkpoint>,
    epoch: &ChainEpoch,
) -> anyhow::Result<Option<&'m Checkpoint>> {
    checkpoints
        .get(&BytesKey::from(epoch.to_ne_bytes().to_vec()))
        .map_err(|e| e.downcast_wrap(format!("failed to get checkpoint for id {}", epoch)))
}

fn put_msgmeta<BS: Blockstore>(
    registry: &mut Map<BS, CrossMsgs>,
    metas: CrossMsgs,
) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
    let m_cid = metas.cid()?;
    registry
        .set(m_cid.cid().to_bytes().into(), metas)
        .map_err(|e| e.downcast_wrap(format!("failed to set crossmsg meta for cid {}", m_cid)))?;
    Ok(m_cid)
}

/// insert a message meta and remove the old one.
fn replace_msgmeta<BS: Blockstore>(
    registry: &mut Map<BS, CrossMsgs>,
    prev_cid: &TCid<TLink<CrossMsgs>>,
    meta: CrossMsgs,
) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
    // add new meta
    let m_cid = put_msgmeta(registry, meta)?;
    // remove the previous one
    registry.delete(&prev_cid.cid().to_bytes())?;
    Ok(m_cid)
}

pub fn get_bottomup_msg<'m, BS: Blockstore>(
    crossmsgs: &'m CrossMsgMetaArray<BS>,
    nonce: u64,
) -> anyhow::Result<Option<&'m CrossMsgMeta>> {
    crossmsgs
        .get(nonce)
        .map_err(|e| anyhow!("failed to get crossmsg meta by nonce: {:?}", e))
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
