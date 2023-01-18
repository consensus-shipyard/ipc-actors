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
use std::collections::HashMap;
use std::str::FromStr;

use ipc_sdk::subnet_id::SubnetID;

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
            // Because we first increase to the subsequent and then execute
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

        let out_ch = match get_checkpoint(&checkpoints, &ch_epoch)? {
            Some(ch) => ch.clone(),
            None => Checkpoint::new(self.network_name.clone(), ch_epoch),
        };

        Ok(out_ch)
    }

    /// apply the cross-messages included in a checkpoint.
    pub(crate) fn apply_check_msgs<'m, BS: Blockstore>(
        &mut self,
        store: &'m BS,
        sub: &mut Subnet,
        commit: &'m Checkpoint,
    ) -> anyhow::Result<(TokenAmount, HashMap<SubnetID, Vec<&'m CrossMsgMeta>>)> {
        let mut burn_val = TokenAmount::zero();
        let mut aux: HashMap<SubnetID, Vec<&CrossMsgMeta>> = HashMap::new();

        // if cross-msgs directed to current network
        for mm in commit.cross_msgs() {
            if mm.to == self.network_name {
                self.store_bottomup_msg(&store, mm)
                    .map_err(|e| anyhow!("error storing bottomup msg: {}", e))?;
            } else {
                // if we are not the parent, someone is trying to forge messages
                if mm.from.parent().unwrap_or_default() != self.network_name {
                    continue;
                }
                let meta = aux.entry(mm.to.clone()).or_insert_with(|| vec![mm]);
                (*meta).push(mm);
            }
            burn_val += &mm.value;
            self.release_circ_supply(store, sub, &mm.from, &mm.value)?;
        }

        Ok((burn_val, aux))
    }

    /// aggregate child message meta that are not directed for the current
    /// subnet to propagate them further.
    pub(crate) fn agg_child_msgmeta<BS: Blockstore>(
        &mut self,
        store: &BS,
        ch: &mut Checkpoint,
        aux: HashMap<SubnetID, Vec<&CrossMsgMeta>>,
    ) -> anyhow::Result<()> {
        for (to, mm) in aux.into_iter() {
            // aggregate values inside msgmeta
            let value = mm.iter().fold(TokenAmount::zero(), |acc, x| acc + &x.value);
            let metas = mm.into_iter().cloned().collect();

            match ch.crossmsg_meta_index(&self.network_name, &to) {
                Some(index) => {
                    let msgmeta = &mut ch.data.cross_msgs[index];
                    let prev_cid = &msgmeta.msgs_cid;
                    let m_cid = self.append_metas_to_meta(store, prev_cid, metas)?;
                    msgmeta.msgs_cid = m_cid;
                    msgmeta.value += value;
                }
                None => {
                    let mut msgmeta = CrossMsgMeta::new(&self.network_name, &to);
                    let mut n_mt = CrossMsgs::new();
                    n_mt.metas = metas;
                    let meta_cid = self
                        .check_msg_registry
                        .modify(store, |cross_reg| put_msgmeta(cross_reg, n_mt))?;
                    msgmeta.value += &value;
                    msgmeta.msgs_cid = meta_cid;
                    ch.append_msgmeta(msgmeta)?;
                }
            };
        }

        Ok(())
    }

    /// store a cross message in the current checkpoint for propagation
    // TODO: We can probably de-duplicate a lot of code from agg_child_msgmeta
    pub(crate) fn store_msg_in_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &CrossMsg,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<()> {
        let mut ch = self.get_window_checkpoint(store, curr_epoch)?;

        let msg = &cross_msg.msg;
        let sto = msg.to.subnet()?;
        let sfrom = msg.from.subnet()?;
        match ch.crossmsg_meta_index(&sfrom, &sto) {
            Some(index) => {
                let msgmeta = &mut ch.data.cross_msgs[index];
                let prev_cid = &msgmeta.msgs_cid;
                let m_cid = self.append_msg_to_meta(store, prev_cid, cross_msg)?;
                msgmeta.msgs_cid = m_cid;
                msgmeta.value += &msg.value;
            }
            None => {
                let mut msgmeta = CrossMsgMeta::new(&sfrom, &sto);
                let mut n_mt = CrossMsgs::new();
                n_mt.msgs = vec![cross_msg.clone()];
                let meta_cid = self
                    .check_msg_registry
                    .modify(store, |cross_reg| put_msgmeta(cross_reg, n_mt))?;
                msgmeta.value += &msg.value;
                msgmeta.msgs_cid = meta_cid;
                ch.append_msgmeta(msgmeta)?;
            }
        };

        // flush checkpoint
        self.flush_checkpoint(store, &ch).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing checkpoint")
        })?;

        Ok(())
    }

    /// append crossmsg_meta to a specific mesasge meta.
    pub(crate) fn append_metas_to_meta<BS: Blockstore>(
        &mut self,
        store: &BS,
        meta_cid: &TCid<TLink<CrossMsgs>>,
        metas: Vec<CrossMsgMeta>,
    ) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
        self.check_msg_registry.modify(store, |cross_reg| {
            // get previous meta stored
            let mut prev_meta = match cross_reg.get(&meta_cid.cid().to_bytes())? {
                Some(m) => m.clone(),
                None => return Err(anyhow!("no msgmeta found for cid")),
            };
            prev_meta.add_metas(metas)?;
            // if the cid hasn't changed
            let cid = TCid::from(prev_meta.cid()?);
            if &cid == meta_cid {
                Ok(cid)
            } else {
                replace_msgmeta(cross_reg, meta_cid, prev_meta)
            }
        })
    }

    /// append crossmsg to a specific mesasge meta.
    // TODO: Consider de-duplicating code from append_metas_to_meta
    // if possible
    pub(crate) fn append_msg_to_meta<BS: Blockstore>(
        &mut self,
        store: &BS,
        meta_cid: &TCid<TLink<CrossMsgs>>,
        cross_msg: &CrossMsg,
    ) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
        self.check_msg_registry.modify(store, |cross_reg| {
            // get previous meta stored
            let mut prev_meta = match cross_reg.get(&meta_cid.cid().to_bytes())? {
                Some(m) => m.clone(),
                None => return Err(anyhow!("no msgmeta found for cid")),
            };

            prev_meta.add_msg(cross_msg)?;

            // if the cid hasn't changed
            let cid = TCid::from(prev_meta.cid()?);
            if &cid == meta_cid {
                Ok(cid)
            } else {
                replace_msgmeta(cross_reg, meta_cid, prev_meta)
            }
        })
    }

    /// release circulating supply from a subent
    ///
    /// This is triggered through bottom-up messages sending subnet tokens
    /// to some other subnet in the hierarchy.
    pub(crate) fn release_circ_supply<BS: Blockstore>(
        &mut self,
        store: &BS,
        curr: &mut Subnet,
        id: &SubnetID,
        val: &TokenAmount,
    ) -> anyhow::Result<()> {
        // if current subnet, we don't need to get the
        // subnet again
        if curr.id == *id {
            curr.release_supply(val)?;
            return Ok(());
        }

        let sub = self
            .get_subnet(store, id)
            .map_err(|e| anyhow!("failed to load subnet: {}", e))?;
        match sub {
            Some(mut sub) => {
                sub.release_supply(val)?;
                self.flush_subnet(store, &sub)
            }
            None => return Err(anyhow!("subnet with id {} not registered", id)),
        }?;
        Ok(())
    }

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
    ) -> anyhow::Result<()> {
        let msg = &cross_msg.msg;
        let sto = msg.to.subnet()?;
        // let sfrom = msg.from.subnet()?;

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
            }
            None => {
                if sto == self.network_name {
                    return Err(anyhow!(
                        "can't direct top-down message to the current subnet"
                    ));
                } else {
                    self.noop_msg();
                }
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
    ) -> anyhow::Result<()> {
        // store msg in checkpoint for propagation
        self.store_msg_in_checkpoint(store, msg, curr_epoch)?;
        // increment nonce
        self.nonce += 1;

        Ok(())
    }

    /// commits a cross-msg for propagation
    pub(crate) fn send_cross<BS: Blockstore>(
        &mut self,
        store: &BS,
        cross_msg: &mut CrossMsg,
        curr_epoch: ChainEpoch,
    ) -> anyhow::Result<IPCMsgType> {
        let msg = &cross_msg.msg;
        let tp = msg.ipc_type()?;
        match tp {
            IPCMsgType::TopDown => self.commit_topdown_msg(store, cross_msg)?,
            IPCMsgType::BottomUp => self.commit_bottomup_msg(store, cross_msg, curr_epoch)?,
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

    /// noop is triggered to notify when a crossMsg fails to be applied successfully.
    pub fn noop_msg(&self) {
        panic!("error committing cross-msg. noop should be returned but not implemented yet");
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
    let m_cid = TCid::from(metas.cid()?);
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
