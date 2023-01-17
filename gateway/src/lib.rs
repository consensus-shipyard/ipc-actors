#![feature(let_chains)] // For some simpler syntax for if let Some conditions

use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{
    actor_error, cbor, ActorDowncast, ActorError, BURNT_FUNDS_ACTOR_ADDR, CALLER_TYPES_SIGNABLE,
    INIT_ACTOR_ADDR, REWARD_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::bigint::Zero;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::METHOD_SEND;
use fvm_shared::{MethodNum, METHOD_CONSTRUCTOR};
use lazy_static::lazy_static;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cmp::Ordering;
use std::collections::HashMap;

pub use self::checkpoint::{Checkpoint, CrossMsgMeta};
pub use self::cross::{is_bottomup, CrossMsg, CrossMsgs, IPCMsgType, StorableMsg};
pub use self::state::*;
pub use self::subnet::*;
pub use self::types::*;
pub use ipc_sdk::address::IPCAddress;
pub use ipc_sdk::subnet_id::SubnetID;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

pub mod checkpoint;
mod cross;
mod error;
#[doc(hidden)]
pub mod ext;
mod state;
pub mod subnet;
mod types;

// TODO: make this into constructor!
lazy_static! {
    pub static ref SCA_ACTOR_ADDR: Address = Address::new_id(100);
    pub static ref MIN_CROSS_MSG_GAS: TokenAmount = TokenAmount::from_atto(1);
    pub static ref SYSTEM_ACTORS: [&'static Address; 1] = [&SYSTEM_ACTOR_ADDR];
}

/// SCA actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    /// Constructor for Storage Power Actor
    Constructor = METHOD_CONSTRUCTOR,
    Register = 2,
    AddStake = 3,
    ReleaseStake = 4,
    Kill = 5,
    CommitChildCheckpoint = 6,
    Fund = 7,
    Release = 8,
    SendCross = 9,
    ApplyMessage = 10,
    Propagate = 11,
    WhitelistPropagator = 12,
}

/// Subnet Coordinator Actor
pub struct Actor;

impl Actor {
    /// Constructor for SCA actor
    fn constructor<BS, RT>(rt: &mut RT, params: ConstructorParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_is(std::iter::once(&*INIT_ACTOR_ADDR))?;

        let st = State::new(rt.store(), params).map_err(|e| {
            e.downcast_default(
                ExitCode::USR_ILLEGAL_STATE,
                "Failed to create SCA actor state",
            )
        })?;
        rt.create(&st)?;
        Ok(())
    }

    /// Register is called by subnet actors to put the required collateral
    /// and register the subnet to the hierarchy.
    fn register<BS, RT>(rt: &mut RT) -> Result<SubnetID, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_accept_any()?;

        let subnet_addr = rt.message().caller();
        let mut shid = SubnetID::default();
        rt.transaction(|st: &mut State, rt| {
            shid = SubnetID::new_from_parent(&st.network_name, subnet_addr);
            let sub = st.get_subnet(rt.store(), &shid).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
            match sub {
                Some(_) => {
                    return Err(actor_error!(
                        illegal_argument,
                        "subnet with id {} already registered",
                        shid
                    ));
                }
                None => {
                    st.register_subnet(rt, &shid).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_ARGUMENT,
                            "Failed to register subnet",
                        )
                    })?;
                }
            }

            Ok(())
        })?;

        log::debug!("registered new subnet: {:?}", shid);
        Ok(shid)
    }

    /// Add stake adds stake to the collateral of a subnet.
    fn add_stake<BS, RT>(rt: &mut RT) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_accept_any()?;

        let subnet_addr = rt.message().caller();

        let val = rt.message().value_received();
        if val <= TokenAmount::zero() {
            return Err(actor_error!(illegal_argument, "no stake to add"));
        }

        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new_from_parent(&st.network_name, subnet_addr);
            let sub = st.get_subnet(rt.store(), &shid).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
            match sub {
                Some(mut sub) => {
                    sub.add_stake(rt, st, &val).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "Failed to add stake to subnet",
                        )
                    })?;
                }
                None => {
                    return Err(actor_error!(
                        illegal_argument,
                        "subnet with id {} not registered",
                        shid
                    ));
                }
            }

            Ok(())
        })?;

        Ok(())
    }

    /// Release stake recovers some collateral of the subnet
    fn release_stake<BS, RT>(rt: &mut RT, params: FundParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_accept_any()?;

        let subnet_addr = rt.message().caller();

        let send_val = params.value;

        if send_val <= TokenAmount::zero() {
            return Err(actor_error!(
                illegal_argument,
                "no funds to release in params"
            ));
        }

        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new_from_parent(&st.network_name, subnet_addr);
            let sub = st.get_subnet(rt.store(), &shid).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
            match sub {
                Some(mut sub) => {
                    if sub.stake < send_val {
                        return Err(actor_error!(
                            illegal_state,
                            "subnet actor not allowed to release so many funds"
                        ));
                    }
                    // sanity-check: see if the actor has enough balance.
                    if rt.current_balance() < send_val {
                        return Err(actor_error!(
                            illegal_state,
                            "something went really wrong! the actor doesn't have enough balance to release"
                        ));
                    }
                    sub.add_stake(rt, st, &-send_val.clone()).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "Failed to add stake to subnet",
                        )
                    })?;
                }
                None => {
                    return Err(actor_error!(
                        illegal_argument,
                        "subnet with id {} not registered",
                        shid
                    ));
                }
            }

            Ok(())
        })?;

        rt.send(
            subnet_addr,
            METHOD_SEND,
            RawBytes::default(),
            send_val.clone(),
        )?;
        Ok(())
    }

    /// Kill propagates the kill signal from a subnet actor to unregister it from th
    /// hierarchy.
    fn kill<BS, RT>(rt: &mut RT) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_accept_any()?;

        let subnet_addr = rt.message().caller();
        let mut send_val = TokenAmount::zero();

        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new_from_parent(&st.network_name, subnet_addr);
            let sub = st.get_subnet(rt.store(), &shid).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
            match sub {
                Some(sub) => {
                    if rt.current_balance() < sub.stake {
                        return Err(actor_error!(
                            illegal_state,
                            "something went really wrong! the actor doesn't have enough balance to release"
                        ));
                    }
                    if sub.circ_supply > TokenAmount::zero() {
                        return Err(actor_error!(
                            illegal_state,
                            "cannot kill a subnet that still holds user funds in its circ. supply"
                        ));
                    }
                    send_val = sub.stake;
                    // delete subnet
                    st.rm_subnet(rt.store(), &shid).map_err(|e| {
                        e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
                    })?;
                }
                None => {
                    return Err(actor_error!(
                        illegal_argument,
                        "subnet with id {} not registered",
                        shid
                    ));
                }
            }

            Ok(())
        })?;

        rt.send(
            subnet_addr,
            METHOD_SEND,
            RawBytes::default(),
            send_val.clone(),
        )?;
        Ok(())
    }

    /// CommitChildCheck propagates the commitment of a checkpoint from a child subnet,
    /// process the cross-messages directed to the subnet, and propagates the corresponding
    /// once further.
    fn commit_child_check<BS, RT>(rt: &mut RT, params: Checkpoint) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_accept_any()?;

        let subnet_addr = rt.message().caller();
        let commit = params;

        // check if the checkpoint belongs to the subnet
        if subnet_addr != commit.source().subnet_actor() {
            return Err(actor_error!(
                illegal_argument,
                "source in checkpoint doesn't belong to subnet"
            ));
        }

        let mut burn_value = TokenAmount::zero();
        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new_from_parent(&st.network_name, subnet_addr);
            let sub = st.get_subnet(rt.store(), &shid).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
            })?;
            match sub {
                Some(mut sub) => {
                    // check if subnet active
                    if sub.status != Status::Active {
                        return Err(actor_error!(
                            illegal_state,
                            "can't commit checkpoint for an inactive subnet"
                        ));
                    }

                    // get window checkpoint being populated to include child info
                    let mut ch = st
                        .get_window_checkpoint(rt.store(), rt.curr_epoch())
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "failed to get current epoch checkpoint",
                            )
                        })?;

                    // if this is not the first checkpoint we need to perform some
                    // additional verifications.
                    if let Some(ref prev_checkpoint) = sub.prev_checkpoint {
                        if prev_checkpoint.epoch() > commit.epoch() {
                            return Err(actor_error!(
                                illegal_argument,
                                "checkpoint being committed belongs to the past"
                            ));
                        }
                        // check that the previous cid is consistent with the previous one
                        if commit.prev_check().cid() != prev_checkpoint.cid() {
                            return Err(actor_error!(
                                illegal_argument,
                                "previous checkpoint not consistente with previous one"
                            ));
                        }
                    }

                    // process and commit the checkpoint
                    // apply check messages
                    let ap_msgs: HashMap<SubnetID, Vec<&CrossMsgMeta>>;
                    (burn_value, ap_msgs) = st
                        .apply_check_msgs(rt.store(), &mut sub, &commit)
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error applying check messages",
                            )
                        })?;
                    // aggregate message metas in checkpoint
                    st.agg_child_msgmeta(rt.store(), &mut ch, ap_msgs)
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error aggregating child msgmeta",
                            )
                        })?;
                    // append new checkpoint to the list of childs
                    ch.add_child_check(&commit).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_ARGUMENT,
                            "error adding child checkpoint",
                        )
                    })?;
                    // flush checkpoint
                    st.flush_checkpoint(rt.store(), &ch).map_err(|e| {
                        e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing checkpoint")
                    })?;

                    // update prev_check for child
                    sub.prev_checkpoint = Some(commit);
                    // flush subnet
                    st.flush_subnet(rt.store(), &sub).map_err(|e| {
                        e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error flushing subnet")
                    })?;
                }
                None => {
                    return Err(actor_error!(
                        illegal_argument,
                        "subnet with id {} not registered",
                        shid
                    ));
                }
            }

            Ok(())
        })?;

        if burn_value > TokenAmount::zero() {
            rt.send(
                *BURNT_FUNDS_ACTOR_ADDR,
                METHOD_SEND,
                RawBytes::default(),
                burn_value.clone(),
            )?;
        }
        Ok(())
    }

    /// Fund injects new funds from an account of the parent chain to a subnet.
    ///
    /// This functions receives a transaction with the FILs that want to be injected in the subnet.
    /// - Funds injected are frozen.
    /// - A new fund cross-message is created and stored to propagate it to the subnet. It will be
    /// picked up by miners to include it in the next possible block.
    /// - The cross-message nonce is updated.
    fn fund<BS, RT>(rt: &mut RT, params: SubnetID) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // funds can only be moved between subnets by signable addresses
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        let value = rt.message().value_received();
        if value <= TokenAmount::zero() {
            return Err(actor_error!(
                illegal_argument,
                "no funds included in fund message"
            ));
        }

        let sig_addr = resolve_secp_bls(rt, rt.message().caller())?;

        rt.transaction(|st: &mut State, rt| {
            // Create fund message
            let mut f_msg = CrossMsg {
                msg: StorableMsg::new_fund_msg(&params, &sig_addr, value).map_err(|e| {
                    e.downcast_default(
                        ExitCode::USR_ILLEGAL_STATE,
                        "error creating fund cross-message",
                    )
                })?,
                wrapped: false,
            };

            log::debug!("fund cross msg is: {:?}", f_msg);

            // Commit top-down message.
            st.commit_topdown_msg(rt.store(), &mut f_msg).map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_ILLEGAL_STATE,
                    "error committing top-down message",
                )
            })?;
            Ok(())
        })?;

        Ok(())
    }

    /// Release creates a new check message to release funds in parent chain
    ///
    /// This function burns the funds that will be released in the current subnet
    /// and propagates a new checkpoint message to the parent chain to signal
    /// the amount of funds that can be released for a specific address.
    fn release<BS, RT>(rt: &mut RT) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // funds can only be moved between subnets by signable addresses
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        // FIXME: Only supporting cross-messages initiated by signable addresses for
        // now. Consider supporting also send-cross messages initiated by actors.

        let value = rt.message().value_received();
        if value <= TokenAmount::zero() {
            return Err(actor_error!(
                illegal_argument,
                "no funds included in message"
            ));
        }

        let sig_addr = resolve_secp_bls(rt, rt.message().caller())?;

        // burn funds that are being released
        rt.send(
            *BURNT_FUNDS_ACTOR_ADDR,
            METHOD_SEND,
            RawBytes::default(),
            value.clone(),
        )?;

        rt.transaction(|st: &mut State, rt| {
            // Create release message
            let r_msg = CrossMsg {
                msg: StorableMsg::new_release_msg(&st.network_name, &sig_addr, value, st.nonce)
                    .map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "error creating release cross-message",
                        )
                    })?,
                wrapped: false,
            };

            // Commit bottom-up message.
            st.commit_bottomup_msg(rt.store(), &r_msg, rt.curr_epoch())
                .map_err(|e| {
                    e.downcast_default(
                        ExitCode::USR_ILLEGAL_STATE,
                        "error committing top-down message",
                    )
                })?;
            Ok(())
        })?;

        Ok(())
    }

    /// SendCross sends an arbitrary cross-message to other subnet in the hierarchy.
    ///
    /// If the message includes any funds they need to be burnt (like in Release)
    /// before being propagated to the corresponding subnet.
    /// The circulating supply in each subnet needs to be updated as the message passes through them.
    ///
    /// Params expect a raw message without any subnet context (the IPC address is
    /// included in the message by the actor). Only actors are allowed to send arbitrary
    /// cross-messages as a side-effect of their execution. For plain token exchanges
    /// fund and release have to be used.
    fn send_cross<BS, RT>(rt: &mut RT, params: CrossMsgParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // only actor are allowed to send cross-message
        rt.validate_immediate_caller_not_type(CALLER_TYPES_SIGNABLE.iter())?;

        // FIXME: Should we add an additional check to ensure that the included message
        // has an actor ID as from and thus that the message doesn't come from a
        // account actor or a multisig?

        if params.destination == SubnetID::default() {
            return Err(actor_error!(
                illegal_argument,
                "no destination for cross-message explicitly set"
            ));
        }
        let CrossMsgParams {
            mut cross_msg,
            destination,
        } = params;
        let mut tp = None;

        rt.transaction(|st: &mut State, rt| {
            if destination == st.network_name {
                return Err(actor_error!(
                    illegal_argument,
                    "destination is the current network, you are better off with a good ol' message, no cross needed"
                ));
            }
            // we disregard the to of the message. the caller is the one set as the from of the
            // message.
            let msg = &mut cross_msg.msg;
            let to = msg.to.raw_addr().map_err(|_| actor_error!(illegal_argument, "invalid to addr"))?;
            msg.to = match IPCAddress::new(&destination, &to) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(actor_error!(
                        illegal_argument,
                        "error setting IPC address in cross-msg to param"
                    ));
                }
            };
            msg.from = match IPCAddress::new(&st.network_name, &rt.message().caller()) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(actor_error!(
                        illegal_argument,
                        "error setting IPC address in cross-msg from param"
                    ));
                }
            };

            tp = Some(st.send_cross(rt.store(), &mut cross_msg, rt.curr_epoch()).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error committing cross message")
            })?);

            Ok(())
        })?;

        let msg = cross_msg.msg;
        if let Some(t) = tp {
            if t == IPCMsgType::BottomUp && msg.value > TokenAmount::zero() {
                rt.send(
                    *BURNT_FUNDS_ACTOR_ADDR,
                    METHOD_SEND,
                    RawBytes::default(),
                    msg.value,
                )?;
            }
        }

        Ok(())
    }

    /// ApplyMessage triggers the execution of a cross-subnet message validated through the consensus.
    ///
    /// This function can only be triggered using `ApplyImplicitMessage`, and the source needs to
    /// be the SystemActor. Cross messages are applied similarly to how rewards are applied once
    /// a block has been validated. This function:
    /// - Determines the type of cross-message.
    /// - Performs the corresponding state changes.
    /// - And updated the latest nonce applied for future checks.
    fn apply_msg<BS, RT>(rt: &mut RT, params: ApplyMsgParams) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_is(*SYSTEM_ACTORS)?;

        let ApplyMsgParams { cross_msg } = params;

        let rto = match cross_msg.msg.to.raw_addr() {
            Ok(to) => to,
            Err(_) => {
                return Err(actor_error!(
                    illegal_argument,
                    "error getting raw address from msg"
                ));
            }
        };
        let sto = match cross_msg.msg.to.subnet() {
            Ok(to) => to,
            Err(_) => {
                return Err(actor_error!(
                    illegal_argument,
                    "error getting subnet from msg"
                ));
            }
        };

        let st: State = rt.state()?;

        log::debug!("sto: {:?}, network: {:?}", sto, st.network_name);

        match cross_msg.msg.apply_type(&st.network_name) {
            Ok(IPCMsgType::BottomUp) => {
                // if directed to current network, execute message.
                if sto == st.network_name {
                    rt.transaction(|st: &mut State, _| {
                        st.bottomup_state_transition(&cross_msg.msg).map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "failed applying bottomup message",
                            )
                        })?;
                        Ok(())
                    })?;
                    return cross_msg.send(rt, rto);
                }
            }
            Ok(IPCMsgType::TopDown) => {
                // Mint funds for SCA so it can direct them accordingly as part of the message.
                let params = ext::reward::FundingParams {
                    addr: *SCA_ACTOR_ADDR,
                    value: cross_msg.msg.value.clone(),
                };
                rt.send(
                    *REWARD_ACTOR_ADDR,
                    ext::reward::EXTERNAL_FUNDING_METHOD,
                    RawBytes::serialize(params)?,
                    TokenAmount::zero(),
                )?;

                match st.applied_topdown_nonce.cmp(&cross_msg.msg.nonce) {
                    Ordering::Less => {
                        return Err(actor_error!(
                            illegal_state,
                            "the top-down message being applied doesn't hold the subsequent nonce"
                        ));
                    }
                    Ordering::Equal => {
                        // TODO: consider remove `cross_msg.msg` from txn pool if persisted before
                        return Err(actor_error!(
                            illegal_state,
                            "the top-down message being applied nonce too old"
                        ));
                    }
                    Ordering::Greater => {}
                }

                if sto == st.network_name {
                    rt.transaction(|st: &mut State, _| {
                        st.applied_topdown_nonce += 1;
                        Ok(())
                    })?;

                    // We can return the send result
                    return cross_msg.send(rt, rto);
                }
            }
            _ => {
                return Err(actor_error!(
                    illegal_argument,
                    "cross-message to apply dosen't have the right type"
                ))
            }
        };

        let mut cid = None;
        rt.transaction(|st: &mut State, rt| {
            let owner = cross_msg
                .msg
                .from
                .raw_addr()
                .map_err(|_| actor_error!(illegal_argument, "invalid address"))?;
            let r = st
                .insert_postbox(rt.store(), Some(vec![owner]), cross_msg)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error save topdown messages")
                })?;
            cid = Some(r);
            Ok(())
        })?;

        // it is safe to just unwrap. If `transaction` fails, cid is None and wont reach here.
        Ok(RawBytes::new(cid.unwrap().to_bytes()))
    }

    /// Whitelist a series of addresses as propagator of a cross net message.
    /// This is basically adding this list of addresses to the `PostBoxItem::owners`.
    /// Only existing owners can perform this operation.
    fn whitelist_propagator<BS, RT>(
        rt: &mut RT,
        params: WhitelistPropagatorParams,
    ) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // does not really need check as we are checking against the PostboxItem.owners
        rt.validate_immediate_caller_accept_any()?;

        let caller = rt.message().caller();
        let WhitelistPropagatorParams {
            postbox_cid,
            to_add,
        } = params;

        rt.transaction(|st: &mut State, rt| {
            let mut postbox_item = st.load_from_postbox(rt.store(), postbox_cid).map_err(|e| {
                log::error!("encountered error loading from postbox: {:?}", e);
                actor_error!(unhandled_message, "cannot load from postbox")
            })?;

            // Currently we dont support adding owners if the owners field is None.
            // This might change in the future.
            if postbox_item.owners.is_none() {
                return Err(actor_error!(
                    illegal_state,
                    "postbox item cannot add owner for now"
                ));
            }

            let owners = postbox_item.owners.as_mut().unwrap();
            if !owners.contains(&caller) {
                return Err(actor_error!(illegal_state, "not owner"));
            }
            owners.extend(to_add);

            st.swap_postbox_item(rt.store(), postbox_cid, postbox_item)
                .map_err(|e| {
                    log::error!("encountered error loading from postbox: {:?}", e);
                    actor_error!(unhandled_message, "cannot load from postbox")
                })?;

            Ok(())
        })?;

        Ok(RawBytes::default())
    }

    fn propagate<BS, RT>(rt: &mut RT, params: PropagateParams) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // does not really need check as we are checking against the PostboxItem.owners
        rt.validate_immediate_caller_accept_any()?;

        let PropagateParams { postbox_cid } = params;
        let owner = rt.message().caller();

        rt.transaction(|st: &mut State, rt| {
            let postbox_item = st.load_from_postbox(rt.store(), postbox_cid).map_err(|e| {
                log::error!("encountered error loading from postbox: {:?}", e);
                actor_error!(unhandled_message, "cannot load from postbox")
            })?;

            if let Some(owners) = postbox_item.owners && !owners.contains(&owner) {
                return Err(actor_error!(illegal_state, "owner not match"));
            }

            if rt.message().value_received() < *MIN_CROSS_MSG_GAS {
                return Err(actor_error!(illegal_state, "not enough gas"));
            }

            let PostBoxItem { cross_msg, .. } = postbox_item;
            Self::commit_cross_message(rt, st, cross_msg)?;
            st.remove_from_postbox(rt.store(), postbox_cid)
        })?;

        Ok(RawBytes::default())
    }

    /// Commit the cross message to storage.
    ///
    /// NOTE: This function should always be called inside an `rt.transaction`
    fn commit_cross_message<BS, RT>(
        rt: &mut RT,
        st: &mut State,
        mut cross_msg: CrossMsg,
    ) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        let sto = cross_msg
            .msg
            .to
            .subnet()
            .map_err(|_| actor_error!(illegal_argument, "error getting subnet from msg"))?;
        if sto == st.network_name {
            return Err(actor_error!(illegal_state, "should already be committed"));
        }

        match cross_msg.msg.apply_type(&st.network_name).map_err(|e| {
            e.downcast_default(
                ExitCode::USR_ILLEGAL_STATE,
                "cannot convert cross message type",
            )
        })? {
            IPCMsgType::BottomUp => {
                st.commit_bottomup_msg(rt.store(), &cross_msg, rt.curr_epoch())
                    .map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "error committing topdown messages",
                        )
                    })?;

                Ok(())
            }
            IPCMsgType::TopDown => {
                st.applied_topdown_nonce += 1;
                st.commit_topdown_msg(rt.store(), &mut cross_msg)
                    .map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "error committing top-down message while applying it",
                        )
                    })?;
                Ok(())
            }
        }
    }
}

impl ActorCode for Actor {
    fn invoke_method<BS, RT>(
        rt: &mut RT,
        method: MethodNum,
        params: &RawBytes,
    ) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        match FromPrimitive::from_u64(method) {
            Some(Method::Constructor) => {
                Self::constructor(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::Register) => {
                let res = Self::register(rt)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::AddStake) => {
                Self::add_stake(rt)?;
                Ok(RawBytes::default())
            }
            Some(Method::ReleaseStake) => {
                Self::release_stake(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::Kill) => {
                Self::kill(rt)?;
                Ok(RawBytes::default())
            }
            Some(Method::CommitChildCheckpoint) => {
                Self::commit_child_check(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::Fund) => {
                Self::fund(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::Release) => {
                Self::release(rt)?;
                Ok(RawBytes::default())
            }
            Some(Method::SendCross) => {
                Self::send_cross(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::ApplyMessage) => Self::apply_msg(rt, cbor::deserialize_params(params)?),
            Some(Method::Propagate) => {
                Self::propagate(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::WhitelistPropagator) => {
                Self::whitelist_propagator(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            None => Err(actor_error!(unhandled_message; "Invalid method")),
        }
    }
}

fn resolve_secp_bls<BS, RT>(rt: &mut RT, raw: Address) -> Result<Address, ActorError>
where
    BS: Blockstore,
    RT: Runtime<BS>,
{
    let resolved = rt
        .resolve_address(&raw)
        .ok_or_else(|| actor_error!(illegal_argument, "unable to resolve address: {}", raw))?;
    let ret = rt.send(
        resolved,
        ext::account::PUBKEY_ADDRESS_METHOD,
        RawBytes::default(),
        TokenAmount::zero(),
    )?;
    let id: Address = cbor::deserialize(&ret, "address response")?;
    Ok(id)
}
