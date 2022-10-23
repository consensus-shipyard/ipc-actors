use crate::address::HierarchicalAddress;
use cid::Cid;
use exec::{
    is_addr_in_exec, is_common_parent, AtomicExec, AtomicExecParamsRaw, ExecStatus, LockedOutput,
    SubmitExecParams, SubmitOutput,
};
use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{
    actor_error, cbor, ActorDowncast, ActorError, BURNT_FUNDS_ACTOR_ADDR, INIT_ACTOR_ADDR,
    REWARD_ACTOR_ADDR,
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
use std::collections::HashMap;

pub use self::checkpoint::{Checkpoint, CrossMsgMeta};
pub use self::cross::{is_bottomup, CrossMsgs, HCMsgType, StorableMsg};
pub use self::state::*;
pub use self::subnet::*;
pub use self::types::*;
use crate::subnet_id::SubnetID;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

mod address;
mod atomic;
pub mod checkpoint;
mod cross;
mod error;
pub mod exec;
#[doc(hidden)]
pub mod ext;
mod state;
pub mod subnet;
mod subnet_id;
mod types;

// TODO: make this into constructor!
lazy_static! {
    pub static ref SCA_ACTOR_ADDR: Address = Address::new_id(100);
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
    InitAtomicExec = 11,
    SubmitAtomicExec = 12,
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
        // TODO: handle type check here.
        rt.validate_immediate_caller_accept_any()?;
        // rt.validate_immediate_caller_type(std::iter::once(&Type::Subnet))?;

        let subnet_addr = rt.message().caller();
        let mut shid = SubnetID::default();
        rt.transaction(|st: &mut State, rt| {
            shid = SubnetID::new(&st.network_name, subnet_addr);
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

        Ok(shid)
    }

    /// Add stake adds stake to the collateral of a subnet.
    fn add_stake<BS, RT>(rt: &mut RT) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // TODO: handle type check here.
        rt.validate_immediate_caller_accept_any()?;
        // rt.validate_immediate_caller_type(std::iter::once(&Type::Subnet))?;

        let subnet_addr = rt.message().caller();

        let val = rt.message().value_received();
        if val <= TokenAmount::zero() {
            return Err(actor_error!(illegal_argument, "no stake to add"));
        }

        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new(&st.network_name, subnet_addr);
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
        // TODO: probably a registry for permission check
        // rt.validate_immediate_caller_type(std::iter::once(&Type::Subnet))?;
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
            let shid = SubnetID::new(&st.network_name, subnet_addr);
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
        // TODO: handle type check here.
        rt.validate_immediate_caller_accept_any()?;
        // rt.validate_immediate_caller_type(std::iter::once(&Type::Subnet))?;

        let subnet_addr = rt.message().caller();
        let mut send_val = TokenAmount::zero();

        rt.transaction(|st: &mut State, rt| {
            let shid = SubnetID::new(&st.network_name, subnet_addr);
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
        // TODO: handle type check here.
        rt.validate_immediate_caller_accept_any()?;
        // rt.validate_immediate_caller_type(std::iter::once(&Type::Subnet))?;

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
            let shid = SubnetID::new(&st.network_name, subnet_addr);
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
        // FIXME: Only supporting cross-messages initiated by signable addresses for
        // now. Consider supporting also send-cross messages initiated by actors.
        // TODO: handle type check here.
        // rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        rt.validate_immediate_caller_accept_any()?;

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
            let mut f_msg = StorableMsg::new_fund_msg(&params, &sig_addr, value).map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_ILLEGAL_STATE,
                    "error creating fund cross-message",
                )
            })?;
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
        // FIXME: Only supporting cross-messages initiated by signable addresses for
        // now. Consider supporting also send-cross messages initiated by actors.

        // TODO: handle type check here.
        // rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        rt.validate_immediate_caller_accept_any()?;

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
            let r_msg = StorableMsg::new_release_msg(&st.network_name, &sig_addr, value, st.nonce)
                .map_err(|e| {
                    e.downcast_default(
                        ExitCode::USR_ILLEGAL_STATE,
                        "error creating release cross-message",
                    )
                })?;

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
    /// Params expect a raw message without any subnet context (the hierarchical address is
    /// included in the message by the actor).
    fn send_cross<BS, RT>(rt: &mut RT, params: CrossMsgParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // TODO: handle type check here.
        // rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        rt.validate_immediate_caller_accept_any()?;

        if params.destination == SubnetID::default() {
            return Err(actor_error!(
                illegal_argument,
                "no destination for cross-message explicitly set"
            ));
        }
        let mut msg = params.msg.clone();
        let mut tp = HCMsgType::Unknown;

        // FIXME: Only supporting cross-messages initiated by signable addresses for
        // now. Consider supporting also send-cross messages initiated by actors.
        let sig_addr = resolve_secp_bls(rt, rt.message().caller())?;

        rt.transaction(|st: &mut State, rt| {
            if params.destination == st.network_name {
                return Err(actor_error!(
                illegal_argument,
                "destination is the current network, you are better off with a good ol' message, no cross needed"
            ));
            }
            // we disregard the to of the message. the caller is the one set as the from of the
            // message.
            msg.to = match HierarchicalAddress::new_from_hc(&params.destination, &msg.to) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(actor_error!(
                illegal_argument,
                "error setting hierarchical address in cross-msg to param"
            ));
                }
            };
            msg.from = match HierarchicalAddress::new(&st.network_name, &sig_addr) {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(actor_error!(
                illegal_argument,
                "error setting hierarchical address in cross-msg from param"
            ));
                }
            };
            tp = st.send_cross(rt.store(), &mut msg, rt.curr_epoch()).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "error committing cross message")
            })?;

            Ok(())
        })?;

        if tp == HCMsgType::BottomUp && msg.value > TokenAmount::zero() {
            rt.send(
                *BURNT_FUNDS_ACTOR_ADDR,
                METHOD_SEND,
                RawBytes::default(),
                msg.value,
            )?;
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
    fn apply_msg<BS, RT>(rt: &mut RT, params: StorableMsg) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // TODO: handle type check here.
        rt.validate_immediate_caller_accept_any()?;
        // rt.validate_immediate_caller_is(std::iter::once(&*SYSTEM_ACTOR_ADDR))?;

        // FIXME: We just need the state to check the current network name, but we are
        // picking up the whole state. Is it more efficient in terms of performance and
        // gas usage to check how to apply the message (b-u or t-p) inside rt.transaction?
        let st: State = rt.state()?;
        let mut msg = params;
        let rto = match msg.to.raw_addr() {
            Ok(to) => to,
            Err(_) => {
                return Err(actor_error!(
                    illegal_argument,
                    "error getting raw address from msg"
                ));
            }
        };
        let sto = match msg.to.subnet() {
            Ok(to) => to,
            Err(_) => {
                return Err(actor_error!(
                    illegal_argument,
                    "error getting subnet from msg"
                ));
            }
        };
        match msg.apply_type(&st.network_name) {
            Ok(HCMsgType::BottomUp) => {
                // perform state transition
                rt.transaction(|st: &mut State, rt| {
                    st.bottomup_state_transition(&msg).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "failed applying bottomup message",
                        )
                    })?;
                    if sto != st.network_name {
                        st.commit_topdown_msg(rt.store(), &mut msg).map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error committing topdown messages",
                            )
                        })?;
                    }
                    Ok(())
                })?;
                // if directed to current network, execute message.
                if sto == st.network_name {
                    // FIXME: Should we handle return in some way?
                    let _ = rt.send(rto, msg.method, msg.params, msg.value)?;
                }
            }
            Ok(HCMsgType::TopDown) => {
                // Mint funds for SCA so it can direct them accordingly as part of the message.
                let params = ext::reward::FundingParams {
                    addr: *SCA_ACTOR_ADDR,
                    value: msg.value.clone(),
                };
                rt.send(
                    *REWARD_ACTOR_ADDR,
                    ext::reward::EXTERNAL_FUNDING_METHOD,
                    RawBytes::serialize(params)?,
                    TokenAmount::zero(),
                )?;

                rt.transaction(|st: &mut State, rt| {
                    // perform nonce state transition
                    if st.applied_topdown_nonce != msg.nonce {
                        return Err(actor_error!(
                            illegal_state,
                            "the top-down message being applied doesn't hold the subsequent nonce"
                        ));
                    }
                    st.applied_topdown_nonce += 1;
                    // if not directed to subnet go down.
                    if sto != st.network_name {
                        st.commit_topdown_msg(rt.store(), &mut msg).map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error committing top-down message while applying it",
                            )
                        })?;
                    }
                    Ok(())
                })?;

                // if directed to the current network propagate the message
                if sto == st.network_name {
                    // FIXME: Should we handle return in some way?
                    let _ = rt.send(rto, msg.method, msg.params, msg.value)?;
                }
            }
            _ => {
                return Err(actor_error!(
                    illegal_argument,
                    "cross-message to apply dosen't have the right type"
                ));
            }
        };

        Ok(())
    }

    /// Initializes an atomic execution to be orchestrated by the current subnet.
    /// This method verifies that the execution is being orchestrated by the right subnet
    /// and that its semantics and inputs are correct.
    fn init_atomic_exec<BS, RT>(
        rt: &mut RT,
        params: AtomicExecParamsRaw,
    ) -> Result<LockedOutput, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // TODO: handle type check here.
        // rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        rt.validate_immediate_caller_accept_any()?;

        // get cid for atomic execution
        let cid = params.cid().map_err(|e| {
            e.downcast_default(
                ExitCode::USR_ILLEGAL_ARGUMENT,
                "error computing Cid for params",
            )
        })?;

        // translate inputs into id addresses for the subnet.
        let params = params.input_into_ids(rt).map_err(|e| {
            e.downcast_default(
                ExitCode::USR_ILLEGAL_ARGUMENT,
                "error translating execution input addresses to IDs",
            )
        })?;

        rt.transaction(|st: &mut State, rt| {
            match st.get_atomic_exec(rt.store(), &cid.into()).map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_ILLEGAL_ARGUMENT,
                    "error translating execution input addresses to IDs",
                )
            })? {
                Some(_) => {
                    return Err(actor_error!(
                    illegal_argument,
                    format!("execution with cid {} already exists", &cid)
                ));
                }
                None => {
                    // check if exec has correct number of inputs and messages.
                    if params.msgs.is_empty() || params.inputs.len() < 2 {
                        return Err(actor_error!(
                        illegal_argument,
                        "wrong number of messages or inputs provided for execution"
                    ));
                    }
                    // check if we are the common parent and entitle to execute the system.
                    if !is_common_parent(&st.network_name, &params.inputs).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_ARGUMENT,
                            "computing common parent for the execution",
                        )
                    })?
                    {
                        return Err(actor_error!(
                        illegal_argument,
                        "can't initialize atomic execution if we are not the common parent"
                    ));
                    }

                    // TODO: check if the atomic execution is initiated in the same address for different
                    // subnets? (that would be kind of stupid -.-)

                    // sanity-check: verify that all messages have same method and are directed to the same actor
                    // NOTE: This can probably be relaxed in the future
                    let method = params.msgs[0].method;
                    let to = params.msgs[0].to.clone();
                    for m in params.msgs.iter() {
                        if m.method != method || m.to != to {
                            return Err(actor_error!(
                            illegal_argument,
                            "atomic exec doesn't support execution for messages with different methods and to different actors"
                        ));
                        }
                    }

                    // store the new initialized execution
                    st.set_atomic_exec(rt.store(), &cid.into(), AtomicExec::new(params)).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_STATE,
                            "error putting initialized atomic execution in registry",
                        )
                    })?
                    ;
                }
            };
            Ok(())
        })?;

        // return cid for the execution
        Ok(LockedOutput { cid })
    }

    /// This method submits the result of an atomic execution and mutates its state
    /// accordingly.
    fn submit_atomic_exec<BS, RT>(
        rt: &mut RT,
        params: SubmitExecParams,
    ) -> Result<SubmitOutput, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // TODO: handle type check here.
        // rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        rt.validate_immediate_caller_accept_any()?;

        let caller = rt.message().caller();

        let status = rt.transaction(|st: &mut State, rt| {
            let cid = params.cid;

            match st.get_atomic_exec(rt.store(), &cid.into()).map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_ILLEGAL_ARGUMENT,
                    "error translating execution input addresses to IDs",
                )
            })? {
                None => Err(actor_error!(
                    illegal_argument,
                    format!("execution with cid {} no longer exist", &cid)
                )),
                Some(mut exec) => {
                    // check if the output is aborted or already succeeded
                    if exec.status() != ExecStatus::Initialized {
                        return Err(actor_error!(
                            illegal_state,
                            format!("execution with cid {} no longer exist", &cid)
                        ));
                    }

                    // check if the user is involved in the execution
                    if !is_addr_in_exec(&caller, &exec.params().inputs).map_err(|e| {
                        e.downcast_default(
                            ExitCode::USR_ILLEGAL_ARGUMENT,
                            "error checking if address is involved in the execution",
                        )
                    })? {
                        return Err(actor_error!(
                            illegal_argument,
                            format!("caller not part of the execution for cid {}", &cid)
                        ));
                    }

                    // check if the address already submitted an output
                    // FIXME: At this point we don't support the atomic execution between
                    // the same address in different subnets. This can be easily supported if needed.
                    if exec.submitted().get(&caller.to_string()).is_some() {
                        return Err(actor_error!(
                            illegal_argument,
                            format!("caller for exec {} already submitted their output", &cid)
                        ));
                    };

                    // check if this is an abort
                    if params.abort {
                        // mutate status
                        exec.set_status(ExecStatus::Aborted);
                        //  propagate result to subnet
                        st.propagate_exec_result(
                            rt.store(),
                            &cid.into(),
                            &exec,
                            params.output,
                            rt.curr_epoch(),
                            true,
                        )
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error propagating execution result to subnets",
                            )
                        })?;
                        return Ok(exec.status());
                    }

                    // if not aborting
                    let output_cid = params.output.cid();
                    // check if all the submitted are equal to current cid
                    let out_cids: Vec<Cid> = exec.submitted().values().cloned().collect();
                    if !out_cids.iter().all(|&c| c == output_cid) {
                        return Err(actor_error!(
                            illegal_argument,
                            format!("cid provided not equal to the ones submitted: {}", &cid)
                        ));
                    }
                    exec.submitted_mut().insert(caller.to_string(), output_cid);
                    // if all submissions collected
                    if exec.submitted().len() == exec.params().inputs.len() {
                        exec.set_status(ExecStatus::Success);
                        st.propagate_exec_result(
                            rt.store(),
                            &cid.into(),
                            &exec,
                            params.output,
                            rt.curr_epoch(),
                            false,
                        )
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error propagating execution result to subnets",
                            )
                        })?;
                        return Ok(exec.status());
                    }
                    // persist the execution
                    let status = exec.status();
                    st.set_atomic_exec(rt.store(), &cid.into(), exec)
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "error putting aborted atomic execution in registry",
                            )
                        })?;
                    Ok(status)
                }
            }
        })?;

        // return cid for the execution
        Ok(SubmitOutput { status })
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
            Some(Method::ApplyMessage) => {
                Self::apply_msg(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::InitAtomicExec) => {
                let res = Self::init_atomic_exec(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::SubmitAtomicExec) => {
                let res = Self::submit_atomic_exec(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
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
