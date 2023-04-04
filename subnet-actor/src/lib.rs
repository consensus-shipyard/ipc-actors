#![feature(is_some_and)]

pub mod state;
pub mod types;

use anyhow::anyhow;
use cid::Cid;
use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{
    actor_dispatch, actor_error, restrict_internal_api, ActorDowncast, ActorError,
    CALLER_TYPES_SIGNABLE, INIT_ACTOR_ADDR,
};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::{MethodNum, METHOD_CONSTRUCTOR, METHOD_SEND};
use ipc_gateway::{Checkpoint, FundParams, MIN_COLLATERAL_AMOUNT};
use ipc_sdk::vote::Voting;
use num::BigInt;
use num_derive::FromPrimitive;
use num_traits::{FromPrimitive, Zero};

pub use crate::state::State;
pub use crate::types::*;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

/// Atomic execution coordinator actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    Join = frc42_dispatch::method_hash!("Join"),
    Leave = frc42_dispatch::method_hash!("Leave"),
    Kill = frc42_dispatch::method_hash!("Kill"),
    SubmitCheckpoint = frc42_dispatch::method_hash!("SubmitCheckpoint"),
    SetValidatorNetAddr = frc42_dispatch::method_hash!("SetValidatorNetAddr"),
    Reward = frc42_dispatch::method_hash!("Reward"),
}

/// SubnetActor trait. Custom subnet actors need to implement this trait
/// in order to be used as part of hierarchical consensus.
///
/// Subnet actors are responsible for the governing policies of HC subnets.
// TODO: Instead of `RawBytes` we should consider returning a generic type for
// the subnet actor interface
pub trait SubnetActor {
    /// Deploys subnet actor with the corresponding parameters.
    fn constructor(rt: &mut impl Runtime, params: ConstructParams) -> Result<(), ActorError>;

    /// Logic for new peers to join a subnet.
    fn join(rt: &mut impl Runtime, params: JoinParams) -> Result<Option<RawBytes>, ActorError>;

    /// Called by peers to leave a subnet.
    fn leave(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError>;

    /// Sends a kill signal for the subnet to the gateway.
    fn kill(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError>;

    /// Submits a new checkpoint for the subnet.
    fn submit_checkpoint(
        rt: &mut impl Runtime,
        ch: Checkpoint,
    ) -> Result<Option<RawBytes>, ActorError>;

    /// Distributes the rewards for the subnet to validators.
    fn reward(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError>;
}

/// SubnetActor trait. Custom subnet actors need to implement this trait
/// in order to be used as part of hierarchical consensus.
///
/// Subnet actors are responsible for the governing policies of IPC subnets.
pub struct Actor;

impl SubnetActor for Actor {
    /// The constructor populates the initial state.
    ///
    /// Method num 1. This is part of the Filecoin calling convention.
    /// InitActor#Exec will call the constructor on method_num = 1.
    fn constructor(rt: &mut impl Runtime, params: ConstructParams) -> Result<(), ActorError> {
        rt.validate_immediate_caller_is(std::iter::once(&INIT_ACTOR_ADDR))?;

        let st = State::new(rt.store(), params, rt.curr_epoch()).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "Failed to create actor state")
        })?;

        rt.create(&st)?;

        Ok(())
    }

    /// Called by peers looking to join a subnet.
    ///
    /// It implements the basic logic to onboard new peers to the subnet.
    fn join(rt: &mut impl Runtime, params: JoinParams) -> Result<Option<RawBytes>, ActorError> {
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        let caller = rt.message().caller();
        let amount = rt.message().value_received();
        if amount == TokenAmount::zero() {
            return Err(actor_error!(
                illegal_argument,
                "a minimum collateral is required to join the subnet"
            ));
        }

        let mut msg = None;
        rt.transaction(|st: &mut State, rt| {
            // increase collateral
            st.add_stake(rt.store(), &caller, &params.validator_net_addr, &amount)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load subnet")
                })?;

            let total_stake = st.total_stake.clone();

            if st.status == Status::Instantiated {
                if total_stake >= TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT) {
                    msg = Some(CrossActorPayload::new(
                        st.ipc_gateway_addr,
                        ipc_gateway::Method::Register as u64,
                        None,
                        total_stake,
                    ));
                }
            } else {
                msg = Some(CrossActorPayload::new(
                    st.ipc_gateway_addr,
                    ipc_gateway::Method::AddStake as u64,
                    None,
                    amount,
                ));
            }

            st.mutate_state();

            Ok(())
        })?;

        if let Some(p) = msg {
            rt.send(&p.to, p.method, p.params, p.value)?;
        }

        Ok(None)
    }

    /// Called by peers looking to leave a subnet.
    fn leave(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError> {
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        let caller = rt.message().caller();
        let mut msg = None;
        let value = rt.transaction(|st: &mut State, rt| {
            let stake = st.get_stake(rt.store(), &caller).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load stake")
            })?;

            if stake.is_none() || stake.as_ref().is_some_and(|a| *a == TokenAmount::zero()) {
                return Err(actor_error!(illegal_state, "caller has no stake in subnet"));
            }

            let stake = stake.unwrap();
            if st.status != Status::Terminating {
                msg = Some(CrossActorPayload::new(
                    st.ipc_gateway_addr,
                    ipc_gateway::Method::ReleaseStake as u64,
                    IpldBlock::serialize_cbor(&FundParams {
                        value: stake.clone(),
                    })?,
                    TokenAmount::zero(),
                ));
            }

            // remove stake from balance table
            let ret_amount = st.rm_stake(&rt.store(), &caller, &stake).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "cannot remove stake")
            })?;

            st.mutate_state();

            Ok(ret_amount)
        })?;

        if let Some(p) = msg {
            // release the stake
            rt.send(&p.to, p.method, p.params, p.value)?;
            // return stake to caller
            rt.send(&caller, METHOD_SEND, None, value)?;
        }

        Ok(None)
    }

    fn kill(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError> {
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        // prevent a subnet from being killed until all its locked balance has been withdrawn
        if rt.current_balance() != TokenAmount::zero() {
            return Err(actor_error!(
                illegal_state,
                format!("the subnet has non-zero balance: {:}", rt.current_balance())
            ));
        }

        let mut msg = None;
        rt.transaction(|st: &mut State, _| {
            if st.status == Status::Terminating || st.status == Status::Killed {
                return Err(actor_error!(
                    illegal_state,
                    "the subnet is already in a killed or terminating state"
                ));
            }

            if !st.validator_set.validators().is_empty() || st.total_stake != TokenAmount::zero() {
                return Err(actor_error!(
                    illegal_state,
                    "this subnet can only be killed when all validators have left"
                ));
            }

            // move to terminating state
            st.status = Status::Terminating;

            st.mutate_state();

            msg = Some(CrossActorPayload::new(
                st.ipc_gateway_addr,
                ipc_gateway::Method::Kill as u64,
                None,
                TokenAmount::zero(),
            ));

            Ok(())
        })?;

        // unregister subnet
        if let Some(p) = msg {
            rt.send(&p.to, p.method, p.params, p.value)?;
        }

        Ok(None)
    }

    /// SubmitCheckpoint accepts signed checkpoint votes for miners.
    ///
    /// This functions verifies that the checkpoint is valid before
    /// propagating it for commitment to the IPC gateway. It expects at least
    /// votes from 2/3 of miners with collateral.
    fn submit_checkpoint(
        rt: &mut impl Runtime,
        ch: Checkpoint,
    ) -> Result<Option<RawBytes>, ActorError> {
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;

        let state: State = rt.state()?;
        let caller = rt.message().caller();

        if !state.is_validator(&caller) {
            return Err(actor_error!(illegal_state, "not validator"));
        }

        state.verify_checkpoint(rt, &ch).map_err(|e| {
            actor_error!(
                illegal_state,
                format!("checkpoint failed: {}", e.to_string())
            )
        })?;

        let msg = rt.transaction(|st: &mut State, rt| {
            let store = rt.store();

            let total_validator_weight = st.total_stake.clone();
            let submitter_weight = st
                .get_stake(store, &caller)
                .map_err(|_| actor_error!(illegal_state, "cannot get validator stake"))?
                .unwrap_or_else(TokenAmount::zero);
            let submission_epoch = ch.epoch();

            let some_checkpoint = st
                .epoch_checkpoint_voting
                .submit_vote(
                    rt.store(),
                    ch,
                    submission_epoch,
                    caller,
                    submitter_weight,
                    total_validator_weight,
                )
                .map_err(|e| {
                    log::error!("encountered error submitting checkpoint: {:?}", e);
                    actor_error!(illegal_state, e.to_string())
                })?;

            if let Some(ch) = some_checkpoint {
                commit_checkpoint(st, store, &ch)
            } else if let Some(ch) = st
                .epoch_checkpoint_voting
                .get_next_executable_vote(store)
                .map_err(|_| actor_error!(illegal_state, "cannot check previous checkpoint"))?
            {
                commit_checkpoint(st, store, &ch)
            } else {
                Ok(None)
            }
        })?;

        // propagate to gateway
        if let Some(p) = msg {
            rt.send(&p.to, p.method, p.params, p.value)?;
        }

        Ok(None)
    }

    /// Distributes the rewards for the subnet to validators.
    fn reward(rt: &mut impl Runtime) -> Result<Option<RawBytes>, ActorError> {
        let st: State = rt.state()?;
        // the ipc-gateway must trigger the reward distribution
        rt.validate_immediate_caller_is(vec![&st.ipc_gateway_addr])?;

        let amount = rt.message().value_received();
        if amount == TokenAmount::zero() {
            return Err(actor_error!(
                illegal_argument,
                "no rewards sent for distribution"
            ));
        };

        // even distribution of rewards. Each subnet may choose more
        // complex and fair policies to incentivize certain behaviors.
        // we may even have a default one for IPC.
        let div = {
            if st.validator_set.validators().is_empty() {
                return Err(actor_error!(illegal_state, "no validators in subnet"));
            };
            match BigInt::from_usize(st.validator_set.validators().len()) {
                None => {
                    return Err(actor_error!(illegal_state, "couldn't convert into BigInt"));
                }
                Some(val) => val,
            }
        };
        let rew_amount = amount.div_floor(div);
        for v in st.validator_set.validators().iter() {
            rt.send(&v.addr, METHOD_SEND, None, rew_amount.clone())?;
        }
        Ok(None)
    }
}

/// This impl includes methods that are not required by the subnet actor
/// trait.
impl Actor {
    /// Sets a new net address to an existing validator
    pub fn set_validator_net_addr(
        rt: &mut impl Runtime,
        params: JoinParams,
    ) -> Result<Option<RawBytes>, ActorError> {
        rt.validate_immediate_caller_type(CALLER_TYPES_SIGNABLE.iter())?;
        let caller = rt.message().caller();

        rt.transaction(|st: &mut State, _rt| {
            // if the caller is a validator allow him to change his net addr
            if let Some(index) = st
                .validator_set
                .validators()
                .iter()
                .position(|x| x.addr == caller)
            {
                if let Some(x) = st.validator_set.validators_mut().get_mut(index) {
                    x.net_addr = params.validator_net_addr;
                }
            } else {
                return Err(actor_error!(forbidden, "caller is not a validator"));
            }
            Ok(())
        })?;
        Ok(None)
    }
}

impl ActorCode for Actor {
    type Methods = Method;

    actor_dispatch! {
        Constructor => constructor,
        Join => join,
        Leave => leave,
        Kill => kill,
        SubmitCheckpoint => submit_checkpoint,
        Reward => reward,
        SetValidatorNetAddr => set_validator_net_addr,
    }
}

/// The checkpoint to be committed should be the same as the previous executed checkpoint's cid before execution
fn commit_checkpoint(
    st: &mut State,
    store: &impl Blockstore,
    ch: &Checkpoint,
) -> Result<Option<CrossActorPayload>, ActorError> {
    if st.ensure_checkpoint_chained(store, &ch)? {
        return Ok(None);
    }

    st.epoch_checkpoint_voting
        .mark_epoch_executed(store, ch.epoch())
        .map_err(|e| {
            log::error!("encountered error marking epoch executed: {:?}", e);
            actor_error!(unhandled_message, e.to_string())
        })?;

    // commit checkpoint
    st.flush_checkpoint(store, ch)
        .map_err(|_| actor_error!(illegal_state, "cannot flush checkpoint"))?;

    // prepare the message
    let msg = Some(CrossActorPayload::new(
        st.ipc_gateway_addr,
        ipc_gateway::Method::CommitChildCheckpoint as u64,
        IpldBlock::serialize_cbor(&ch)?,
        TokenAmount::zero(),
    ));

    Ok(msg)
}
