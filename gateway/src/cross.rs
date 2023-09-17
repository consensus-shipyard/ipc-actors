use crate::ExecutableMessage;
use crate::State;
use crate::SUBNET_ACTOR_REWARD_METHOD;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::ActorError;
use fil_actors_runtime::BURNT_FUNDS_ACTOR_ADDR;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::METHOD_SEND;
use ipc_sdk::cross::{CrossMsg, StorableMsg};

impl ExecutableMessage for StorableMsg {
    fn nonce(&self) -> u64 {
        self.nonce
    }
}

impl ExecutableMessage for CrossMsg {
    fn nonce(&self) -> u64 {
        self.msg.nonce()
    }
}

/// Transaction side-effects from the commitment of a cross-net message. It burns funds
/// and propagates the corresponding rewards.
pub(crate) fn cross_msg_side_effects(
    rt: &impl Runtime,
    cross_msg: &CrossMsg,
    do_burn: bool,
    top_down_fee: &TokenAmount,
) -> Result<(), ActorError> {
    // if this is a bottom-up message funds of the
    // cross-message need to be burnt
    if do_burn {
        burn_bu_funds(rt, cross_msg.msg.value.clone())?;
    }

    // distribute top-down fee if any
    if !top_down_fee.is_zero() {
        distribute_crossmsg_fee(
            rt,
            &cross_msg
                .msg
                .to
                .subnet()
                .unwrap()
                // TODO: double-check if rt.state() is an expensive operation in terms of gas
                .down(&rt.state::<State>()?.network_name)
                .unwrap()
                .subnet_actor(),
            top_down_fee.clone(),
        )?;
    }

    Ok(())
}

pub(crate) fn distribute_crossmsg_fee(
    rt: &impl Runtime,
    subnet_actor: &Address,
    fee: TokenAmount,
) -> Result<(), ActorError> {
    if !fee.is_zero() {
        rt.send(subnet_actor, SUBNET_ACTOR_REWARD_METHOD, None, fee)?;
    }
    Ok(())
}

pub(crate) fn burn_bu_funds(rt: &impl Runtime, value: TokenAmount) -> Result<(), ActorError> {
    rt.send(&BURNT_FUNDS_ACTOR_ADDR, METHOD_SEND, None, value)?;
    Ok(())
}
