use crate::state::State;
use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{actor_error, cbor, ActorDowncast, ActorError, INIT_ACTOR_ADDR};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::{MethodNum, METHOD_CONSTRUCTOR};
use ipc_gateway::{ApplyMsgParams, CrossMsg, IPCAddress, StorableMsg, SubnetID};
use num_derive::FromPrimitive;
use num_traits::{FromPrimitive, Zero};

pub use crate::types::{AtomicExecID, ConstructorParams, PreCommitParams, RevokeParams};

mod state;
mod types;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

/// Atomic execution coordinator actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    PreCommit = 2,
    Revoke = 3,
}

/// Atomic execution coordinator actor
pub struct Actor;

lazy_static::lazy_static! {
    static ref IPC_ADDR_PLACEHOLDER: IPCAddress = IPCAddress::new(
        &SubnetID::default(),
        &Address::new_bls(&[0; fvm_shared::address::BLS_PUB_LEN]).unwrap(),
    )
        .unwrap();
}

impl Actor {
    fn constructor<BS, RT>(rt: &mut RT, params: ConstructorParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        rt.validate_immediate_caller_is(std::iter::once(&*INIT_ACTOR_ADDR))?;

        let st = State::new(rt.store(), params).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "Failed to create actor state")
        })?;
        rt.create(&st)?;
        Ok(())
    }

    /// Records a pre-commitment from an actor to perform an atomic
    /// execution. This method is to be invoked by a wrapped crossnet
    /// message originating in one of the execution actors involved in
    /// the atomic execution. Once the coordinator actor collects
    /// pre-commitments from all the execution actors, it emits for
    /// each of the execution actors a crossnet message triggering the
    /// specified method to commit the atomic execution.
    fn pre_commit<BS, RT>(rt: &mut RT, params: ApplyMsgParams) -> Result<bool, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway actor
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway_address))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg: StorableMsg { from, params, .. },
                    ..
                },
        } = params;

        let params: PreCommitParams = cbor::deserialize_params(&params)?;
        let actors = &params.actors;
        let exec_id = &params.exec_id;

        if !actors.contains(&from) {
            return Err(actor_error!(
                illegal_argument,
                "unexpected cross-message origin"
            ));
        }

        let msgs = rt.transaction(|st: &mut State, rt| {
            st.modify_atomic_exec(rt.store(), &exec_id, &actors, |entry| {
                // Record the pre-commitment
                entry.insert(from.to_string().unwrap(), params.commit);

                // Check if any pre-commitment is missing
                for actor in actors {
                    if !entry.contains_key(&actor.to_string().unwrap()) {
                        return Ok(None);
                    }
                }

                // Prepare messages to commit the atomic execution
                let mut msgs = Vec::new();
                for actor in actors {
                    let method = entry[&actor.to_string().unwrap()];
                    msgs.push(CrossMsg {
                        msg: StorableMsg {
                            from: IPC_ADDR_PLACEHOLDER.clone(),
                            to: actor.clone(),
                            method,
                            params: exec_id.clone(),
                            value: TokenAmount::default(),
                            nonce: 0,
                        },
                        wrapped: true,
                    });
                }
                Ok(Some(msgs))
            })
            .map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to update registry")
            })
        })?;

        match msgs {
            Some(msgs) => {
                // Send the messages to commit the atomic execution
                for msg in msgs {
                    rt.send(
                        st.ipc_gateway_address,
                        ipc_gateway::Method::SendCross as MethodNum,
                        RawBytes::serialize(msg)?,
                        TokenAmount::zero(),
                    )?;
                }

                // Remove the atomic execution entry
                rt.transaction(|st: &mut State, rt| {
                    st.rm_atomic_exec(rt.store(), &exec_id, &actors)
                        .map_err(|e| {
                            e.downcast_default(
                                ExitCode::USR_ILLEGAL_STATE,
                                "failed to remove atomic exec from registry",
                            )
                        })
                })?;

                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Removes a pre-commitment from an actor to perform an atomic
    /// execution. This method is to be invoked by a wrapped crossnet
    /// message originating in one of the execution actors involved in
    /// the atomic execution.
    fn revoke<BS, RT>(rt: &mut RT, params: ApplyMsgParams) -> Result<(), ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway actor
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway_address))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg: StorableMsg { from, params, .. },
                    ..
                },
        } = params;

        let params: RevokeParams = cbor::deserialize_params(&params)?;
        let actors = &params.actors;
        let exec_id = &params.exec_id;

        if !actors.contains(&from) {
            return Err(actor_error!(
                illegal_argument,
                "unexpected cross-message origin"
            ));
        }

        let msg = rt.transaction(|st: &mut State, rt| {
            st.modify_atomic_exec(rt.store(), &exec_id, &actors, |entry| {
                // Remove the pre-commitment
                entry.remove_entry(&from.to_string().unwrap());

                // Prepare a message to rollback the atomic execution
                Ok(Some(CrossMsg {
                    msg: StorableMsg {
                        from: IPC_ADDR_PLACEHOLDER.clone(),
                        to: from,
                        method: params.rollback,
                        params: exec_id.clone(),
                        value: TokenAmount::default(),
                        nonce: 0,
                    },
                    wrapped: true,
                }))
            })
            .map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to update registry")
            })
        })?;

        if let Some(msg) = msg {
            // Send the message to rollback the atomic execution
            rt.send(
                st.ipc_gateway_address,
                ipc_gateway::Method::SendCross as MethodNum,
                RawBytes::serialize(msg)?,
                TokenAmount::zero(),
            )?;
        }

        Ok(())
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
            Some(Method::PreCommit) => {
                let res = Self::pre_commit(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::Revoke) => {
                Self::revoke(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            None => Err(actor_error!(unhandled_message; "Invalid method")),
        }
    }
}
