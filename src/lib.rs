use crate::exec::{
    is_addr_in_exec, is_common_parent, AtomicExec, AtomicExecParamsRaw, ExecStatus, LockedOutput,
    SubmitExecParams, SubmitOutput,
};
use crate::state::State;
use cid::Cid;
use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{actor_error, cbor, ActorDowncast, ActorError, INIT_ACTOR_ADDR};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::error::ExitCode;
use fvm_shared::{MethodNum, METHOD_CONSTRUCTOR};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::subnet_id::SubnetID;
use crate::types::ConstructorParams;

mod address;
mod atomic;
mod cross;
mod error;
mod exec;
mod state;
mod subnet_id;
mod types;

fil_actors_runtime::wasm_trampoline!(Actor);

/// Atomic execution coordinator actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    InitAtomicExec = 2,
    SubmitAtomicExec = 3,
}

/// Atomic execution coordinator actor
pub struct Actor;

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

        let mut msgs = vec![];

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
                        let mut m = st
                            .propagate_exec_result(
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

                        msgs.append(&mut m);

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
                        let mut m = st
                            .propagate_exec_result(
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

                        msgs.append(&mut m);

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

        for (to, method, payload, amount) in msgs {
            rt.send(to, method, payload, amount)?;
        }

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
