//! This is a simplistic example of an [FRC-0046][frc-46]-like actor supporting
//! atomic execution. It illustrates how the atomic execution
//! primitives can be used.
//!
//! [frc-46]: https://github.com/filecoin-project/FIPs/blob/master/FRCs/frc-0046.md

use frc42_dispatch::method_hash;
use fvm_actors_runtime::runtime::{ActorCode, Runtime};
use fvm_actors_runtime::{
    actor_dispatch, actor_error, restrict_internal_api, ActorDowncast, ActorError, INIT_ACTOR_ADDR,
};
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::{MethodNum, METHOD_CONSTRUCTOR};
use ipc_atomic_execution_primitives::{AtomicExecID, AtomicInputID};
use ipc_gateway::{ApplyMsgParams, CrossMsg, IPCAddress, StorableMsg, SubnetID};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use state::{AtomicTransfer, State};
use std::collections::HashMap;
use std::str::FromStr;

mod state;

#[cfg(test)]
mod tests;

fvm_actors_runtime::wasm_trampoline!(Actor);

lazy_static::lazy_static! {
    static ref IPC_ADDR_PLACEHOLDER: IPCAddress = IPCAddress::new(
        &SubnetID::default(),
        &Address::new_bls(&[0; fvm_shared::address::BLS_PUB_LEN]).unwrap(),
    )
        .unwrap();
}

/// Method numbers.
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    /// Actor constructor; takes [ConstructorParams] as parameter.
    Constructor = METHOD_CONSTRUCTOR,
    /// Returns the name of the token.
    Name = method_hash!("Name"),
    /// Returns the ticker symbol of the token.
    Symbol = method_hash!("Symbol"),
    /// Returns the total amount of the token in existence.
    TotalSupply = method_hash!("TotalSupply"),
    /// Returns the balance of an address. Takes [Address] as
    /// parameter.
    Balance = method_hash!("Balance"),
    /// Transfers tokens from caller to another address. Takes
    /// [TransferParams] as parameter and returns [TransferReturn].
    Transfer = method_hash!("Transfer"),
    /// Initiates a transfer of tokens as part of an atomic execution.
    /// Takes [InitAtomicTransferParams] as parameter and returns
    /// [AtomicInputID]. To be followed by [Method::PrepareAtomicTransfer] or
    /// [Method::CancelAtomicTransfer].
    InitAtomicTransfer = method_hash!("InitAtomicTransfer"),
    /// Prepares an initiated atomic transfer of tokens. Takes
    /// [PrepareAtomicTransferParams] as parameter and returns
    /// [AtomicExecID]. Can be followed by
    /// [Method::AbortAtomicTransfer] until the coordinator actor has
    /// committed the atomic execution.
    PrepareAtomicTransfer = method_hash!("PrepareAtomicTransfer"),
    /// Cancels an initiated but not yet prepared atomic transfer of
    /// tokens. Takes [AtomicInputID] as parameter.
    CancelAtomicTransfer = method_hash!("CancelAtomicTransfer"),
    /// Callback method to commit an atomic transfer of tokens; to be
    /// triggered by a cross-message from the coordinator actor.
    CommitAtomicTransfer = method_hash!("CommitAtomicTransfer"),
    /// Aborts a prepared atomic transfer of tokens. Takes
    /// [AbortAtomicTransferParams] as parameter.
    AbortAtomicTransfer = method_hash!("AbortAtomicTransfer"),
    /// Rolls back a prepared atomic transfer of tokens; to be
    /// triggered by a cross-message from the coordinator actor.
    RollbackAtomicTransfer = method_hash!("RollbackAtomicTransfer"),
}

struct Actor;

// Address representation as a string.
pub type AddrString = String;

/// Parameters of [Method::Constructor].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    /// Address of the IPC gateway actor.
    pub ipc_gateway: Address,
    /// ID of the current subnet.
    pub subnet_id: SubnetID,
    /// Token name.
    pub name: String,
    /// Token ticker symbol.
    pub symbol: String,
    /// Initial balance table.
    pub balances: HashMap<AddrString, TokenAmount>,
}

/// Parameters of [Method::Transfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TransferParams {
    /// Recipient address.
    pub to: Address,
    /// Token amount to transfer.
    pub amount: TokenAmount,
}

/// Return values of [Method::Transfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TransferReturn {
    /// Resulting sender's balance.
    pub from_balance: TokenAmount,
    /// Resulting recipient's balance.
    pub to_balance: TokenAmount,
}

/// Parameters of [Method::InitAtomicTransfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct InitAtomicTransferParams {
    /// IPC address of the coordinator actor.
    pub coordinator: IPCAddress,
    /// Token transfer parameters.
    pub transfer: TransferParams,
}

/// Parameters of [Method::PrepareAtomicTransfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct PrepareAtomicTransferParams {
    /// Atomic input IDs from all executing actors participating in
    /// the atomic execution. Corresponding invocations must agree on the
    /// order of elements in the vector.
    pub input_ids: Vec<(IPCAddress, AtomicInputID)>,
}

/// Parameters of [Method::AbortAtomicTransfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct AbortAtomicTransferParams {
    /// IPC addresses of all execution actors participating in the
    /// atomic execution. Corresponding invocations must agree on the
    /// order of elements in the vector.
    pub actors: Vec<IPCAddress>,
    /// Atomic execution ID.
    pub exec_id: AtomicExecID,
}

impl Actor {
    // Handles Constructor method.
    fn constructor(rt: &mut impl Runtime, params: ConstructorParams) -> Result<(), ActorError> {
        // Ensure the constructor is called by the Init system actor.
        rt.validate_immediate_caller_is(std::iter::once(&INIT_ACTOR_ADDR))?;

        let ConstructorParams {
            ipc_gateway,
            subnet_id,
            name,
            symbol,
            balances,
        } = params;
        let ipc_address = IPCAddress::new(&subnet_id, &rt.message().receiver()).unwrap();

        // Resolve initial balance owners' addresses into ID addresses
        // and collect the balances into a new hash map indexed by ID
        // addresses.
        let balances = balances.into_iter().try_fold(HashMap::new(), |mut m, (a, b)| -> Result<_, ActorError> {
            let id = rt
                .resolve_address(&Address::from_str(&a).map_err(|e| actor_error!(
                    illegal_argument; "cannot parse address in initial balance table: {}", e))?
                )
                .ok_or_else(|| actor_error!(illegal_argument; "cannot resolve address in initial balance table"))?
                .id()
                .unwrap();
            m.insert(id, b);
            Ok(m)
        })?;

        // Create the initial actor state.
        let st = State::new(rt.store(), ipc_gateway, ipc_address, name, symbol, balances).map_err(
            |e| e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to create actor state"),
        )?;
        rt.create(&st)?;

        Ok(())
    }

    // Handles Name method.
    fn name(rt: &mut impl Runtime) -> Result<String, ActorError> {
        let st: State = rt.state()?;
        Ok(st.name().to_string())
    }

    // Handles Symbol method.
    fn symbol(rt: &mut impl Runtime) -> Result<String, ActorError> {
        let st: State = rt.state()?;
        Ok(st.symbol().to_string())
    }

    // Handles TotalSupply method.
    fn total_supply(rt: &mut impl Runtime) -> Result<TokenAmount, ActorError> {
        let st: State = rt.state()?;
        Ok(st.total_supply().clone())
    }

    // Handles Balance method.
    fn balance(rt: &mut impl Runtime, addr: Address) -> Result<TokenAmount, ActorError> {
        let id = rt
            .resolve_address(&addr)
            .ok_or_else(|| actor_error!(illegal_argument; "cannot resolve account address"))?
            .id()
            .unwrap();
        let st: State = rt.state()?;
        let b = st.balance(rt.store(), id).map_err(|e| {
            e.downcast_default(
                ExitCode::USR_ILLEGAL_STATE,
                "failed to get balance from store",
            )
        })?;
        Ok(b)
    }

    // Handles Transfer method.
    fn transfer(
        rt: &mut impl Runtime,
        params: TransferParams,
    ) -> Result<TransferReturn, ActorError> {
        let TransferParams { to, amount } = params;

        // Resolve sender's and recipient's addresses to ID addresses.
        let from_id = rt.message().caller().id().unwrap();
        let to_id = rt
            .resolve_address(&to)
            .ok_or_else(
                || actor_error!(illegal_argument; "cannot resolve destination account address"),
            )?
            .id()
            .unwrap();

        // Attempt to modify the state to reflect the transfer.
        let (from_balance, to_balance) = rt.transaction(|st: &mut State, rt| {
            st.transfer(rt.store(), from_id, to_id, amount)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot perform transfer")
                })
        })?;

        Ok(TransferReturn {
            from_balance,
            to_balance,
        })
    }

    // Handles InitAtomicTransfer method.
    fn init_atomic_transfer(
        rt: &mut impl Runtime,
        params: InitAtomicTransferParams,
    ) -> Result<AtomicInputID, ActorError> {
        let InitAtomicTransferParams {
            coordinator,
            transfer: TransferParams { to, amount },
        } = params;

        // Resolve sender's and recipient's addresses to ID addresses.
        let from_id = rt.message().caller().id().unwrap();
        let to_id = rt
            .resolve_address(&to)
            .ok_or_else(
                || actor_error!(illegal_argument; "cannot resolve destination account address"),
            )?
            .id()
            .unwrap();

        // Attempt to modify the state to initiate an atomic transfer.
        let input_id = rt.transaction(|st: &mut State, rt| {
            st.init_atomic_transfer(rt.store(), coordinator, from_id, to_id, amount)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot init atomic transfer")
                })
        })?;
        Ok(input_id)
    }

    // Handles CancelAtomicTransfer method.
    fn cancel_atomic_transfer(
        rt: &mut impl Runtime,
        input_id: AtomicInputID,
    ) -> Result<(), ActorError> {
        // Resolve sender's address to ID addresses.
        let from_id = rt.message().caller().id().unwrap();

        // Attempt to modify the state to cancel the atomic transfer.
        rt.transaction(|st: &mut State, rt| {
            st.cancel_atomic_transfer(rt.store(), from_id, input_id)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot cancel atomic transfer")
                })
        })
    }

    // Handles PrepareAtomicTransfer method.
    fn prepare_atomic_transfer(
        rt: &mut impl Runtime,
        params: PrepareAtomicTransferParams,
    ) -> Result<AtomicExecID, ActorError> {
        let PrepareAtomicTransferParams { input_ids } = params;

        // Resolve sender's address to ID addresses.
        let from_id = rt.message().caller().id().unwrap();

        // Attempt to modify the state to prepare the atomic transfer.
        // This returns the IPC address of the coordinator actor and
        // the atomic exec ID.
        let st: State = rt.state()?;
        let (coordinator, exec_id) = rt.transaction(|st: &mut State, rt| {
            st.prep_atomic_transfer(rt.store(), from_id, &input_ids)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot prepare atomic transfer")
                })
        })?;

        // Send a cross-message to the coordinator actor,
        // pre-committing the atomic transfer.
        let msg = CrossMsg {
            msg: ipc_gateway::StorableMsg {
                from: IPC_ADDR_PLACEHOLDER.clone(),
                to: coordinator,
                method: ipc_atomic_execution::Method::PreCommit as MethodNum,
                params: RawBytes::serialize(ipc_atomic_execution::PreCommitParams {
                    actors: input_ids.iter().map(|(a, _)| a.clone()).collect(),
                    exec_id: exec_id.clone(),
                    commit: Method::CommitAtomicTransfer as MethodNum,
                })?,
                value: TokenAmount::default(),
                nonce: 0,
            },
            wrapped: true,
        };
        rt.send(
            &st.ipc_gateway(),
            ipc_gateway::Method::SendCross as MethodNum,
            IpldBlock::serialize_cbor(&msg)?,
            TokenAmount::default(),
        )?;

        Ok(exec_id)
    }

    // Handles CommitAtomicTransfer method.
    fn commit_atomic_transfer(
        rt: &mut impl Runtime,
        params: ApplyMsgParams,
    ) -> Result<(), ActorError> {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway.
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway()))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg:
                        StorableMsg {
                            from,
                            params: exec_id,
                            ..
                        },
                    ..
                },
        } = params;

        // Modify the state to commit the atomic transfer.
        rt.transaction(|st: &mut State, rt| {
            st.commit_atomic_transfer(rt.store(), from, exec_id)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot commit atomic transfer")
                })
        })
    }

    // Handles AbortAtomicTransfer method.
    fn abort_atomic_transfer(
        rt: &mut impl Runtime,
        params: AbortAtomicTransferParams,
    ) -> Result<(), ActorError> {
        let AbortAtomicTransferParams { actors, exec_id } = params;

        // Resolve sender's address to ID addresses.
        let from_id = rt.message().caller().id().unwrap();

        // Retrieve the IPC address of the coordinator actor
        // associates with this atomic transfer.
        let st: State = rt.state()?;
        let AtomicTransfer {
            coordinator,
            from: orig_from,
            ..
        } = st
            .atomic_transfer_coordinator(rt.store(), &exec_id)
            .map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_UNSPECIFIED,
                    "cannot retrieve coordinator actor address",
                )
            })?;

        // Check if the sender matches
        if from_id != orig_from {
            return Err(actor_error!(forbidden; "unexpected sender address"));
        }

        // Send a cross-message to the coordinator actor, revoking
        // actor's pre-committment to the atomic transfer.
        let msg = CrossMsg {
            msg: ipc_gateway::StorableMsg {
                from: IPC_ADDR_PLACEHOLDER.clone(),
                to: coordinator,
                method: ipc_atomic_execution::Method::Revoke as MethodNum,
                params: RawBytes::serialize(ipc_atomic_execution::RevokeParams {
                    actors,
                    exec_id,
                    rollback: Method::RollbackAtomicTransfer as MethodNum,
                })?,
                value: TokenAmount::default(),
                nonce: 0,
            },
            wrapped: true,
        };
        rt.send(
            &st.ipc_gateway(),
            ipc_gateway::Method::SendCross as MethodNum,
            IpldBlock::serialize_cbor(&msg)?,
            TokenAmount::default(),
        )?;
        Ok(())
    }

    // Handles RollbackAtomicTransfer method.
    fn rollback_atomic_transfer(
        rt: &mut impl Runtime,
        params: ApplyMsgParams,
    ) -> Result<(), ActorError> {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway actor
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway()))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg:
                        StorableMsg {
                            from,
                            params: exec_id,
                            ..
                        },
                    ..
                },
        } = params;

        // Modify the state to roll back the atomic transfer.
        rt.transaction(|st: &mut State, rt| {
            st.rollback_atomic_transfer(rt.store(), from, exec_id)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot rollback atomic transfer")
                })
        })
    }
}

impl ActorCode for Actor {
    type Methods = Method;

    actor_dispatch! {
        Constructor => constructor,
        Name => name,
        Symbol => symbol,
        TotalSupply => total_supply,
        Balance => balance,
        Transfer => transfer,
        InitAtomicTransfer => init_atomic_transfer,
        PrepareAtomicTransfer => prepare_atomic_transfer,
        CancelAtomicTransfer => cancel_atomic_transfer,
        CommitAtomicTransfer => commit_atomic_transfer,
        AbortAtomicTransfer => abort_atomic_transfer,
        RollbackAtomicTransfer => rollback_atomic_transfer,
    }
}
