//! This is a simplistic example of an [FRC-0046][frc-46]-like actor supporting
//! atomic execution. It illustrates how the atomic execution
//! primitives can be used.
//!
//! [frc-46]: https://github.com/filecoin-project/FIPs/blob/master/FRCs/frc-0046.md

use frc42_macros::method_hash;
use fvm_actors_runtime::runtime::{ActorCode, Runtime};
use fvm_actors_runtime::{actor_error, cbor, ActorDowncast, ActorError, INIT_ACTOR_ADDR};
use fvm_ipld_blockstore::Blockstore;
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
use state::State;
use std::collections::{HashMap, HashSet};

mod state;

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
    pub balances: HashMap<Address, TokenAmount>,
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
    /// the atomic execution.
    pub input_ids: HashMap<IPCAddress, AtomicInputID>,
}

/// Parameters of [Method::AbortAtomicTransfer].
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct AbortAtomicTransferParams {
    /// IPC addresses of all execution actors participating in the
    /// atomic execution.
    pub actors: HashSet<IPCAddress>,
    /// Atomic execution ID.
    pub exec_id: AtomicExecID,
}

impl Actor {
    // Handles Constructor method.
    fn constructor<BS, RT>(rt: &mut RT, params: ConstructorParams) -> Result<(), ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        // Ensure the constructor is called by the Init system actor.
        rt.validate_immediate_caller_is(std::iter::once(&*INIT_ACTOR_ADDR))?;

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
                .resolve_address(&a)
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
    fn name<BS, RT>(rt: &mut RT) -> Result<String, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;
        Ok(st.name().to_string())
    }

    // Handles Symbol method.
    fn symbol<BS, RT>(rt: &mut RT) -> Result<String, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;
        Ok(st.symbol().to_string())
    }

    // Handles TotalSupply method.
    fn total_supply<BS, RT>(rt: &mut RT) -> Result<TokenAmount, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;
        Ok(st.total_supply().clone())
    }

    // Handles Balance method.
    fn balance<BS, RT>(rt: &mut RT, addr: Address) -> Result<TokenAmount, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
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
    fn transfer<BS, RT>(rt: &mut RT, params: TransferParams) -> Result<TransferReturn, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
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
    fn init_atomic_transfer<BS, RT>(
        rt: &mut RT,
        params: InitAtomicTransferParams,
    ) -> Result<AtomicInputID, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
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
    fn cancel_atomic_transfer<BS, RT>(
        rt: &mut RT,
        input_id: AtomicInputID,
    ) -> Result<(), ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        // Modify the state to cancel the atomic transfer.
        rt.transaction(|st: &mut State, rt| {
            st.cancel_atomic_transfer(rt.store(), input_id)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot cancel atomic transfer")
                })
        })
    }

    // Handles PrepareAtomicTransfer method.
    fn prepare_atomic_transfer<BS, RT>(
        rt: &mut RT,
        params: PrepareAtomicTransferParams,
    ) -> Result<AtomicExecID, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let PrepareAtomicTransferParams { input_ids } = params;

        // Attempt to modify the state to prepare the atomic transfer.
        // This returns the IPC address of the coordinator actor and
        // the atomic exec ID.
        let st: State = rt.state()?;
        let (coordinator, exec_id) = rt.transaction(|st: &mut State, rt| {
            st.prep_atomic_transfer(rt.store(), &input_ids)
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
                    actors: input_ids.keys().cloned().collect(),
                    exec_id: exec_id.clone(),
                    commit: Method::CommitAtomicTransfer as MethodNum,
                })?,
                value: TokenAmount::default(),
                nonce: 0,
            },
            wrapped: true,
        };
        rt.send(
            st.ipc_gateway(),
            ipc_gateway::Method::SendCross as MethodNum,
            RawBytes::serialize(msg)?,
            TokenAmount::default(),
        )?;

        Ok(exec_id)
    }

    // Handles CommitAtomicTransfer method.
    fn commit_atomic_transfer<BS, RT>(rt: &mut RT, params: ApplyMsgParams) -> Result<(), ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway.
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway()))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg: StorableMsg { from, params, .. },
                    ..
                },
        } = params;
        let exec_id = cbor::deserialize_params(&params)?;

        // Modify the state to commit the atomic transfer.
        rt.transaction(|st: &mut State, rt| {
            st.commit_atomic_transfer(rt.store(), from, exec_id)
                .map_err(|e| {
                    e.downcast_default(ExitCode::USR_UNSPECIFIED, "cannot commit atomic transfer")
                })
        })
    }

    // Handles AbortAtomicTransfer method.
    fn abort_atomic_transfer<BS, RT>(
        rt: &mut RT,
        params: AbortAtomicTransferParams,
    ) -> Result<(), ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let AbortAtomicTransferParams { actors, exec_id } = params;

        // Retrieve the IPC address of the coordinator actor
        // associates with this atomic transfer.
        let st: State = rt.state()?;
        let coordinator = st
            .atomic_transfer_coordinator(rt.store(), &exec_id)
            .map_err(|e| {
                e.downcast_default(
                    ExitCode::USR_UNSPECIFIED,
                    "cannot retrieve coordinator actor address",
                )
            })?;

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
            st.ipc_gateway(),
            ipc_gateway::Method::SendCross as MethodNum,
            RawBytes::serialize(msg)?,
            TokenAmount::default(),
        )?;
        Ok(())
    }

    // Handles RollbackAtomicTransfer method.
    fn rollback_atomic_transfer<BS, RT>(
        rt: &mut RT,
        params: ApplyMsgParams,
    ) -> Result<(), ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        let st: State = rt.state()?;

        // Check if the cross-message comes from the IPC gateway actor
        rt.validate_immediate_caller_is(std::iter::once(&st.ipc_gateway()))?;

        let ApplyMsgParams {
            cross_msg:
                CrossMsg {
                    msg: StorableMsg { from, params, .. },
                    ..
                },
        } = params;
        let exec_id = cbor::deserialize_params(&params)?;

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
    fn invoke_method<BS, RT>(
        rt: &mut RT,
        method: MethodNum,
        params: &RawBytes,
    ) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore + Clone,
        RT: Runtime<BS>,
    {
        match FromPrimitive::from_u64(method) {
            Some(Method::Constructor) => {
                Self::constructor(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::Name) => {
                let res = Self::name(rt)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::Symbol) => {
                let res = Self::symbol(rt)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::TotalSupply) => {
                let res = Self::total_supply(rt)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::Balance) => {
                let res = Self::balance(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::Transfer) => {
                let res = Self::transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::InitAtomicTransfer) => {
                let res = Self::init_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::PrepareAtomicTransfer) => {
                let res = Self::prepare_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::serialize(res)?)
            }
            Some(Method::CancelAtomicTransfer) => {
                Self::cancel_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::CommitAtomicTransfer) => {
                Self::commit_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::AbortAtomicTransfer) => {
                Self::abort_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            Some(Method::RollbackAtomicTransfer) => {
                Self::rollback_atomic_transfer(rt, cbor::deserialize_params(params)?)?;
                Ok(RawBytes::default())
            }
            None => Err(actor_error!(unhandled_message; "Invalid method")),
        }
    }
}
