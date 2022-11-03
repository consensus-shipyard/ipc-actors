// Copyright: ConsensusLab
//
use cid::Cid;
use fil_actors_runtime::{ActorDowncast, Map, SYSTEM_ACTOR_ADDR};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use num_traits::Zero;
use primitives::{TCid, THamt, TLink};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

use crate::address::IPCAddress;
use crate::cross::StorableMsg;
use crate::exec::{AtomicExec, AtomicExecParams, AtomicExecParamsMeta};
use crate::subnet_id::SubnetID;
use crate::types::CrossMsgParams;
use crate::{atomic, ConstructorParams};

/// Storage power actor state
#[derive(Serialize, Deserialize)]
pub struct State {
    pub network_name: SubnetID,
    pub atomic_exec_registry: TCid<THamt<Cid, AtomicExec>>,
    pub nonce: u64,
    pub ipc_gateway_address: Address,
    pub ipc_gateway_cross_method_num: MethodNum,
}

impl Cbor for State {}

impl State {
    pub fn new<BS: Blockstore>(store: &BS, params: ConstructorParams) -> anyhow::Result<State> {
        Ok(State {
            network_name: SubnetID::from_str(&params.network_name)?,
            atomic_exec_registry: TCid::new_hamt(store)?,
            nonce: Default::default(),
            ipc_gateway_address: Address::from_bytes(&params.ipc_gateway_address)?,
            ipc_gateway_cross_method_num: MethodNum::from(params.ipc_gateway_cross_method_num),
        })
    }

    /// Gets an atomic execution by cid from the state
    pub fn get_atomic_exec<BS: Blockstore>(
        &self,
        store: &BS,
        cid: &TCid<TLink<AtomicExecParams>>,
    ) -> anyhow::Result<Option<AtomicExec>> {
        let registry = self.atomic_exec_registry.load(store)?;
        let exec = get_atomic_exec(&registry, cid)?;
        Ok(exec.cloned())
    }

    /// Sets a new atomic exec with Cid
    pub fn set_atomic_exec<BS: Blockstore>(
        &mut self,
        store: &BS,
        cid: &TCid<TLink<AtomicExecParamsMeta>>,
        exec: AtomicExec,
    ) -> anyhow::Result<()> {
        self.atomic_exec_registry.update(store, |registry| {
            registry
                .set(cid.cid().to_bytes().into(), exec)
                .map_err(|e| e.downcast_wrap("failed to set atomic exec"))?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn rm_atomic_exec<BS: Blockstore>(
        &mut self,
        store: &BS,
        cid: &TCid<TLink<AtomicExecParamsMeta>>,
    ) -> anyhow::Result<()> {
        self.atomic_exec_registry.update(store, |registry| {
            registry
                .delete(&cid.cid().to_bytes())
                .map_err(|e| e.downcast_wrap("failed to delete atomic exec"))?;
            Ok(())
        })?;
        Ok(())
    }

    /// Propagates the result of an execution to the corresponding subnets
    /// in a cross-net message.
    #[allow(clippy::too_many_arguments)]
    pub fn propagate_exec_result<BS: Blockstore>(
        &mut self,
        store: &BS,
        cid: &TCid<TLink<AtomicExecParamsMeta>>,
        exec: &AtomicExec,
        output: atomic::SerializedState, // LockableState to propagate. The same as in SubmitAtomicExecParams
        _curr_epoch: ChainEpoch,
        abort: bool,
    ) -> anyhow::Result<Vec<(Address, MethodNum, RawBytes, TokenAmount)>> {
        // This tracks the list of cross message to send
        let mut msgs = vec![];

        let mut visited = HashSet::new();
        let params = exec.params();
        for (k, v) in params.inputs.iter() {
            let sn = k.subnet()?;
            if visited.get(&sn).is_none() {
                // let mut msg =
                //     self.exec_result_msg(&sn, &v.actor, &params.msgs[0], output.clone(), abort)?;
                let msg =
                    self.exec_result_msg(&sn, &v.actor, &params.msgs[0], output.clone(), abort)?;

                // TODO: is this cross message correct?
                let cross_payload = fil_actors_runtime::util::cbor::serialize(
                    &CrossMsgParams::new(msg, sn.clone()),
                    "",
                )?;

                msgs.push(
                    (self.ipc_gateway_address, self.ipc_gateway_cross_method_num, cross_payload, TokenAmount::zero())
                );

                // mark as sent
                visited.insert(sn);
            }
        }

        // after propagating the execution result it is safe to remove the finalized execution
        // from the registry. Users looking to list previous atomic executions, we'll need
        // to inspect previous state (but this is a UX matter).
        self.rm_atomic_exec(store, cid)?;

        Ok(msgs)
    }

    fn exec_result_msg(
        &self,
        subnet: &SubnetID,
        actor: &Address,
        msg: &StorableMsg,
        output: atomic::SerializedState, /* FIXME: LockedState to propagate. The same as in SubmitAtomicExecParams*/
        abort: bool,
    ) -> anyhow::Result<StorableMsg> {
        // to signal that is a system message we use system_actor_addr as source.
        // TODO: do we expect SYSTEM_ACTOR_ADDR still?
        let from = IPCAddress::new(&self.network_name, &SYSTEM_ACTOR_ADDR)?;
        let to = IPCAddress::new(subnet, actor)?;
        let lock_params = atomic::LockParams::new(msg.method, msg.clone().params);
        if abort {
            let method = atomic::METHOD_ABORT;
            let enc = RawBytes::serialize(lock_params)?;
            return Ok(StorableMsg {
                to,
                from,
                value: TokenAmount::zero(),
                nonce: self.nonce,
                method,
                params: enc,
            });
        }

        let method = atomic::METHOD_UNLOCK;
        let unlock_params = atomic::UnlockParams::new(lock_params, output);
        let enc = RawBytes::serialize(unlock_params)?;
        Ok(StorableMsg {
            to,
            from,
            value: TokenAmount::zero(),
            nonce: self.nonce,
            method,
            params: enc,
        })
    }
}

fn get_atomic_exec<'m, BS: Blockstore>(
    registry: &'m Map<BS, AtomicExec>,
    cid: &TCid<TLink<AtomicExecParams>>,
) -> anyhow::Result<Option<&'m AtomicExec>> {
    let c = cid.cid();
    registry
        .get(&c.to_bytes())
        .map_err(|e| e.downcast_wrap(format!("failed to get atomic exec for cid {}", c)))
}
