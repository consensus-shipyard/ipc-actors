// Copyright: ConsensusLab
//
use cid::multihash::Blake2b256;
use cid::multihash::Hasher;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::{Cbor, RawBytes};
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::MethodNum;
use ipc_gateway::IPCAddress;
use primitives::{TCid, THamt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::AtomicExecID;
use crate::ConstructorParams;

#[derive(Serialize, Deserialize)]
pub struct State {
    pub registry: RegistryCid, // H(exec_id, actors) -> pre-commitments
    pub ipc_gateway_address: Address,
}
impl Cbor for State {}

type RegistryCid = TCid<THamt<RegistryKey, RegistryEntry>>;
type RegistryKey = BytesKey;
type RegistryEntry = HashMap<IPCAddrString, MethodNum>;
type IPCAddrString = String;

impl State {
    pub fn new<BS: Blockstore>(store: &BS, params: ConstructorParams) -> anyhow::Result<State> {
        Ok(State {
            registry: TCid::new_hamt(store)?,
            ipc_gateway_address: params.ipc_gateway_address,
        })
    }

    /// Modifies the atomic execution entry associated with the atomic
    /// execution ID and the actors.
    pub fn modify_atomic_exec<BS: Blockstore, R>(
        &mut self,
        store: &BS,
        exec_id: &AtomicExecID,
        actors: &Vec<IPCAddress>,
        f: impl FnOnce(&mut RegistryEntry) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        let k = Self::registry_key(exec_id, actors);
        self.registry.modify(store, |registry| {
            let mut entry = registry
                .get(&k)?
                .map_or_else(HashMap::new, |e| e.to_owned());
            let res = f(&mut entry)?;
            registry.set(k, entry)?;
            Ok(res)
        })
    }

    /// Removes the atomic execution entry associated with the atomic
    /// execution ID and the actors.
    pub fn rm_atomic_exec<BS: Blockstore>(
        &mut self,
        store: &BS,
        exec_id: &AtomicExecID,
        actors: &Vec<IPCAddress>,
    ) -> anyhow::Result<()> {
        let k = Self::registry_key(exec_id, actors);
        self.registry.update(store, |registry| {
            registry.delete(&k)?;
            Ok(())
        })?;
        Ok(())
    }

    fn registry_key(exec_id: &AtomicExecID, actors: &Vec<IPCAddress>) -> RegistryKey {
        let mut h = Blake2b256::default();
        h.update(exec_id);
        h.update(&RawBytes::serialize(actors).unwrap());
        RegistryKey::from(h.finalize())
    }
}
