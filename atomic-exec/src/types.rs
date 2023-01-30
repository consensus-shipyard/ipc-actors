use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::MethodNum;
use ipc_gateway::IPCAddress;

/// Concise identifier of an atomic execution instance.
pub type AtomicExecID = RawBytes;

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub ipc_gateway_address: Address,
}

/// Parameters for [crate::Method::PreCommit].
#[derive(Clone, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct PreCommitParams {
    /// Actors participating in the atomic execution. Corresponding
    /// invocations must agree on the order of elements in the vector.
    pub actors: Vec<IPCAddress>,
    /// Atomic execution ID.
    pub exec_id: AtomicExecID,
    /// Method to call back to commit atomic execution.
    pub commit: MethodNum,
}

/// Parameters for [crate::Method::Revoke].
#[derive(Clone, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct RevokeParams {
    /// Actors participating in the atomic execution. Corresponding
    /// invocations must agree on the order of elements in the vector.
    pub actors: Vec<IPCAddress>,
    /// Atomic execution ID.
    pub exec_id: AtomicExecID,
    /// Method to call back to rollback atomic execution.
    pub rollback: MethodNum,
}
