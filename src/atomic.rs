use cid::multihash::Code::Blake2b256;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fil_actors_runtime::cbor;
use fvm_ipld_encoding::tuple::Deserialize_tuple;
use fvm_ipld_encoding::{serde_bytes, Cbor, RawBytes, DAG_CBOR};
use fvm_shared::MethodNum;
use primitives::{TCid, THamt};
use serde::{de::DeserializeOwned, Serialize};

/// Trait that determines the functions that need to be implemented by
/// a state object to be lockable and be used in an atomic execution.
///
/// Different strategies may be used to merge different locked state to
/// prepare the actor state for the execution, and for the merging of the
/// output of the execution to the original state of the actor.
pub trait MergeableState<S: Serialize + DeserializeOwned> {
    /// Merge a locked state (not necessarily the output) to the current state.
    fn merge(&mut self, other: Self) -> anyhow::Result<()>;
    /// Merge the output of an execution to the current state.
    fn merge_output(&mut self, other: Self) -> anyhow::Result<()>;
}

/// Internal map kept by actor supporting atomic executions to track
/// the states that have been locked and are used in an atomic exec.
#[allow(dead_code)]
pub type LockedMap<T> = TCid<THamt<Cid, LockableState<T>>>;

/// Trait that specifies the interface of an actor state able to support
/// atomic executions.
pub trait LockableActorState<T>
where
    T: Serialize + DeserializeOwned + MergeableState<T>,
{
    /// Map with all the locked state in the actor uniquely identified through
    /// their Cid.
    fn locked_map_cid(&self) -> LockedMap<T>;
    /// Returns the output state of an execution from the current state
    /// of the actor according to the input parameters.
    fn output(&self, params: LockParams) -> LockableState<T>;
}

/// Return type for all actor functions.
///
/// It returns an option for developers to optionally choose if
/// to return an output in the function.
#[allow(dead_code)]
type ActorResult = anyhow::Result<Option<RawBytes>>;

/// Trait for an actor able to support an atomic execution.
///
/// The functions of this trait represent the set of methods that
/// and actor support atomic executions needs to implement. Correspondingly,
/// it follows the same return convention used for every FVM actor method.
pub trait LockableActor<T, S>
where
    T: Serialize + DeserializeOwned + MergeableState<T>,
    S: Serialize + DeserializeOwned + LockableActorState<T>,
{
    /// Locks the state to perform the execution determined by the locking params.
    fn lock(params: LockParams) -> ActorResult;
    /// Merges some state to the current state of the actor to prepare for the execution
    /// of the protocol.
    fn merge(params: MergeParams<T>) -> ActorResult;
    /// Merges the output state of an execution to the actor and unlocks the state
    /// involved in the execution.
    fn unlock(params: UnlockParams) -> ActorResult;
    /// Aborts the execution and unlocks the locked state.
    fn abort(params: LockParams) -> ActorResult;
    /// Returns the lockable state of the actor.
    fn state(params: LockParams) -> S;
}

/// Serialized representation of the locked state of an actor.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize_tuple, Default)]
pub struct SerializedState {
    #[serde(with = "serde_bytes")]
    ser: Vec<u8>,
}
impl SerializedState {
    // TODO: This is used for testing purposes in order to have all the
    // SCA functions running. In the next iteration we will implement proper
    // primitives to get from/to a MergeableState to SerializedState using
    // code-gen and generics.
    #[allow(dead_code)]
    pub fn new(ser: Vec<u8>) -> Self {
        SerializedState { ser }
    }

    #[allow(dead_code)]
    pub fn cid(&self) -> Cid {
        Cid::new_v1(DAG_CBOR, Blake2b256.digest(self.ser.as_slice()))
    }
}

/// Parameters used to lock certain state of an actor for its use in an atomic
/// execution
///
/// Different locking strategies may be implemented in the actor according to the
/// method and parameters used in the atomic execution. This parameters gives
/// information to the actor about the execution to be performed and thus the state
/// that needs to be locked.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize_tuple)]
pub struct LockParams {
    pub method: MethodNum,
    pub params: RawBytes,
}

impl Cbor for LockParams {}

impl LockParams {
    #[allow(dead_code)]
    pub fn new(method: MethodNum, params: RawBytes) -> Self {
        LockParams { method, params }
    }
}

/// Parameters used to specify the input state to merge to the current
/// state of an actor to perform the atomic execution.
#[derive(Serialize, Deserialize_tuple)]
pub struct MergeParams<T>
where
    T: Serialize + DeserializeOwned + MergeableState<T>,
{
    state: T,
}
impl<T: Serialize + DeserializeOwned + MergeableState<T>> Cbor for MergeParams<T> {}

/// Unlock parameters that pass the output of the execution as the serialized
/// output state of the execution, along with the lock parameters that determines
/// the type of execution being performed and thus the merging strategy that needs
/// to be followed by the actor.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize_tuple)]
pub struct UnlockParams {
    pub params: LockParams,
    pub state: SerializedState, // FIXME: This is a locked state for the output. We may be able to use generics here.
}
impl Cbor for UnlockParams {}
impl UnlockParams {
    #[allow(dead_code)]
    pub fn new(params: LockParams, state: SerializedState) -> Self {
        UnlockParams { params, state }
    }

    #[allow(dead_code)]
    pub fn from_raw_bytes(ser: &RawBytes) -> anyhow::Result<Self> {
        Ok(cbor::deserialize_params(ser)?)
    }
}

/// State of an actor including a lock to support atomic executions.
#[derive(Serialize, Deserialize_tuple)]
pub struct LockableState<T>
where
    T: Serialize + DeserializeOwned + MergeableState<T>,
{
    lock: bool,
    state: T,
}
impl<T: Serialize + DeserializeOwned + MergeableState<T>> Cbor for LockableState<T> {}
