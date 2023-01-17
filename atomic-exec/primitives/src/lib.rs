use cid::multihash::{Blake2b256, MultihashDigest};
use cid::multihash::{Code, Hasher};
use fvm_ipld_hamt::BytesKey;
use ipc_gateway::IPCAddress;
use std::ops::Deref;

use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::tuple::Deserialize_tuple;
use fvm_ipld_encoding::{Cbor, CborStore, RawBytes, DAG_CBOR};
use fvm_primitives::{TCid, THamt};
use serde::Deserialize;
use serde::{self, de::DeserializeOwned, Serialize};
use serde_tuple::Serialize_tuple;

pub use ipc_atomic_execution::AtomicExecID;

/// State that supports locking, as well as computing its CID.
pub trait LockableState: Cbor {
    /// Locks the state so that it cannot be changed until unlocked.
    fn lock(&mut self) -> anyhow::Result<()>;

    /// Unlocks the state and allows it to be modified.
    fn unlock(&mut self) -> anyhow::Result<()>;

    /// Checks if the state is locked.
    fn is_locked(&self) -> bool;

    /// Returns current state CID.
    fn cid(&self) -> Cid {
        cid_from_cbor(self)
    }
}

/// Computes the CID of a CBOR object.
fn cid_from_cbor(obj: &impl Cbor) -> Cid {
    Cid::new_v1(
        DAG_CBOR,
        Code::Blake2b256.digest(&obj.marshal_cbor().unwrap()),
    )
}

/// Lockable piece of actor state that can be used as an input for
/// atomic execution.
///
/// It can be either incorporated into other data structure, or
/// referred to by its CID. In the latter case, it is user's
/// responsibility to flush to and load from the blockstore.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize_tuple, Deserialize_tuple)]
pub struct AtomicInputState<T>
where
    T: Serialize + DeserializeOwned,
{
    // Flag indicating if the state is locked.
    locked: bool,

    // Arbitrary piece of state.
    state: T,
}
impl<T: Serialize + DeserializeOwned> Cbor for AtomicInputState<T> {}

impl<T: Serialize + DeserializeOwned> AtomicInputState<T> {
    /// Converts some state into a lockable piece of state.
    pub fn new(state: T) -> Self {
        Self {
            locked: false,
            state,
        }
    }

    /// Attempts to load the content from the blockstore.
    pub fn load(cid: &Cid, bs: &impl Blockstore) -> anyhow::Result<Option<Self>> {
        let res = bs.get_cbor::<Self>(cid)?;
        Ok(res)
    }

    /// Flushes the content to the blockstore.
    pub fn flush(&self, bs: &impl Blockstore) -> anyhow::Result<Cid> {
        let cid = bs.put_cbor(&self, Code::Blake2b256)?;
        Ok(cid)
    }

    /// Returns a shared reference to the inner content.
    pub fn get(&self) -> &T {
        &self.state
    }

    /// Attempts to set the inner content; fails if the state is
    /// locked.
    pub fn set(&mut self, state: T) -> anyhow::Result<()> {
        self.modify(|s| {
            *s = state;
            Ok(())
        })
    }

    /// Attempts to get a mutable reference to the inner content;
    /// fails if the state is locked.
    pub fn get_mut(&mut self) -> anyhow::Result<&mut T> {
        match self.locked {
            false => Ok(&mut self.state),
            true => Err(anyhow::anyhow!("cannot modify locked state")),
        }
    }

    /// Attempts to modify the inner content in the supplied closure,
    /// as well as to produce some result value; fails if locked.
    pub fn modify<F, R>(&mut self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut T) -> anyhow::Result<R>,
    {
        let s = self.get_mut()?;
        let r = f(s)?;
        Ok(r)
    }
}

impl<T: Serialize + DeserializeOwned> Deref for AtomicInputState<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.state
    }
}

impl<T: Serialize + DeserializeOwned> LockableState for AtomicInputState<T> {
    fn lock(&mut self) -> anyhow::Result<()> {
        match self.locked {
            false => {
                self.locked = true;
                Ok(())
            }
            true => Err(anyhow::anyhow!("state already locked")),
        }
    }

    fn unlock(&mut self) -> anyhow::Result<()> {
        match self.locked {
            true => {
                self.locked = false;
                Ok(())
            }
            false => Err(anyhow::anyhow!("state not locked")),
        }
    }

    fn is_locked(&self) -> bool {
        self.locked
    }

    fn cid(&self) -> Cid {
        cid_from_cbor(self)
    }
}

impl<T: Default + Serialize + DeserializeOwned> Default for AtomicInputState<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

/// Concise identifier of an atomic execution input.
pub type AtomicInputID = RawBytes;

type AtomicExecNonce = u64;

/// Internal state associated with an atomic execution input.
#[derive(Debug, PartialEq, Serialize_tuple, Deserialize_tuple)]
struct AtomicInputEntry {
    unlocked_state_cids: Vec<Cid>,
    input: RawBytes,
}
impl Cbor for AtomicInputEntry {}

/// Internal state associated with an atomic execution ID.
#[derive(Debug, PartialEq, Serialize_tuple, Deserialize_tuple)]
struct AtomicOutputEntry {
    output: RawBytes,
}

/// Registry of atomic execution instances.
///
/// Each atomic execution actor should maintain a single instance of
/// it as a part of its state. It can be either incorporated into a
/// bigger data structure, or referred to by its CID. In the latter
/// case, it is user's responsibility to flush to and load from the
/// blockstore.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtomicExecRegistry {
    nonce: AtomicExecNonce,
    input_ids: TCid<THamt<AtomicInputID, AtomicInputEntry>>,
    exec_ids: TCid<THamt<AtomicExecID, AtomicOutputEntry>>,
}
impl Cbor for AtomicExecRegistry {}

impl AtomicExecRegistry {
    /// Constructs a new instance of the atomic execution registry.
    ///
    /// It flushes its internals to the supplied blockstore. However,
    /// the registry itself is not flushed to the blockstore.
    pub fn new(bs: &impl Blockstore) -> anyhow::Result<AtomicExecRegistry> {
        Ok(Self {
            nonce: 0,
            input_ids: TCid::new_hamt(bs)?,
            exec_ids: TCid::new_hamt(bs)?,
        })
    }

    /// Loads the atomic execution registry from the supplied
    /// blockstore by its CID.
    pub fn load(cid: &Cid, bs: &impl Blockstore) -> anyhow::Result<Option<AtomicExecRegistry>> {
        bs.get_cbor(cid)
    }

    /// Flushes the atomic execution registry to the supplied
    /// blockstore and return its CID.
    pub fn flush(&self, bs: &impl Blockstore) -> anyhow::Result<Cid> {
        let cid = bs.put_cbor(&self, Code::Blake2b256)?;
        Ok(cid)
    }

    /// Initializes a new instance of the atomic execution protocol.
    ///
    /// It returns a unique identifier of the atomic execution input.
    ///
    /// The supplied iterable collection `state` represents pieces of
    /// actor's state that are involved in the atomic execution.
    ///
    /// `input` is any data to associate with the returned input ID.
    ///
    /// If `lock` is set to `true` then the method automatically locks
    /// the supplied state; otherwise it just captures the state CIDs
    /// to check against when calling
    /// [`prepare_atomic_exec`](Self::prepare_atomic_exec). In that
    /// case, the caller is responsible for flushing the supplied
    /// lockable state to the blockstore.
    pub fn init_atomic_exec<'a, S, I>(
        &mut self,
        bs: &impl Blockstore,
        state: impl IntoIterator<Item = &'a mut S>,
        input: I,
        lock: bool,
    ) -> anyhow::Result<AtomicInputID>
    where
        S: LockableState + 'a,
        I: Serialize,
    {
        // Optionally lock the state and compute its CIDs
        let unlocked_state_cids = state.into_iter().try_fold(Vec::new(), |mut v, s| {
            if lock {
                s.lock()?;
            } else if !s.is_locked() {
                v.push(s.cid());
            }
            anyhow::Ok(v)
        })?;

        // Generate and register a new input ID
        let input = RawBytes::serialize(&input)?;
        let input_id = self.new_input_id(&unlocked_state_cids, &input);
        self.input_ids.modify(bs, |m| {
            let k = BytesKey::from(input_id.bytes());
            let v = m.set(
                k,
                AtomicInputEntry {
                    unlocked_state_cids,
                    input,
                },
            )?;
            assert!(v.is_none(), "input ID collision");
            Ok(())
        })?;

        Ok(input_id)
    }

    /// Retrieves the data associated with the specified input ID.
    pub fn atomic_input<I>(
        &self,
        bs: &impl Blockstore,
        input_id: &AtomicInputID,
    ) -> anyhow::Result<Option<I>>
    where
        I: DeserializeOwned,
    {
        let k = BytesKey::from(input_id.bytes());
        let input_ids = self.input_ids.load(bs)?;
        let input = input_ids
            .get(&k)?
            .map(|e| e.input.deserialize())
            .transpose()?;
        Ok(input)
    }

    /// Consumes and discards the supplied atomic execution input ID.
    ///
    /// This cancels the associated initiated instance of the atomic
    /// execution protocol.
    ///
    /// The supplied iterable collection `state` represents pieces of
    /// actor's state matching the one previously supplied to the
    /// corresponding invocation of
    /// [`init_atomic_exec`](Self::init_atomic_exec).
    ///
    /// Any locked piece of the state is automatically unlocked by the
    /// method.
    pub fn cancel_atomic_exec<'a, S>(
        &mut self,
        bs: &impl Blockstore,
        input_id: AtomicInputID,
        state: impl IntoIterator<Item = &'a mut S>,
    ) -> anyhow::Result<()>
    where
        S: LockableState + 'a,
    {
        // Consume own input ID and retrieve the associated data
        let k = BytesKey::from(input_id.bytes());
        self.input_ids.modify(bs, |m| {
            m.delete(&k)?
                .ok_or_else(|| anyhow::anyhow!("unexpected input ID"))
        })?;

        // Get the state and ensure it's unlocked
        for s in state {
            if s.is_locked() {
                s.unlock().unwrap();
            }
        }

        Ok(())
    }

    /// Consumes the supplied own atomic execution input ID and
    /// produces an atomic execution identifier.
    ///
    /// It returns a unique identifier of the atomic execution to be
    /// submitted to the coordinator actor in a cross-net message.
    ///
    /// Every executing actor should agree on the supplied input IDs
    /// `input_ids`, which should include the supplied `own_input_id`.
    ///
    /// The supplied iterable collection `state` represents pieces of
    /// actor's state matching the one previously supplied to the
    /// corresponding invocation of
    /// [`init_atomic_exec`](Self::init_atomic_exec).
    ///
    /// Any unlocked piece of the state is automatically locked by the
    /// method.
    ///
    /// `output` is any data to associate with the returned exec ID.
    pub fn prepare_atomic_exec<'a, S, O>(
        &mut self,
        bs: &impl Blockstore,
        own_input_id: &AtomicInputID,
        input_ids: &[(IPCAddress, AtomicInputID)],
        state: impl IntoIterator<Item = &'a mut S>,
        output: O,
    ) -> anyhow::Result<AtomicExecID>
    where
        S: 'a + LockableState,
        O: Serialize,
    {
        // Consume own input ID and retrieve the associated data
        let AtomicInputEntry {
            unlocked_state_cids,
            input: _,
        } = self.input_ids.modify(bs, |m| {
            let k = BytesKey::from(own_input_id.bytes());
            let (_, v) = m
                .delete(&k)?
                .ok_or_else(|| anyhow::anyhow!("unexpected own input ID"))?;
            Ok(v)
        })?;

        // Check that the unlocked state has not changed and lock it
        let unlocked_state_cid_iter = state.into_iter().filter(|s| !s.is_locked()).map(|s| {
            let cid = s.cid();
            s.lock().unwrap();
            cid
        });
        if !unlocked_state_cid_iter.eq(unlocked_state_cids) {
            anyhow::bail!("state CID mismatch");
        }

        // Compute the atomic execution ID and store the output
        let exec_id = Self::compute_exec_id(input_ids);
        self.exec_ids.modify(bs, |m| {
            let k = BytesKey::from(exec_id.bytes());
            let output = RawBytes::serialize(output)?;
            let v = m.set(k, AtomicOutputEntry { output })?;
            assert!(v.is_none(), "exec ID collision");
            Ok(())
        })?;

        Ok(exec_id)
    }

    /// Retrieves the data associated with the specified exec ID.
    pub fn atomic_output<O>(
        &self,
        bs: &impl Blockstore,
        exec_id: &AtomicExecID,
    ) -> anyhow::Result<Option<O>>
    where
        O: DeserializeOwned,
    {
        let k = BytesKey::from(exec_id.bytes());
        let exec_ids = self.exec_ids.load(bs)?;
        let output = exec_ids
            .get(&k)?
            .map(|e| e.output.deserialize())
            .transpose()?;
        Ok(output)
    }

    /// Consumes the supplied atomic exec ID and unlocks the state
    /// locked for the atomic execution.
    ///
    /// The supplied iterable collection `state` represents pieces of
    /// actor's state matching the one previously supplied to the
    /// corresponding invocation of
    /// [`init_atomic_exec`](Self::init_atomic_exec).
    ///
    /// The state is automatically unlocked by the method.
    pub fn finish_atomic_exec<'a, S>(
        &mut self,
        bs: &impl Blockstore,
        exec_id: AtomicExecID,
        state: impl IntoIterator<Item = &'a mut S>,
    ) -> anyhow::Result<()>
    where
        S: 'a + LockableState,
    {
        // Consume the atomic exec ID
        self.exec_ids.modify(bs, |m| {
            let k = BytesKey::from(exec_id.bytes());
            let (_, v) = m
                .delete(&k)?
                .ok_or_else(|| anyhow::anyhow!("unexpected atomic exec ID"))?;
            Ok(v)
        })?;

        // Get the output and the state; unlock the state
        for s in state {
            s.unlock().unwrap()
        }

        Ok(())
    }

    fn new_input_id<'a>(
        &mut self,
        unlocked_state_cids: impl IntoIterator<Item = &'a Cid>,
        input: &RawBytes,
    ) -> AtomicInputID {
        let nonce = self.nonce;
        self.nonce += 1; // ensure uniqueness of the input ID

        let mut h = Blake2b256::default();
        h.update(&RawBytes::serialize(nonce).unwrap());
        for s in unlocked_state_cids {
            h.update(&RawBytes::serialize(s).unwrap());
        }
        h.update(input);
        Vec::from(h.finalize()).into()
    }

    pub fn compute_exec_id(input_ids: &[(IPCAddress, AtomicInputID)]) -> AtomicExecID {
        let mut h = Blake2b256::default();
        h.update(&RawBytes::serialize(input_ids).unwrap());
        Vec::from(h.finalize()).into()
    }
}
