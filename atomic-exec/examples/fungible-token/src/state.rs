use fvm_actors_runtime::Map;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_hamt::BytesKey;
use fvm_primitives::{TCid, THamt};
use fvm_shared::{address::Address, bigint::Zero, econ::TokenAmount, ActorID, HAMT_BIT_WIDTH};
use integer_encoding::VarInt;
use ipc_atomic_execution_primitives::{
    AtomicExecID, AtomicExecRegistry, AtomicInputID, AtomicInputState,
};
use ipc_gateway::IPCAddress;
use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

pub type AccountState = AtomicInputState<TokenAmount>;

/// Represents the state of the actor.
#[derive(Serialize, Deserialize)]
pub struct State {
    /// Address of the IPC gateway actor.
    ipc_gateway: Address,
    /// IPC address of the actor.
    ipc_address: IPCAddress,
    /// Name of the token.
    name: String,
    /// Ticker symbol of the token.
    symbol: String,
    /// Total amount of the token in existence.
    total: TokenAmount,
    /// Balance table.
    balances: TCid<THamt<ActorID, AccountState>>,
    /// Atomic execution registry.
    atomic_registry: AtomicExecRegistry,
}
impl Cbor for State {}

impl State {
    /// Creates a new actor state instance.
    pub fn new(
        bs: &impl Blockstore,
        ipc_gateway: Address,
        ipc_address: IPCAddress,
        name: String,
        symbol: String,
        balances: impl IntoIterator<Item = (ActorID, TokenAmount)>,
    ) -> anyhow::Result<Self> {
        // Construct balance table HAMT, computing the total supply
        // and checking the initial balance table for duplicates.
        let mut total = TokenAmount::zero();
        let mut balance_map = fvm_actors_runtime::make_empty_map(bs, HAMT_BIT_WIDTH);
        for (a, b) in balances {
            total += &b;
            let k = BytesKey::from(a.encode_var_vec());
            if !balance_map.set_if_absent(k, AccountState::new(b))? {
                anyhow::bail!("duplicate balance for {}", a)
            }
        }

        Ok(Self {
            ipc_gateway,
            ipc_address,
            name,
            symbol,
            total,
            balances: TCid::from(balance_map.flush()?),
            atomic_registry: AtomicExecRegistry::new(bs)?,
        })
    }

    pub fn ipc_gateway(&self) -> Address {
        self.ipc_gateway
    }

    pub fn ipc_address(&self) -> &IPCAddress {
        &self.ipc_address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub fn total_supply(&self) -> &TokenAmount {
        &self.total
    }

    pub fn balance(&self, bs: &impl Blockstore, id: ActorID) -> anyhow::Result<TokenAmount> {
        Ok(self
            .balances
            .load(bs)?
            .get(&Self::account_key(id))?
            .map(|a| a.get().clone())
            .unwrap_or_default())
    }

    pub fn transfer(
        &mut self,
        bs: &impl Blockstore,
        from: ActorID,
        to: ActorID,
        amount: TokenAmount,
    ) -> anyhow::Result<(TokenAmount, TokenAmount)> {
        let mut balances = self.balances.load(bs)?;
        let res = Self::do_transfer(&mut balances, from, to, amount)?;
        self.balances.flush(balances)?;
        Ok(res)
    }

    /// Initializes an atomic transfer using the specified atomic
    /// execution coordinator actor.
    pub fn init_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        coordinator: IPCAddress,
        from: ActorID,
        to: ActorID,
        amount: TokenAmount,
    ) -> anyhow::Result<AtomicInputID> {
        // Get sender's balance state.
        let from_key = Self::account_key(from);
        let mut balances = self.balances.load(bs)?;
        let mut from_state = balances.get(&from_key)?.cloned().unwrap_or_default();

        if *from_state < amount {
            anyhow::bail!("insufficient balance");
        }

        // Register a new atomic execution, locking sender's balance.
        let input_id = self.atomic_registry.init_atomic_exec(
            bs,
            std::iter::once(&mut from_state),
            AtomicTransfer {
                coordinator,
                from,
                to,
                amount,
            },
            true, // lock the state
        )?;

        // Update and flush the balance table.
        balances.set(from_key, from_state)?;
        self.balances.flush(balances)?;

        Ok(input_id)
    }

    /// Cancels an initialized but not yet prepared atomic transfer.
    pub fn cancel_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        input_id: AtomicInputID,
    ) -> anyhow::Result<()> {
        // Get the parameters of the atomic transfer.
        let atomic_registry = &mut self.atomic_registry;
        let AtomicTransfer { from, .. } = atomic_registry
            .atomic_input(bs, &input_id)?
            .ok_or_else(|| anyhow::anyhow!("unexpected own input ID"))?;

        // Get sender's account state.
        let from_key = Self::account_key(from);
        let mut balances = self.balances.load(bs)?;
        let mut from_state = balances.get(&from_key)?.cloned().unwrap_or_default();

        // Cancel the atomic execution, unlocking sender's state.
        atomic_registry.cancel_atomic_exec(bs, input_id, std::iter::once(&mut from_state))?;

        // Update and flush the balance table.
        balances.set(from_key, from_state)?;
        self.balances.flush(balances)?;

        Ok(())
    }

    /// Prepares an initiated atomic transfer given atomic input IDs
    /// of all executing actors participating in the atomic execution.
    pub fn prep_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        input_ids: &[(IPCAddress, AtomicInputID)],
    ) -> anyhow::Result<(IPCAddress, AtomicExecID)> {
        let own_addr = self.ipc_address();
        let own_input_id = input_ids
            .iter()
            .find_map(|(a, i)| {
                if a == own_addr {
                    return Some(i);
                };
                None
            })
            .ok_or_else(|| anyhow::anyhow!("missing own input ID"))?;

        // Get the parameters of the atomic transfer.
        let atomic_registry = &mut self.atomic_registry;
        let input: AtomicTransfer = atomic_registry
            .atomic_input(bs, own_input_id)?
            .ok_or_else(|| anyhow::anyhow!("unexpected own input ID"))?;
        let from = input.from;
        let coordinator = input.coordinator.clone();

        // Get sender's account state.
        let from_key = Self::account_key(from);
        let mut balances = self.balances.load(bs)?;
        let mut from_state = balances.get(&from_key)?.cloned().unwrap_or_default();

        // Prepare the atomic execution, computing its atomic exec ID.
        let exec_id = atomic_registry.prepare_atomic_exec(
            bs,
            own_input_id,
            input_ids,
            std::iter::once(&mut from_state),
            input,
        )?;

        // Update and flush the balance table (just in case sender's
        // balance has not been locked before).
        balances.set(from_key, from_state)?;
        self.balances.flush(balances)?;

        Ok((coordinator, exec_id))
    }

    /// Returns the IPC address of the atomic execution coordinator.
    pub fn atomic_transfer_coordinator(
        &self,
        bs: &impl Blockstore,
        exec_id: &AtomicExecID,
    ) -> anyhow::Result<IPCAddress> {
        let output: AtomicTransfer = self
            .atomic_registry
            .atomic_output(bs, exec_id)?
            .ok_or_else(|| anyhow::anyhow!("unexpected exec ID"))?;
        Ok(output.coordinator)
    }

    /// Commits the atomic transfer.
    pub fn commit_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        coordinator: IPCAddress,
        exec_id: AtomicExecID,
    ) -> anyhow::Result<()> {
        self.finish_atomic_transfer(bs, coordinator, exec_id, true)
    }

    /// Rolls back the atomic transfer.
    pub fn rollback_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        coordinator: IPCAddress,
        exec_id: AtomicExecID,
    ) -> anyhow::Result<()> {
        self.finish_atomic_transfer(bs, coordinator, exec_id, false)
    }

    /// Completes the atomic transfer either committing or discarding
    /// its result.
    fn finish_atomic_transfer(
        &mut self,
        bs: &impl Blockstore,
        coordinator: IPCAddress,
        exec_id: AtomicExecID,
        commit: bool,
    ) -> anyhow::Result<()> {
        // Get the parameters of the atomic transfer.
        let atomic_registry = &mut self.atomic_registry;
        let AtomicTransfer {
            coordinator: orig_coordinator,
            from,
            to,
            amount,
        } = atomic_registry
            .atomic_output(bs, &exec_id)?
            .ok_or_else(|| anyhow::anyhow!("unexpected exec ID"))?;

        // Check if the atomic execution coordinator matches.
        if coordinator != orig_coordinator {
            anyhow::bail!("unexpected coordinator actor address");
        }

        // Get sender's account state.
        let from_key = Self::account_key(from);
        let mut balances = self.balances.load(bs)?;
        let mut from_state = balances.get(&from_key)?.cloned().unwrap_or_default();

        // Complete the atomic execution, unlocking sender's balance.
        atomic_registry.finish_atomic_exec(bs, exec_id, std::iter::once(&mut from_state))?;

        // Update and flush the balance table.
        balances.set(from_key, from_state)?;
        if commit {
            Self::do_transfer(&mut balances, from, to, amount)?;
        }
        self.balances.flush(balances)?;

        Ok(())
    }

    // Perform a transfer in a balance table.
    fn do_transfer(
        balances: &mut Map<impl Blockstore, AccountState>,
        from: ActorID,
        to: ActorID,
        amount: TokenAmount,
    ) -> anyhow::Result<(TokenAmount, TokenAmount)> {
        // Get sender's account state.
        let from_key = Self::account_key(from);
        let mut from_state = balances.get(&from_key)?.cloned().unwrap_or_default();

        // Get recipient's account state.
        let to_key = Self::account_key(to);
        let mut to_state = balances.get(&to_key)?.cloned().unwrap_or_default();

        // Check if sender has enough tokens.
        if *from_state < amount {
            anyhow::bail!("insufficient balance");
        }

        // Debit sender's balance state; fail if locked.
        from_state.modify(|b| {
            *b -= &amount;
            Ok(())
        })?;

        // Credit recipient's balance state; fail if locked.
        // TODO: No need to fail if locked; find a way to optimize.
        to_state.modify(|b| {
            *b += &amount;
            Ok(())
        })?;

        // Update sender's balance state.
        let from_balance = from_state.get().clone();
        balances.set(from_key, from_state)?;

        // Update recipient's balance state.
        let to_balance = to_state.get().clone();
        balances.set(to_key, to_state)?;

        Ok((from_balance, to_balance))
    }

    fn account_key(id: ActorID) -> BytesKey {
        BytesKey::from(id.encode_var_vec())
    }
}

#[derive(Serialize_tuple, Deserialize_tuple)]
struct AtomicTransfer {
    coordinator: IPCAddress,
    from: ActorID,
    to: ActorID,
    amount: TokenAmount,
}
