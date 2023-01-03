use anyhow::anyhow;
use cid::Cid;
use fil_actors_runtime::runtime::fvm::resolve_secp_bls;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{actor_error, ActorError};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::{Cbor, RawBytes};
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::bigint::Zero;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_gateway::{Checkpoint, SubnetID, DEFAULT_CHECKPOINT_PERIOD, MIN_COLLATERAL_AMOUNT};
use lazy_static::lazy_static;
use num::rational::Ratio;
use num::BigInt;
use primitives::{TCid, THamt};
use serde::{Deserialize, Serialize};

use crate::types::*;

lazy_static! {
    static ref VOTING_THRESHOLD: Ratio<BigInt> = Ratio::new(
        TokenAmount::from_atto(2).atto().clone(),
        TokenAmount::from_atto(3).atto().clone()
    );
}

/// The state object.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    pub name: String,
    pub parent_id: SubnetID,
    pub ipc_gateway_addr: Address,
    pub consensus: ConsensusType,
    pub min_validator_stake: TokenAmount,
    pub total_stake: TokenAmount,
    pub stake: TCid<THamt<Cid, TokenAmount>>,
    pub status: Status,
    pub genesis: Vec<u8>,
    pub finality_threshold: ChainEpoch,
    pub check_period: ChainEpoch,
    pub checkpoints: TCid<THamt<Cid, Checkpoint>>,
    pub window_checks: TCid<THamt<Cid, Votes>>,
    pub validator_set: Vec<Validator>,
    pub min_validators: u64,
}

impl Cbor for State {}

/// We should probably have a derive macro to mark an object as a state object,
/// and have load and save methods automatically generated for them as part of a
/// StateObject trait (i.e. impl StateObject for State).
impl State {
    pub fn new<BS: Blockstore>(store: &BS, params: ConstructParams) -> anyhow::Result<State> {
        let min_stake = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);

        let state = State {
            name: params.name,
            parent_id: params.parent,
            ipc_gateway_addr: Address::new_id(params.ipc_gateway_addr),
            consensus: params.consensus,
            total_stake: TokenAmount::zero(),
            min_validator_stake: if params.min_validator_stake < min_stake {
                min_stake
            } else {
                params.min_validator_stake
            },
            min_validators: params.min_validators,
            finality_threshold: params.finality_threshold,
            check_period: if params.check_period < DEFAULT_CHECKPOINT_PERIOD {
                DEFAULT_CHECKPOINT_PERIOD
            } else {
                params.check_period
            },
            genesis: params.genesis,
            status: Status::Instantiated,
            checkpoints: TCid::new_hamt(store)?,
            stake: TCid::new_hamt(store)?,
            window_checks: TCid::new_hamt(store)?,
            validator_set: Vec::new(),
        };

        Ok(state)
    }

    pub fn get_votes<BS: Blockstore>(
        &self,
        store: &BS,
        cid: &Cid,
    ) -> Result<Option<Votes>, ActorError> {
        let hamt = self
            .window_checks
            .load(store)
            .map_err(|_| actor_error!(illegal_state, "cannot load votes hamt"))?;
        let votes = hamt
            .get(&BytesKey::from(cid.to_bytes()))
            .map_err(|_| actor_error!(illegal_state, "cannot read votes"))?;
        Ok(votes.cloned())
    }

    pub fn remove_votes<BS: Blockstore>(
        &mut self,
        store: &BS,
        cid: &Cid,
    ) -> Result<(), ActorError> {
        self.window_checks
            .modify(store, |hamt| {
                hamt.delete(&BytesKey::from(cid.to_bytes()))
                    .map_err(|_| actor_error!(illegal_state, "cannot remove votes from hamt"))?;
                Ok(true)
            })
            .map_err(|_| actor_error!(illegal_state, "cannot modify window checks"))?;

        Ok(())
    }

    pub fn set_votes<BS: Blockstore>(
        &mut self,
        store: &BS,
        cid: &Cid,
        votes: Votes,
    ) -> Result<(), ActorError> {
        self.window_checks
            .modify(store, |hamt| {
                hamt.set(BytesKey::from(cid.to_bytes()), votes)
                    .map_err(|_| actor_error!(illegal_state, "cannot set votes in hamt"))?;
                Ok(true)
            })
            .map_err(|_| actor_error!(illegal_state, "cannot modify window checks"))?;
        Ok(())
    }

    /// Get the stake of an address.
    pub fn get_stake<BS: Blockstore>(
        &self,
        store: &BS,
        addr: &Address,
    ) -> anyhow::Result<Option<TokenAmount>> {
        let hamt = self.stake.load(store)?;
        let amount = hamt.get(&BytesKey::from(addr.to_bytes()))?;
        Ok(amount.cloned())
    }

    /// Adds stake from a validator
    pub(crate) fn add_stake<BS: Blockstore>(
        &mut self,
        store: &BS,
        addr: &Address,
        net_addr: &str,
        amount: &TokenAmount,
    ) -> anyhow::Result<()> {
        // update miner stake
        self.stake.modify(store, |hamt| {
            // Note that when trying to get stake, if it is not found in the
            // hamt, that means it's the first time adding stake and we just
            // give default stake amount 0.
            let key = BytesKey::from(addr.to_bytes());
            let stake = hamt.get(&key)?.unwrap_or(&TokenAmount::zero()).clone();
            let updated_stake = stake + amount;

            hamt.set(key, updated_stake.clone())?;

            // update total collateral
            self.total_stake += amount;

            // check if the miner has collateral to become a validator
            if updated_stake >= self.min_validator_stake
                && (self.consensus != ConsensusType::Delegated || self.validator_set.is_empty())
            {
                self.validator_set.push(Validator {
                    addr: *addr,
                    net_addr: String::from(net_addr),
                });
            }

            Ok(true)
        })?;

        Ok(())
    }

    pub fn rm_stake<BS: Blockstore>(
        &mut self,
        store: &BS,
        addr: &Address,
        amount: &TokenAmount,
    ) -> anyhow::Result<()> {
        // update miner stake
        self.stake.modify(store, |hamt| {
            // Note that when trying to get stake, if it is not found in the
            // hamt, that means it's the first time adding stake and we just
            // give default stake amount 0.
            let key = BytesKey::from(addr.to_bytes());
            let mut stake = hamt.get(&key)?.unwrap_or(&TokenAmount::zero()).clone();
            stake = stake.div_floor(LEAVING_COEFF);

            if stake.lt(amount) {
                return Err(anyhow!(format!(
                    "address not enough stake to withdraw: {:?}",
                    addr
                )));
            }

            hamt.set(key, stake - amount)?;

            // update total collateral
            self.total_stake -= amount;

            // remove miner from list of validators
            // NOTE: We currently only support full recovery of collateral.
            // And additional check will be needed here if we consider part-recoveries.
            self.validator_set.retain(|x| x.addr != *addr);

            Ok(true)
        })?;

        Ok(())
    }

    pub fn has_majority_vote<BS: Blockstore>(
        &self,
        store: &BS,
        votes: &Votes,
    ) -> Result<bool, ActorError> {
        let mut sum = TokenAmount::zero();
        for v in &votes.validators {
            let stake = self
                .get_stake(store, v)
                .map_err(|_| actor_error!(illegal_state, "cannot load stake from hamt"))?;
            sum += stake.unwrap_or_else(TokenAmount::zero);
        }
        let ftotal = Ratio::from_integer(self.total_stake.atto().clone());
        Ok(Ratio::from_integer(sum.atto().clone()) / ftotal >= *VOTING_THRESHOLD)
    }

    pub fn mutate_state(&mut self) {
        match self.status {
            Status::Instantiated => {
                if self.total_stake >= TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT) {
                    self.status = Status::Active
                }
            }
            Status::Active => {
                if self.total_stake < TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT) {
                    self.status = Status::Inactive
                }
            }
            Status::Inactive => {
                if self.total_stake >= TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT) {
                    self.status = Status::Active
                }
            }
            // if no total_stake and current_balance left (except if we are testing where the funds
            // are never leaving the actor)
            Status::Terminating => {
                if self.total_stake == TokenAmount::zero() {
                    self.status = Status::Killed
                }
            }
            _ => {}
        }
    }

    fn get_checkpoint<BS: Blockstore>(
        &self,
        store: &BS,
        epoch: &ChainEpoch,
    ) -> anyhow::Result<Option<Checkpoint>> {
        let hamt = self
            .checkpoints
            .load(store)
            .map_err(|e| anyhow!("failed to load checkpoints: {}", e))?;
        let checkpoint = hamt
            .get(&BytesKey::from(epoch.to_ne_bytes().to_vec()))
            .map_err(|e| anyhow!("failed to get checkpoint for id {}: {:?}", epoch, e))?
            .cloned();
        Ok(checkpoint)
    }

    pub fn is_validator(&self, addr: &Address) -> bool {
        self.validator_set.iter().any(|x| x.addr == *addr)
    }

    /// Do not call this function in transaction
    pub fn verify_checkpoint<BS, RT>(&self, rt: &mut RT, ch: &Checkpoint) -> anyhow::Result<()>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        // check that subnet is active
        if self.status != Status::Active {
            return Err(anyhow!(
                "submitting checkpoints is not allowed while subnet is not active"
            ));
        }

        // check that a checkpoint for the epoch doesn't exist already.
        if self.get_checkpoint(rt.store(), &ch.epoch())?.is_some() {
            return Err(anyhow!("cannot submit checkpoint for epoch"));
        };

        // check that the epoch is correct
        if ch.epoch() % self.check_period != 0 {
            return Err(anyhow!(
                "epoch in checkpoint doesn't correspond with a signing window"
            ));
        }

        // check the source is correct
        if *ch.source() != SubnetID::new(&self.parent_id, rt.message().receiver()) {
            return Err(anyhow!("submitting checkpoint with the wrong source"));
        }

        // check previous checkpoint
        if self.prev_checkpoint_cid(rt.store(), &ch.epoch())? != ch.prev_check().cid() {
            return Err(anyhow!(
                "previous checkpoint not consistent with previously committed"
            ));
        }

        // check signature
        let caller = rt.message().caller();
        let pkey = resolve_secp_bls(rt, &caller)?;

        rt.verify_signature(
            &RawBytes::deserialize(&ch.signature().clone().into())?,
            &pkey,
            &ch.cid().to_bytes(),
        )?;

        Ok(())
    }

    fn prev_checkpoint_cid<BS: Blockstore>(
        &self,
        store: &BS,
        epoch: &ChainEpoch,
    ) -> anyhow::Result<Cid> {
        let mut epoch = epoch - self.check_period;
        while epoch >= 0 {
            match self.get_checkpoint(store, &epoch)? {
                Some(ch) => return Ok(ch.cid()),
                None => {
                    epoch -= self.check_period;
                }
            }
        }
        Ok(Cid::default())
    }

    pub fn flush_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        ch: &Checkpoint,
    ) -> anyhow::Result<()> {
        let epoch = ch.epoch();
        self.checkpoints.modify(store, |hamt| {
            hamt.set(BytesKey::from(epoch.to_ne_bytes().to_vec()), ch.clone())
                .map_err(|e| anyhow!("failed to set checkpoint: {:?}", e))?;
            Ok(true)
        })?;
        Ok(())
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            name: String::new(),
            parent_id: SubnetID::default(),
            ipc_gateway_addr: Address::new_id(0),
            consensus: ConsensusType::Delegated,
            min_validator_stake: TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            total_stake: TokenAmount::zero(),
            finality_threshold: 5,
            check_period: 10,
            genesis: Vec::new(),
            status: Status::Instantiated,
            checkpoints: TCid::default(),
            stake: TCid::default(),
            window_checks: TCid::default(),
            validator_set: Vec::new(),
            min_validators: 0,
        }
    }
}
