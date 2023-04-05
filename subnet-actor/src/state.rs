use anyhow::anyhow;
use cid::Cid;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{actor_error, ActorError};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::serde_bytes;
use fvm_ipld_hamt::BytesKey;
use fvm_shared::address::Address;
use fvm_shared::bigint::Zero;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_actor_common::vote::Voting;
use ipc_gateway::{
    Checkpoint, SubnetID, CHECKPOINT_GENESIS_CID, DEFAULT_CHECKPOINT_PERIOD, MIN_COLLATERAL_AMOUNT,
};
use ipc_sdk::epoch_key;
use ipc_sdk::{Validator, ValidatorSet};
use lazy_static::lazy_static;
use num::rational::Ratio;
use num::BigInt;
use primitives::{TCid, THamt};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::types::*;

lazy_static! {
    static ref VOTING_THRESHOLD: Ratio<BigInt> = Ratio::new(
        TokenAmount::from_atto(2).atto().clone(),
        TokenAmount::from_atto(3).atto().clone()
    );
}

/// The state object.
#[derive(Serialize_tuple, Deserialize_tuple, Clone, Debug)]
pub struct State {
    pub name: String,
    /// The parent id of the subnet actor, it should be the same as the
    /// actor's gateway's state.network_name
    pub parent_id: SubnetID,
    pub ipc_gateway_addr: Address,
    pub consensus: ConsensusType,
    pub min_validator_stake: TokenAmount,
    pub total_stake: TokenAmount,
    pub stake: TCid<THamt<Cid, TokenAmount>>,
    pub status: Status,
    #[serde(with = "serde_bytes")]
    pub genesis: Vec<u8>,
    pub finality_threshold: ChainEpoch,

    // duplicated definition for easier data access in client applications
    pub check_period: ChainEpoch,
    pub genesis_epoch: ChainEpoch,

    // FIXME: Consider making checkpoints a HAMT instead of an AMT so we use
    // the AMT index instead of and epoch k for object indexing.
    pub committed_checkpoints: TCid<THamt<ChainEpoch, Checkpoint>>,
    pub validator_set: ValidatorSet,
    pub min_validators: u64,
    pub previous_executed_checkpoint_cid: Cid,
    pub epoch_checkpoint_voting: Voting<Checkpoint>,
}

/// We should probably have a derive macro to mark an object as a state object,
/// and have load and save methods automatically generated for them as part of a
/// StateObject trait (i.e. impl StateObject for State).
impl State {
    pub fn new<BS: Blockstore>(
        store: &BS,
        params: ConstructParams,
        current_epoch: ChainEpoch,
    ) -> anyhow::Result<State> {
        let min_stake = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        let check_period = if params.check_period < DEFAULT_CHECKPOINT_PERIOD {
            DEFAULT_CHECKPOINT_PERIOD
        } else {
            params.check_period
        };
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
            check_period,
            committed_checkpoints: TCid::new_hamt(store)?,
            genesis: params.genesis,
            status: Status::Instantiated,
            stake: TCid::new_hamt(store)?,
            validator_set: ValidatorSet::default(),
            genesis_epoch: current_epoch,
            previous_executed_checkpoint_cid: CHECKPOINT_GENESIS_CID.clone(),
            epoch_checkpoint_voting: Voting::<Checkpoint>::new_with_ratio(
                store,
                current_epoch,
                check_period,
                1,
                2,
            )?,
        };

        Ok(state)
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
            if updated_stake >= self.min_validator_stake {
                // check if it is already a validator
                if !self
                    .validator_set
                    .validators()
                    .iter()
                    .any(|x| x.addr == *addr)
                    && (self.consensus != ConsensusType::Delegated
                        || self.validator_set.validators().is_empty())
                {
                    self.validator_set.push(Validator {
                        addr: *addr,
                        net_addr: String::from(net_addr),
                        weight: updated_stake,
                    });
                } else {
                    // update the weight if it is already a validator
                    self.validator_set.update_weight(addr, &updated_stake)
                }
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
    ) -> anyhow::Result<TokenAmount> {
        // update miner stake
        self.stake.modify(store, |hamt| {
            let key = BytesKey::from(addr.to_bytes());
            let stake = hamt.get(&key)?.unwrap_or(&TokenAmount::zero()).clone();
            // return amount corrected by an optional leaving coefficient
            let ret_amount = amount.clone().div_floor(LEAVING_COEFF);

            if stake.lt(&ret_amount) {
                return Err(anyhow!(format!(
                    "address not enough stake to withdraw: {:?}",
                    addr
                )));
            }

            // set updated stake for user
            hamt.set(key, stake - amount)?;

            // update total collateral in subnet actor
            self.total_stake -= &ret_amount;

            // remove miner from list of validators
            // NOTE: We currently only support full recovery of collateral.
            // And additional check will be needed here if we consider part-recoveries.
            self.validator_set.rm(addr);

            Ok(ret_amount)
        })
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

    pub fn is_validator(&self, addr: &Address) -> bool {
        self.validator_set
            .validators()
            .iter()
            .any(|x| x.addr == *addr)
    }

    /// Do not call this function in transaction
    pub fn verify_checkpoint(&self, rt: &mut impl Runtime, ch: &Checkpoint) -> anyhow::Result<()> {
        // check that subnet is active
        if self.status != Status::Active {
            return Err(anyhow!(
                "submitting checkpoints is not allowed while subnet is not active"
            ));
        }

        // check the source is correct
        if *ch.source() != SubnetID::new_from_parent(&self.parent_id, rt.message().receiver()) {
            return Err(anyhow!("submitting checkpoint with the wrong source"));
        }

        // the epoch being submitted is the next executable epoch, we perform a check to ensure
        // the checkpoints are chained. This is an early termination check to ensure the checkpoints
        // are actually chained.
        if self
            .epoch_checkpoint_voting
            .is_next_executable_epoch(ch.epoch())
        {
            if self.previous_executed_checkpoint_cid != ch.prev_check().cid() {
                return Err(anyhow!("checkpoint not chained"));
            }
        }

        // check signature
        // NOTE: In the current implementation the validator is the one sending the message
        // including the checkpoint, so there is no need for a explicit signature in checkpoints,
        // they are implicitly signed by signing the submission message.
        // let caller = rt.message().caller();
        // let pkey = resolve_secp_bls(rt, &caller)?;

        // rt.verify_signature(
        //     &RawBytes::deserialize(&ch.signature().clone().into())?,
        //     &pkey,
        //     &ch.cid().to_bytes(),
        // )?;

        Ok(())
    }

    /// Ensures the checkpoints are chained, aka checkpoint.prev_check() should be the previous executed
    /// checkpoint cid. If not, should abort the current checkpoint.
    pub fn ensure_checkpoint_chained(
        &mut self,
        store: &impl Blockstore,
        ch: &Checkpoint,
    ) -> anyhow::Result<bool> {
        Ok(
            if self.previous_executed_checkpoint_cid != ch.prev_check().cid() {
                self.epoch_checkpoint_voting
                    .abort_epoch(store, ch.data.epoch)?;
                false
            } else {
                true
            },
        )
    }

    pub fn flush_checkpoint<BS: Blockstore>(
        &mut self,
        store: &BS,
        ch: &Checkpoint,
    ) -> anyhow::Result<()> {
        let epoch = ch.epoch();
        self.committed_checkpoints.modify(store, |hamt| {
            hamt.set(epoch_key(epoch), ch.clone())
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
            check_period: 0,
            genesis: Vec::new(),
            status: Status::Instantiated,
            stake: TCid::default(),
            validator_set: ValidatorSet::default(),
            min_validators: 0,
            genesis_epoch: 0,
            previous_executed_checkpoint_cid: CHECKPOINT_GENESIS_CID.clone(),
            epoch_checkpoint_voting: Voting {
                genesis_epoch: 0,
                submission_period: 0,
                last_voting_executed_epoch: 0,
                executable_epoch_queue: None,
                epoch_vote_submissions: TCid::default(),
                threshold_ratio: (2, 3),
            },
            committed_checkpoints: TCid::default(),
        }
    }
}
