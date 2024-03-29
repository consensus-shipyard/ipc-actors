use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::repr::*;
use fvm_ipld_encoding::serde_bytes;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use ipc_gateway::SubnetID;

/// ID used in the builtin-actors bundle manifest
pub const MANIFEST_ID: &str = "ipc_subnet_actor";

/// Optional leaving coefficient to penalize
/// validators leaving the subnet.
// It should be a float between 0-1 but
// setting it to 1_u64 for now for convenience.
// This will change once we figure out the econ model.
pub const LEAVING_COEFF: u64 = 1;
pub const TESTING_ID: u64 = 339;

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct Validator {
    pub addr: Address,
    // TODO: We currently support a single validator address for validators,
    // in the future we should consider supporting more than one multiaddr.
    pub net_addr: String,
    // voting power for the validator determined by its stake in the
    // network.
    pub weight: TokenAmount,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, Default, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    // sequence number that uniquely identifies a validator set
    configuration_number: u64,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validators(&self) -> &Vec<Validator> {
        &self.validators
    }

    pub fn validators_mut(&mut self) -> &mut Vec<Validator> {
        &mut self.validators
    }

    pub fn config_number(&self) -> u64 {
        self.configuration_number
    }

    /// Push a new validator to the validator set.
    pub fn push(&mut self, val: Validator) {
        self.validators.push(val);
        // update the config_number with every update
        // we allow config_number to overflow if that scenario ever comes.
        self.configuration_number += 1;
    }

    /// Remove a validator from validator set by address
    pub fn rm(&mut self, val: &Address) {
        self.validators.retain(|x| x.addr != *val);
        // update the config_number with every update
        // we allow config_number to overflow if that scenario ever comes.
        self.configuration_number += 1;
    }

    pub fn update_weight(&mut self, val: &Address, weight: &TokenAmount) {
        self.validators_mut()
            .iter_mut()
            .filter(|x| x.addr == *val)
            .for_each(|x| x.weight = weight.clone());

        self.configuration_number += 1;
    }
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct Votes {
    pub validators: Vec<Address>,
}

/// Consensus types supported by hierarchical consensus
#[derive(PartialEq, Eq, Clone, Copy, Debug, Deserialize_repr, Serialize_repr)]
#[repr(u64)]
pub enum ConsensusType {
    Mir,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Deserialize_repr, Serialize_repr)]
#[repr(i32)]
pub enum Status {
    Instantiated,
    Active,
    Inactive,
    Terminating,
    Killed,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct ConstructParams {
    pub parent: SubnetID,
    pub name: String,
    pub ipc_gateway_addr: Address,
    pub consensus: ConsensusType,
    pub min_validator_stake: TokenAmount,
    pub min_validators: u64,
    pub bottomup_check_period: ChainEpoch,
    pub topdown_check_period: ChainEpoch,
    // genesis is no longer generated by the actor
    // on-the-fly, but it is accepted as a construct
    // param
    #[serde(with = "serde_bytes")]
    pub genesis: Vec<u8>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct JoinParams {
    pub validator_net_addr: String,
}

pub(crate) struct CrossActorPayload {
    pub to: Address,
    pub method: MethodNum,
    pub params: Option<IpldBlock>,
    pub value: TokenAmount,
}

impl CrossActorPayload {
    pub fn new(
        to: Address,
        method: MethodNum,
        params: Option<IpldBlock>,
        value: TokenAmount,
    ) -> Self {
        Self {
            to,
            method,
            params,
            value,
        }
    }
}
