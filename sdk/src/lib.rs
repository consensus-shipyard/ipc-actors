use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;

pub mod address;
pub mod error;
pub mod subnet_id;

pub mod account {
    /// Public key account actor method.
    pub const PUBKEY_ADDRESS_METHOD: u64 = 2;
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct Validator {
    pub addr: Address,
    pub net_addr: String,
    // voting power for the validator determined by its stake in the
    // network.
    pub weight: TokenAmount,
}

#[derive(Clone, Default, Debug, Serialize_tuple, Deserialize_tuple, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    // sequence number that uniquely identifies a validator set
    configuration_number: u64,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>, configuration_number: u64) -> Self {
        Self {
            validators,
            configuration_number,
        }
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
