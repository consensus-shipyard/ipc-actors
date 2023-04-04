use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::{econ::TokenAmount, address::Address};
use fil_actors_runtime::fvm_ipld_hamt::BytesKey;
use fvm_shared::{
    address::{set_current_network, Network},
    clock::ChainEpoch,
};
use integer_encoding::VarInt;
use num_traits::cast::FromPrimitive;

pub mod address;
pub mod error;
pub mod subnet_id;

/// Sets the type of network from an environmental variable.
/// This is key to set the right network prefixes on string
/// representation of addresses.
pub fn set_network_from_env() {
    let network_raw: u8 = std::env::var("LOTUS_NETWORK")
        // default to testnet
        .unwrap_or_else(|_| String::from("1"))
        .parse()
        .unwrap();
    let network = Network::from_u8(network_raw).unwrap();
    set_current_network(network);
}

/// Encodes the a ChainEpoch as a varInt for its use
/// as a key of a HAMT. This serialization has been
/// tested to be compatible with its go counter-part
/// in github.com/consensus-shipyard/go-ipc-types
pub fn epoch_key(k: ChainEpoch) -> BytesKey {
    let bz = k.encode_var_vec();
    bz.into()
}

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
