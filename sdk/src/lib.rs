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
