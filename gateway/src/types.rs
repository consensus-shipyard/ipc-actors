use anyhow::anyhow;
use cid::multihash::Code;
use cid::{multihash, Cid};
use fil_actors_runtime::runtime::fvm::{equal_account_id, resolve_secp_bls};
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{cbor, ActorError, Array};
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::{RawBytes, DAG_CBOR};
use fvm_shared::address::{Address, Protocol};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::cross::CrossMsg;
use ipc_sdk::subnet_id::SubnetID;
use multihash::MultihashDigest;
use primitives::CodeType;
use std::cmp::Ordering;

/// ID used in the builtin-actors bundle manifest
pub const MANIFEST_ID: &str = "ipc_gateway";

pub const CROSSMSG_AMT_BITWIDTH: u32 = 3;
pub const DEFAULT_CHECKPOINT_PERIOD: ChainEpoch = 10;
pub const MIN_COLLATERAL_AMOUNT: u64 = 10_u64.pow(18);

pub const SUBNET_ACTOR_REWARD_METHOD: u64 = frc42_dispatch::method_hash!("Reward");

pub type CrossMsgArray<'bs, BS> = Array<'bs, CrossMsg, BS>;

/// The executable message trait
pub trait ExecutableMessage {
    /// Get the nonce of the message
    fn nonce(&self) -> u64;
}

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub network_name: String,
    pub bottomup_check_period: ChainEpoch,
    pub topdown_check_period: ChainEpoch,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct AmountParams {
    pub value: TokenAmount,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct FundParams {
    pub subnet: SubnetID,
    pub to: Address,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct ReleaseParams {
    pub to: Address,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct CrossMsgParams {
    pub cross_msg: CrossMsg,
    pub destination: SubnetID,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct ApplyMsgParams {
    pub cross_msg: CrossMsg,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct PropagateParams {
    /// The postbox message cid
    pub postbox_cid: Cid,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct InitGenesisEpoch {
    pub genesis_epoch: ChainEpoch,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct WhitelistPropagatorParams {
    /// The postbox message cid
    pub postbox_cid: Cid,
    /// The owners to add
    pub to_add: Vec<Address>,
}

/// The item to store in the `State::postbox`
#[derive(Serialize_tuple, Deserialize_tuple, PartialEq, Eq, Clone, Debug)]
pub struct PostBoxItem {
    pub cross_msg: CrossMsg,
    pub owners: Option<Vec<Address>>,
}

// The implementation does not matter, we just need to extract the cid
impl CodeType for PostBoxItem {
    fn code() -> Code {
        Code::Blake2b256
    }
}

/// Resolves the from and to to the higher-level cross-net
/// ammenable address
pub(crate) fn resolved_from_to(
    rt: &mut impl Runtime,
    from: &Address,
    to: &Address,
) -> Result<(Address, Address), ActorError> {
    let mut from_sig_addr = *from;
    let mut to_sig_addr = *to;
    let mut resolved = false;

    if to.protocol() != Protocol::Delegated {
        to_sig_addr = resolve_secp_bls(rt, &to_sig_addr)?;
        resolved = true;
    }

    // Check if they are equal to save ourselves a resolution
    if resolved {
        if !equal_account_id(rt, &from_sig_addr, to) {
            from_sig_addr = resolve_secp_bls(rt, &from_sig_addr)?;
        } else {
            from_sig_addr = to_sig_addr;
        }
    } else if from.protocol() != Protocol::Delegated {
        from_sig_addr = resolve_secp_bls(rt, &from_sig_addr)?;
    }

    Ok((from_sig_addr, to_sig_addr))
}

const POSTBOX_ITEM_DESCRIPTION: &str = "postbox";

impl PostBoxItem {
    pub fn new(cross_msg: CrossMsg, owners: Option<Vec<Address>>) -> Self {
        Self { cross_msg, owners }
    }

    pub fn serialize_with_cid(&self) -> Result<(Cid, Vec<u8>), ActorError> {
        let bytes = cbor::serialize(&self, POSTBOX_ITEM_DESCRIPTION)?;
        let cid = Cid::new_v1(DAG_CBOR, Code::Blake2b256.digest(bytes.bytes()));
        Ok((cid, bytes.to_vec()))
    }

    pub fn deserialize(bytes: Vec<u8>) -> Result<PostBoxItem, ActorError> {
        cbor::deserialize(&RawBytes::from(bytes), POSTBOX_ITEM_DESCRIPTION)
    }
}

pub(crate) fn ensure_message_sorted<E: ExecutableMessage>(messages: &[E]) -> anyhow::Result<()> {
    // check top down msgs
    for i in 1..messages.len() {
        match messages[i - 1].nonce().cmp(&messages[i].nonce()) {
            Ordering::Less => {}
            Ordering::Equal => return Err(anyhow!("top down messages not distinct")),
            Ordering::Greater => return Err(anyhow!("top down messages not sorted")),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ConstructorParams;
    use fvm_ipld_encoding::RawBytes;

    #[test]
    fn serialize_params() {
        let p = ConstructorParams {
            network_name: "/root".to_string(),
            bottomup_check_period: 100,
            topdown_check_period: 20,
        };
        let bytes = fil_actors_runtime::util::cbor::serialize(&p, "").unwrap();
        let serialized = base64::encode(bytes.bytes());

        let raw_bytes = RawBytes::new(base64::decode(serialized).unwrap());
        let deserialized =
            fil_actors_runtime::util::cbor::deserialize::<ConstructorParams>(&raw_bytes, "")
                .unwrap();

        assert_eq!(p.network_name, deserialized.network_name);
        assert_eq!(p.bottomup_check_period, deserialized.bottomup_check_period);
        assert_eq!(p.topdown_check_period, deserialized.topdown_check_period);
    }
}
