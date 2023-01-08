use cid::multihash::Code;
use cid::Cid;
use fil_actors_runtime::Array;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_ipld_encoding::Cbor;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use ipc_sdk::subnet_id::SubnetID;
use primitives::CodeType;
use serde::{Deserialize, Serialize};

use crate::checkpoint::{Checkpoint, CrossMsgMeta};
use crate::cross::CrossMsg;

pub const CROSSMSG_AMT_BITWIDTH: u32 = 3;
pub const DEFAULT_CHECKPOINT_PERIOD: ChainEpoch = 10;
pub const MAX_NONCE: u64 = u64::MAX;
pub const MIN_COLLATERAL_AMOUNT: u64 = 10_u64.pow(18);

pub type CrossMsgMetaArray<'bs, BS> = Array<'bs, CrossMsgMeta, BS>;
pub type CrossMsgArray<'bs, BS> = Array<'bs, CrossMsg, BS>;

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub network_name: String,
    pub checkpoint_period: ChainEpoch,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FundParams {
    pub value: TokenAmount,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct CheckpointParams {
    pub checkpoint: Checkpoint,
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
    pub gas: TokenAmount,
    /// The postbox message cid
    pub postbox_cid: Cid,
}

/// The item to store in the `State::postbox`
#[derive(Serialize_tuple, Deserialize_tuple, PartialEq, Eq, Clone)]
pub struct PostBoxItem {
    pub gas: TokenAmount,
    pub cross_msg: CrossMsg,
    pub owner: Address,
}

impl Cbor for PostBoxItem {}

// The implementation does not matter, we just need to extract the cid
impl CodeType for PostBoxItem {
    fn code() -> Code {
        Code::Blake2b256
    }
}

impl PostBoxItem {
    pub fn new(gas: TokenAmount, cross_msg: CrossMsg, owner: Address) -> Self {
        Self {
            gas,
            cross_msg,
            owner,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ConstructorParams;
    use fvm_ipld_encoding::RawBytes;

    #[test]
    fn serialize_params() {
        let p = ConstructorParams {
            network_name: "/root".to_string(),
            checkpoint_period: 100,
        };
        let bytes = fil_actors_runtime::util::cbor::serialize(&p, "").unwrap();
        let serialized = base64::encode(bytes.bytes());

        let raw_bytes = RawBytes::new(base64::decode(serialized).unwrap());
        let deserialized =
            fil_actors_runtime::util::cbor::deserialize::<ConstructorParams>(&raw_bytes, "")
                .unwrap();

        assert_eq!(p.network_name, deserialized.network_name);
        assert_eq!(p.checkpoint_period, deserialized.checkpoint_period);
    }
}
