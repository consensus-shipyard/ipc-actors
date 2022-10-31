use fil_actors_runtime::Array;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use serde::{Deserialize, Serialize};

use crate::checkpoint::{Checkpoint, CrossMsgMeta};
use crate::subnet_id::SubnetID;
use crate::StorableMsg;

pub const CROSSMSG_AMT_BITWIDTH: u32 = 3;
pub const DEFAULT_CHECKPOINT_PERIOD: ChainEpoch = 10;
pub const MAX_NONCE: u64 = u64::MAX;
pub const MIN_COLLATERAL_AMOUNT: u64 = 10_u64.pow(18);

pub type CrossMsgMetaArray<'bs, BS> = Array<'bs, CrossMsgMeta, BS>;
pub type CrossMsgArray<'bs, BS> = Array<'bs, StorableMsg, BS>;

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
    pub msg: StorableMsg,
    pub destination: SubnetID,
}

#[cfg(test)]
mod tests {
    use fvm_ipld_encoding::RawBytes;
    use crate::ConstructorParams;

    #[test]
    fn serialize_params() {
        let p = ConstructorParams{ network_name: "/root".to_string(), checkpoint_period: 100 };
        let bytes = fil_actors_runtime::util::cbor::serialize(&p, "").unwrap();
        let serialized = base64::encode(bytes.bytes());

        let raw_bytes = RawBytes::new(base64::decode(serialized).unwrap());
        let deserialized = fil_actors_runtime::util::cbor::deserialize::<ConstructorParams>(&raw_bytes, "").unwrap();

        assert_eq!(p.network_name, deserialized.network_name);
        assert_eq!(p.checkpoint_period, deserialized.checkpoint_period);
    }
}