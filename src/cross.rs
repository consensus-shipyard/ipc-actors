use crate::address::IPCAddress;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use serde::{Deserialize, Serialize};

/// StorableMsg stores all the relevant information required
/// to execute cross-messages.
///
/// We follow this approach because we can't directly store types.Message
/// as we did in the actor's Go counter-part. Instead we just persist the
/// information required to create the cross-messages and execute in the
/// corresponding node implementation.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct StorableMsg {
    pub from: IPCAddress,
    pub to: IPCAddress,
    pub method: MethodNum,
    pub params: RawBytes,
    pub value: TokenAmount,
    pub nonce: u64,
}
impl Cbor for StorableMsg {}

impl Default for StorableMsg {
    fn default() -> Self {
        Self {
            from: IPCAddress::new_id(0),
            to: IPCAddress::new_id(0),
            method: 0,
            params: RawBytes::default(),
            value: TokenAmount::default(),
            nonce: 0,
        }
    }
}
