use fvm_ipld_encoding::tuple::{Deserialize_tuple, Serialize_tuple};
use ipc_gateway::{StorableMsg, SubnetID};

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub ipc_gateway_address: Vec<u8>,
    pub network_name: String,
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone)]
pub struct CrossMsgParams {
    pub msg: StorableMsg,
    pub destination: SubnetID,
}

impl CrossMsgParams {
    pub fn new(msg: StorableMsg, destination: SubnetID) -> Self {
        Self { msg, destination }
    }
}
