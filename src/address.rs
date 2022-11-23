use crate::error::Error;
use crate::SubnetID;
use fil_actors_runtime::cbor;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::ActorID;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// The default actor id namespace for IPC addresses
lazy_static! {
    pub static ref DEFAULT_IPC_ACTOR_NAMESPACE_ID: ActorID = 1000u64;
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub struct IPCAddress {
    subnet_id: SubnetID,
    raw_address: Address,
}

impl IPCAddress {
    /// Generates new address using ID protocol
    pub fn new_id(id: u64) -> Self {
        let d = SubnetID::default();
        Self {
            subnet_id: d,
            raw_address: Address::new_id(id),
        }
    }

    /// Generates new IPC address
    pub fn new(sn: &SubnetID, addr: &Address) -> Result<Self, Error> {
        Ok(Self {
            subnet_id: sn.clone(),
            raw_address: *addr,
        })
    }

    /// Generates new IPC address
    pub fn new_from_ipc(sn: &SubnetID, addr: &Self) -> Result<Self, Error> {
        Ok(Self {
            subnet_id: sn.clone(),
            raw_address: addr.raw_address,
        })
    }

    /// Returns subnets of a IPC address
    pub fn subnet(&self) -> Result<SubnetID, Error> {
        Ok(self.subnet_id.clone())
    }

    /// Returns the raw address of a IPC address (without subnet context)
    pub fn raw_addr(&self) -> Result<Address, Error> {
        Ok(self.raw_address)
    }

    /// Returns encoded bytes of Address
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor::serialize(self, "ipc-address")?.to_vec())
    }

    pub fn from_bytes(bz: &[u8]) -> Result<Self, Error> {
        let i: Self = cbor::deserialize(&RawBytes::new(bz.to_vec()), "ipc-address")?;
        Ok(i)
    }

    pub fn to_string(&self) -> Result<String, Error> {
        Ok(format!("{}-{}", self.subnet_id.to_string(), self.raw_address.to_string()))
    }
}

impl FromStr for IPCAddress {
    type Err = Error;

    fn from_str(addr: &str) -> Result<Self, Error> {
        let r: Vec<&str> = addr.split("-").collect();
        if r.len() != 2 {
            Err(Error::InvalidIPCAddr)
        } else {
            Ok(Self {
                raw_address: Address::from_str(r[1])?,
                subnet_id: SubnetID::from_str(r[0])?,
            })
        }
    }
}
