use crate::error::Error;
use crate::SubnetID;
use fvm_shared::address::Address;
use fvm_shared::ActorID;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

/// Maximum length for an address payload determined by
/// the maximum size of the IPC address.
const MAX_ADDRESS_LEN: usize = 54;

// The default actor id namespace for IPC addresses
lazy_static! {
    pub static ref DEFAULT_IPC_ACTOR_NAMESPACE_ID: ActorID = 1000u64;
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub struct IPCAddress {
    inner: Address,
}

impl fmt::Display for IPCAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl IPCAddress {
    /// Generates new address using ID protocol
    pub const fn new_id(id: u64) -> Self {
        Self {
            inner: Address::new_id(id),
        }
    }

    /// Generates new IPC address
    pub fn new(sn: &SubnetID, addr: &Address) -> Result<Self, Error> {
        let sn = sn.to_bytes();
        let addr = addr.to_bytes();
        let sn_size_vec = to_leb_bytes(sn.len() as u64)?;
        let sn_size: &[u8] = sn_size_vec.as_ref();
        let addr_size_vec = to_leb_bytes(addr.len() as u64)?;
        let addr_size: &[u8] = addr_size_vec.as_ref();
        let sp = [sn_size, addr_size, sn.as_slice(), addr.as_slice()].concat();
        // include in fixed-length container
        let mut key = [0u8; MAX_ADDRESS_LEN];
        key[..sp.len()].copy_from_slice(sp.as_slice());
        Ok(Self {
            inner: Address::new_delegated(*DEFAULT_IPC_ACTOR_NAMESPACE_ID, &key)?,
        })
    }

    /// Generates new IPC address
    pub fn new_from_ipc(sn: &SubnetID, addr: &Self) -> Result<Self, Error> {
        let sn = sn.to_bytes();
        let addr = addr.to_bytes();
        let sn_size_vec = to_leb_bytes(sn.len() as u64)?;
        let sn_size: &[u8] = sn_size_vec.as_ref();
        let addr_size_vec = to_leb_bytes(addr.len() as u64)?;
        let addr_size: &[u8] = addr_size_vec.as_ref();
        let sp = [sn_size, addr_size, sn.as_slice(), addr.as_slice()].concat();
        // include in fixed-length container
        let mut key = [0u8; MAX_ADDRESS_LEN];
        key[..sp.len()].copy_from_slice(sp.as_slice());
        Ok(Self {
            inner: Address::new_delegated(*DEFAULT_IPC_ACTOR_NAMESPACE_ID, &key)?,
        })
    }

    /// Returns subnets of a IPC address
    pub fn subnet(&self) -> Result<SubnetID, Error> {
        let bz = self.inner.payload().to_raw_bytes();
        let sn_size = from_leb_bytes(&[bz[0]]).unwrap() as usize;
        let s =
            String::from_utf8(bz[2..sn_size + 2].to_vec()).map_err(|_| Error::InvalidIPCAddr)?;
        SubnetID::from_str(&s).map_err(|_| Error::InvalidIPCAddr)
    }

    /// Returns the raw address of a IPC address (without subnet context)
    pub fn raw_addr(&self) -> Result<Address, Error> {
        let bz = self.inner.payload().to_raw_bytes();
        let sn_size = from_leb_bytes(&[bz[0]]).unwrap() as usize;
        Ok(Address::from_bytes(&bz[2 + sn_size..])?)
    }

    /// Returns encoded bytes of Address
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

pub(crate) fn to_leb_bytes(id: u64) -> Result<Vec<u8>, Error> {
    // write id to buffer in leb128 format
    Ok(unsigned_varint::encode::u64(id, &mut unsigned_varint::encode::u64_buffer()).into())
}

pub(crate) fn from_leb_bytes(bz: &[u8]) -> Result<u64, Error> {
    // write id to buffer in leb128 format
    let (id, remaining) = unsigned_varint::decode::u64(bz)?;
    if !remaining.is_empty() {
        return Err(Error::InvalidPayload);
    }
    Ok(id)
}

impl FromStr for IPCAddress {
    type Err = Error;

    fn from_str(addr: &str) -> Result<Self, Error> {
        let inner = Address::from_str(addr)?;
        Ok(Self { inner })
    }
}
