use std::str::FromStr;
use fvm_shared::address::{Address, Network, NETWORK_DEFAULT, Payload};
use crate::error::Error;
use crate::SubnetID;

/// Maximum length for an address payload determined by
/// the maximum size of the hierarchical address.
const MAX_ADDRESS_LEN: usize = 54;

pub struct HierarchicalAddress {
    inner: Address
}

impl HierarchicalAddress {
    /// Generates new address using ID protocol
    pub const fn new_id(id: u64) -> Self {
        Self {
            inner: Address::new_id(id)
        }
    }

    /// Generates new hierarchical address
    pub fn new_hierarchical(sn: &SubnetID, addr: &Address) -> Result<Self, Error> {
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
        Ok(
            Self {
                inner: Address::new_delegated()
            }
        )
    }

    /// Returns subnets of a hierarchical address
    pub fn subnet(&self) -> Result<SubnetID, Error> {
        let bz = self.payload.to_raw_bytes();
        let sn_size = from_leb_bytes(&[bz[0]]).unwrap() as usize;
        let s = String::from_utf8(bz[2..sn_size + 2].to_vec())
            .map_err(|_| Error::InvalidHierarchicalAddr)?;
        SubnetID::from_str(&s).map_err(|_| Error::InvalidHierarchicalAddr)
    }

    /// Returns the raw address of a hierarchical address (without subnet context)
    pub fn raw_addr(&self) -> Result<Address, Error> {
        let bz = self.payload.to_raw_bytes();
        let sn_size = from_leb_bytes(&[bz[0]]).unwrap() as usize;
        Ok(Address::from_bytes(&bz[2 + sn_size..])?)
    }
}

pub(crate) fn to_leb_bytes(id: u64) -> Result<Vec<u8>, Error> {
    // write id to buffer in leb128 format
    Ok(unsigned_varint::encode::u64(id, &mut unsigned_varint::encode::u64_buffer()).into())
}