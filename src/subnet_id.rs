use fvm_ipld_encoding::Cbor;
use fvm_shared::address::Address;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::Error;

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct SubnetID {
    parent: String,
    actor: Address,
}
impl Cbor for SubnetID {}

lazy_static! {
    pub static ref ROOTNET_ID: SubnetID = SubnetID {
        parent: String::from("/root"),
        actor: Address::new_id(0)
    };
    pub static ref UNDEF: SubnetID = SubnetID {
        parent: String::from("/"),
        actor: Address::new_id(0)
    };
}

impl SubnetID {
    pub fn to_bytes(&self) -> Vec<u8> {
        let str_id = self.to_string();
        str_id.into_bytes()
    }

    /// Computes the common parent of the current subnet and the one given
    /// as argument
    pub fn common_parent(&self, other: &SubnetID) -> Option<(usize, SubnetID)> {
        let a = self.to_string();
        let b = other.to_string();
        let a = Path::new(&a).components();
        let b = Path::new(&b).components();
        let mut ret = PathBuf::new();
        let mut found = false;
        let mut index = 0;
        for (i, (one, two)) in a.zip(b).enumerate() {
            if one == two {
                ret.push(one);
                found = true;
                index = i;
            } else {
                break;
            }
        }
        if found {
            return match SubnetID::from_str(ret.to_str()?) {
                Ok(p) => Some((index, p)),
                Err(_) => None,
            };
        }
        Some((index, ROOTNET_ID.clone()))
    }
}

impl fmt::Display for SubnetID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.parent == "/root" && self.actor == Address::new_id(0) {
            return write!(f, "{}", self.parent);
        }
        match Path::join(
            Path::new(&self.parent),
            Path::new(&format!("{}", self.actor)),
        )
        .to_str()
        {
            Some(r) => write!(f, "{}", r),
            None => Err(fmt::Error),
        }
    }
}

impl Default for SubnetID {
    fn default() -> Self {
        Self {
            parent: String::from(""),
            actor: Address::new_id(0),
        }
    }
}

impl FromStr for SubnetID {
    type Err = Error;
    fn from_str(addr: &str) -> Result<Self, Error> {
        if addr == ROOTNET_ID.to_string() {
            return Ok(ROOTNET_ID.clone());
        }

        let id = Path::new(addr);
        let act = match Path::file_name(id) {
            Some(act_str) => Address::from_str(act_str.to_str().unwrap_or("")),
            None => return Err(Error::InvalidID),
        };

        let mut anc = id.ancestors();
        let _ = anc.next();
        let par = match anc.next() {
            Some(par_str) => par_str.to_str(),
            None => return Err(Error::InvalidID),
        }
        .ok_or(Error::InvalidID)
        .unwrap();

        Ok(Self {
            parent: String::from(par),
            actor: match act {
                Ok(addr) => addr,
                Err(_) => return Err(Error::InvalidID),
            },
        })
    }
}
