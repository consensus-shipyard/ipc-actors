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
    pub fn new_from_string(parent: String, subnet_act: Address) -> Self {
        Self {
            parent,
            actor: subnet_act,
        }
    }

    pub fn new(parent: &SubnetID, subnet_act: Address) -> Self {
        Self::new_from_string(parent.to_string(), subnet_act)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let str_id = self.to_string();
        str_id.into_bytes()
    }

    /// Returns the address of the actor governing the subnet in th eparent
    pub fn subnet_actor(&self) -> Address {
        self.actor
    }

    /// Returns the parenet of the current subnet
    pub fn parent(&self) -> Option<SubnetID> {
        if *self == *ROOTNET_ID {
            return None;
        }
        match SubnetID::from_str(&self.parent) {
            Ok(id) => Some(id),
            Err(_) => None,
        }
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

    /// In the path determined by the current subnet id, it moves
    /// down in the path from the subnet id given as argument.
    pub fn down(&self, from: &SubnetID) -> Option<SubnetID> {
        let a = self.to_string();
        let a = Path::new(&a).components();
        let mut cl_a = a.clone();
        let b = from.to_string();
        let b = Path::new(&b).components();
        let mut cl_b = b.clone();
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

        // the from needs to be a subset of the current subnet id
        if found && cl_b.nth(index + 1).is_none() {
            ret.push(cl_a.nth(index + 1)?);
            return match SubnetID::from_str(ret.to_str()?) {
                Ok(p) => Some(p),
                Err(_) => None,
            };
        }
        None
    }

    /// In the path determined by the current subnet id, it moves
    /// up in the path from the subnet id given as argument.
    pub fn up(&self, from: &SubnetID) -> Option<SubnetID> {
        // we can't go upper than the root.
        if self == &*ROOTNET_ID || from == &*ROOTNET_ID {
            return None;
        }
        let a = format!("{}", self);
        let a = Path::new(&a).components();
        let b = format!("{}", from);
        let b = Path::new(&b).components();
        let mut cl_b = b.clone();
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

        // the from needs to be a subset of the current subnet id
        if found && cl_b.nth(index + 1).is_none() {
            // pop to go up
            ret.pop();
            return match SubnetID::from_str(ret.to_str()?) {
                Ok(p) => Some(p),
                Err(_) => None,
            };
        }
        None
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

#[cfg(test)]
mod tests {
    use crate::IPCAddress;
    use fvm_shared::address::Address;
    use sdk::subnet_id::{SubnetID, ROOTNET_ID};
    use std::str::FromStr;

    #[test]
    fn test_subnet_id() {
        let act = Address::new_id(1001);
        let sub_id = SubnetID::new(&ROOTNET_ID.clone(), act);
        let sub_id_str = sub_id.to_string();
        assert_eq!(sub_id_str, "/root/f01001");

        let rtt_id = SubnetID::from_str(&sub_id_str).unwrap();
        assert_eq!(sub_id, rtt_id);

        let rootnet = ROOTNET_ID.clone();
        assert_eq!(rootnet.to_string(), "/root");
        let root_sub = SubnetID::from_str(&rootnet.to_string()).unwrap();
        assert_eq!(root_sub, rootnet);
    }

    // // TODO: temporarily disabled for compilation and comply with Delegated Address
    // #[test]
    // fn test_IPC_address() {
    //     let act = Address::new_id(1001);
    //     let sub_id = SubnetID::new(&ROOTNET_ID.clone(), act);
    //     let bls = Address::from_str("f3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a").unwrap();
    //     let blss = IPCAddress::from_str("f3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a").unwrap();
    //     let haddr = IPCAddress::new(&sub_id, &bls).unwrap();
    //     assert_eq!(haddr.raw_addr().unwrap(), bls);
    //     assert_eq!(haddr.subnet().unwrap(), sub_id);
    //     // assert_eq!(IPCAddress::raw_addr(&bls).unwrap(), bls);
    //
    //     match blss.subnet() {
    //         Err(e) => assert_eq!(e, Error::InvalidIPCAddr),
    //         _ => panic!("subnet over non-IPC address should have failed"),
    //     }
    // }

    #[test]
    fn test_ipc_from_str() {
        let sub_id = SubnetID::new(&ROOTNET_ID.clone(), Address::new_id(100));
        let addr = IPCAddress::new(&sub_id, &Address::new_id(101)).unwrap();
        let st = addr.to_string().unwrap();
        let addr_out = IPCAddress::from_str(&st).unwrap();
        assert_eq!(addr, addr_out);
    }

    #[test]
    fn test_common_parent() {
        common_parent("/root/f01", "/root/f01/f02", "/root/f01", 2);
        common_parent("/root/f01/f02/f03", "/root/f01/f02", "/root/f01/f02", 3);
        common_parent("/root/f01/f03/f04", "/root/f02/f03/f04", "/root", 1);
        common_parent(
            "/root/f01/f03/f04",
            "/root/f01/f03/f04/f05",
            "/root/f01/f03/f04",
            4,
        );
        // The common parent of the same subnet is the current subnet
        common_parent(
            "/root/f01/f03/f04",
            "/root/f01/f03/f04",
            "/root/f01/f03/f04",
            4,
        );
    }

    #[test]
    fn test_down() {
        down(
            "/root/f01/f02/f03",
            "/root/f01",
            Some(SubnetID::from_str("/root/f01/f02").unwrap()),
        );
        down(
            "/root/f01/f02/f03",
            "/root/f01/f02",
            Some(SubnetID::from_str("/root/f01/f02/f03").unwrap()),
        );
        down(
            "/root/f01/f03/f04",
            "/root/f01/f03",
            Some(SubnetID::from_str("/root/f01/f03/f04").unwrap()),
        );
        down("/root", "/root/f01", None);
        down("/root/f01", "/root/f01", None);
        down("/root/f02/f03", "/root/f01/f03/f04", None);
        down("/root", "/root/f01", None);
    }

    #[test]
    fn test_up() {
        up(
            "/root/f01/f02/f03",
            "/root/f01",
            Some(SubnetID::from_str("/root").unwrap()),
        );
        up(
            "/root/f01/f02/f03",
            "/root/f01/f02",
            Some(SubnetID::from_str("/root/f01").unwrap()),
        );
        up("/root", "/root/f01", None);
        up("/root/f02/f03", "/root/f01/f03/f04", None);
        up(
            "/root/f01/f02/f03",
            "/root/f01/f02",
            Some(SubnetID::from_str("/root/f01").unwrap()),
        );
        up(
            "/root/f01/f02/f03",
            "/root/f01/f02/f03",
            Some(SubnetID::from_str("/root/f01/f02").unwrap()),
        );
    }

    fn common_parent(a: &str, b: &str, res: &str, index: usize) {
        let id = SubnetID::from_str(a).unwrap();
        assert_eq!(
            id.common_parent(&SubnetID::from_str(b).unwrap()).unwrap(),
            (index, SubnetID::from_str(res).unwrap()),
        );
    }

    fn down(a: &str, b: &str, res: Option<SubnetID>) {
        let id = SubnetID::from_str(a).unwrap();
        assert_eq!(id.down(&SubnetID::from_str(b).unwrap()), res);
    }

    fn up(a: &str, b: &str, res: Option<SubnetID>) {
        let id = SubnetID::from_str(a).unwrap();
        assert_eq!(id.up(&SubnetID::from_str(b).unwrap()), res);
    }
}
