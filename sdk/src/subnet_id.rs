use fvm_shared::address::Address;
use lazy_static::lazy_static;
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::Error;
use crate::set_network_from_env;

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct SubnetID {
    parent: String,
    actor: Address,
}

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
    pub fn new_from_parent(parent: &SubnetID, subnet_act: Address) -> Self {
        Self {
            parent: parent.to_string(),
            actor: subnet_act,
        }
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
        // FIXME: This is a horrible hack, and it makes me feel dirty,
        // but it is the only way to ensure that we are picking up
        // the right network address for the environment.
        set_network_from_env();

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
    use crate::subnet_id::{SubnetID, ROOTNET_ID};
    use fvm_shared::address::Address;
    use std::str::FromStr;

    #[test]
    fn test_subnet_id() {
        let act = Address::new_id(1001);
        let sub_id = SubnetID::new_from_parent(&ROOTNET_ID.clone(), act);
        let sub_id_str = sub_id.to_string();
        assert_eq!(sub_id_str, "/root/t01001");

        let rtt_id = SubnetID::from_str(&sub_id_str).unwrap();
        assert_eq!(sub_id, rtt_id);

        let rootnet = ROOTNET_ID.clone();
        assert_eq!(rootnet.to_string(), "/root");
        let root_sub = SubnetID::from_str(&rootnet.to_string()).unwrap();
        assert_eq!(root_sub, rootnet);
    }

    #[test]
    fn test_common_parent() {
        common_parent("/root/t01", "/root/t01/t02", "/root/t01", 2);
        common_parent("/root/t01/t02/t03", "/root/t01/t02", "/root/t01/t02", 3);
        common_parent("/root/t01/t03/t04", "/root/t02/t03/t04", "/root", 1);
        common_parent(
            "/root/t01/t03/t04",
            "/root/t01/t03/t04/t05",
            "/root/t01/t03/t04",
            4,
        );
        // The common parent of the same subnet is the current subnet
        common_parent(
            "/root/t01/t03/t04",
            "/root/t01/t03/t04",
            "/root/t01/t03/t04",
            4,
        );
    }

    #[test]
    fn test_down() {
        down(
            "/root/t01/t02/t03",
            "/root/t01",
            Some(SubnetID::from_str("/root/t01/t02").unwrap()),
        );
        down(
            "/root/t01/t02/t03",
            "/root/t01/t02",
            Some(SubnetID::from_str("/root/t01/t02/t03").unwrap()),
        );
        down(
            "/root/t01/t03/t04",
            "/root/t01/t03",
            Some(SubnetID::from_str("/root/t01/t03/t04").unwrap()),
        );
        down("/root", "/root/t01", None);
        down("/root/t01", "/root/t01", None);
        down("/root/t02/t03", "/root/t01/t03/t04", None);
        down("/root", "/root/t01", None);
    }

    #[test]
    fn test_up() {
        up(
            "/root/t01/t02/t03",
            "/root/t01",
            Some(SubnetID::from_str("/root").unwrap()),
        );
        up(
            "/root/t01/t02/t03",
            "/root/t01/t02",
            Some(SubnetID::from_str("/root/t01").unwrap()),
        );
        up("/root", "/root/t01", None);
        up("/root/t02/t03", "/root/t01/t03/t04", None);
        up(
            "/root/t01/t02/t03",
            "/root/t01/t02",
            Some(SubnetID::from_str("/root/t01").unwrap()),
        );
        up(
            "/root/t01/t02/t03",
            "/root/t01/t02/t03",
            Some(SubnetID::from_str("/root/t01/t02").unwrap()),
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
