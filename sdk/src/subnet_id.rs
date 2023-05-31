use fil_actors_runtime::cbor;
use fvm_shared::address::Address;
use lazy_static::lazy_static;
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

const SUBNET_ERR_TAG: &str = "subnetID";

/// SubnetID is a unique identifier for a subnet.
/// It is composed of the chainID of the root network, and the address of
/// all the subnet actors from the root to the corresponding level in the
/// hierarchy where the subnet is spawned.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct SubnetID {
    root: u64,
    children: Vec<Address>,
}

lazy_static! {
    pub static ref UNDEF: SubnetID = SubnetID {
        root: 0,
        children: vec![],
    };
}

impl SubnetID {
    pub fn new(root_id: u64, children: Vec<Address>) -> Self {
        Self {
            root: root_id,
            children,
        }
    }
    /// Create a new subnet id from the root network id and the subnet actor
    pub fn new_from_parent(parent: &SubnetID, subnet_act: Address) -> Self {
        let mut children = parent.children();
        children.push(subnet_act);
        Self {
            root: parent.root_id(),
            children,
        }
    }

    /// Returns true if the current subnet is the root network
    pub fn is_root(&self) -> bool {
        self.children_as_ref().len() == 0
    }

    /// Returns the chainID of the root network.
    pub fn root_id(&self) -> u64 {
        self.root
    }

    /// Returns the route from the root to the current subnet
    pub fn children(&self) -> Vec<Address> {
        self.children.clone()
    }

    /// Returns the route from the root to the current subnet
    pub fn children_as_ref(&self) -> &Vec<Address> {
        &self.children
    }

    /// Returns the serialized version of the subnet id
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::serialize(self, SUBNET_ERR_TAG).unwrap().into()
    }

    /// Returns the address of the actor governing the subnet in the parent
    pub fn subnet_actor(&self) -> Address {
        self.children_as_ref().last().unwrap().clone()
    }

    /// Returns the parenet of the current subnet
    pub fn parent(&self) -> Option<SubnetID> {
        // if the subnet is the root, it has no parent
        if self.children_as_ref().len() == 0 {
            return None;
        }

        let children = self.children();
        Some(SubnetID::new(
            self.root_id(),
            children[..children.len() - 1].to_vec(),
        ))
    }

    /// Computes the common parent of the current subnet and the one given
    /// as argument. It returns the number of common children and the subnet.
    pub fn common_parent(&self, other: &SubnetID) -> Option<(usize, SubnetID)> {
        // check if we have the same root first
        if self.root_id() != other.root_id() {
            return None;
        }

        let common = self
            .children_as_ref()
            .iter()
            .zip(other.children_as_ref())
            .take_while(|(a, b)| a == b)
            .count();
        let children = self.children()[..common].to_vec();
        Some((common, SubnetID::new(self.root_id(), children)))
    }

    /// In the path determined by the current subnet id, it moves
    /// down in the path from the subnet id given as argument.
    pub fn down(&self, from: &SubnetID) -> Option<SubnetID> {
        // check if the current network's path is larger than
        // the one to be traversed.
        if self.children_as_ref().len() <= from.children_as_ref().len() {
            return None;
        }

        if let Some((i, _)) = self.common_parent(from) {
            let children = self.children()[..i + 1].to_vec();
            return Some(SubnetID::new(self.root_id(), children));
        }
        None
    }

    /// In the path determined by the current subnet id, it moves
    /// up in the path from the subnet id given as argument.
    pub fn up(&self, from: &SubnetID) -> Option<SubnetID> {
        // check if the current network's path is larger than
        // the one to be traversed.
        if self.children_as_ref().len() < from.children_as_ref().len() {
            return None;
        }

        if let Some((i, _)) = self.common_parent(from) {
            let children = self.children()[..i - 1].to_vec();
            return Some(SubnetID::new(self.root_id(), children));
        }
        None
    }
}

impl fmt::Display for SubnetID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let children_str = self
            .children_as_ref()
            .iter()
            .map(|s| format!("/{}", s))
            .collect::<String>();

        write!(f, "/r{}{}", self.root_id(), children_str)
    }
}

impl Default for SubnetID {
    fn default() -> Self {
        UNDEF.clone()
    }
}

impl FromStr for SubnetID {
    type Err = Error;
    fn from_str(id: &str) -> Result<Self, Error> {
        let l: Vec<&str> = id.split('/').filter(|&elem| !elem.is_empty()).collect();
        let root = l[0][1..].parse::<u64>().map_err(|_| Error::InvalidID)?;
        let children: Result<Vec<_>, _> = l[1..].iter().map(|s| Address::from_str(s)).collect();
        if let Ok(children) = children {
            return Ok(Self { root, children });
        }
        Err(Error::InvalidID)
    }
}

#[cfg(test)]
mod tests {
    use crate::subnet_id::SubnetID;
    use fvm_shared::address::Address;
    use std::str::FromStr;

    #[test]
    fn test_subnet_id() {
        let act = Address::new_id(1001);
        let sub_id = SubnetID::new(123, vec![act]);
        let sub_id_str = sub_id.to_string();
        assert_eq!(sub_id_str, "/r123/f01001");

        let rtt_id = SubnetID::from_str(&sub_id_str).unwrap();
        assert_eq!(sub_id, rtt_id);

        let rootnet = SubnetID::new(123, vec![]);
        assert_eq!(rootnet.to_string(), "/r123");
        let root_sub = SubnetID::from_str(&rootnet.to_string()).unwrap();
        assert_eq!(root_sub, rootnet);
    }

    #[test]
    fn test_common_parent() {
        common_parent("/r123/f01", "/r123/f01/f02", "/r123/f01", 1);
        common_parent("/r123/f01/f02/f03", "/r123/f01/f02", "/r123/f01/f02", 2);
        common_parent("/r123/f01/f03/f04", "/r123/f02/f03/f04", "/r123", 0);
        common_parent(
            "/r123/f01/f03/f04",
            "/r123/f01/f03/f04/f05",
            "/r123/f01/f03/f04",
            3,
        );
        // The common parent of the same subnet is the current subnet
        common_parent(
            "/r123/f01/f03/f04",
            "/r123/f01/f03/f04",
            "/r123/f01/f03/f04",
            3,
        );
    }

    #[test]
    #[should_panic]
    fn test_panic_different_root() {
        common_parent("/r122/f01", "/r123/f01/f02", "/r123/f01", 1);
    }

    #[test]
    fn test_down() {
        down(
            "/r123/f01/f02/f03",
            "/r123/f01",
            Some(SubnetID::from_str("/r123/f01/f02").unwrap()),
        );
        down(
            "/r123/f01/f02/f03",
            "/r123/f01/f02",
            Some(SubnetID::from_str("/r123/f01/f02/f03").unwrap()),
        );
        down(
            "/r123/f01/f03/f04",
            "/r123/f01/f03",
            Some(SubnetID::from_str("/r123/f01/f03/f04").unwrap()),
        );
        down("/r123", "/r123/f01", None);
        down("/r123/f01", "/r123/f01", None);
        down("/r123/f02/f03", "/r123/f01/f03/f04", None);
        down("/r123", "/r123/f01", None);
    }

    #[test]
    fn test_up() {
        up(
            "/r123/f01/f02/f03",
            "/r123/f01",
            Some(SubnetID::from_str("/r123").unwrap()),
        );
        up(
            "/r123/f01/f02/f03",
            "/r123/f01/f02",
            Some(SubnetID::from_str("/r123/f01").unwrap()),
        );
        up("/r123", "/r123/f01", None);
        up("/r123/f02/f03", "/r123/f01/f03/f04", None);
        up(
            "/r123/f01/f02/f03",
            "/r123/f01/f02",
            Some(SubnetID::from_str("/r123/f01").unwrap()),
        );
        up(
            "/r123/f01/f02/f03",
            "/r123/f01/f02/f03",
            Some(SubnetID::from_str("/r123/f01/f02").unwrap()),
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
