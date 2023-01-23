use crate::ApplyMsgParams;
use anyhow::anyhow;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::ActorError;
use fil_actors_runtime::BURNT_FUNDS_ACTOR_ADDR;
use fil_actors_runtime::REWARD_ACTOR_ADDR;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::MethodNum;
use fvm_shared::METHOD_SEND;
use ipc_sdk::address::IPCAddress;
use ipc_sdk::subnet_id::SubnetID;
use primitives::{TCid, TLink};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct CrossMsg {
    pub msg: StorableMsg,
    pub wrapped: bool,
}

#[derive(PartialEq, Eq)]
pub enum IPCMsgType {
    BottomUp,
    TopDown,
}

impl CrossMsg {
    pub fn send<BS, RT>(self, rt: &mut RT, rto: Address) -> Result<RawBytes, ActorError>
    where
        BS: Blockstore,
        RT: Runtime<BS>,
    {
        if !self.wrapped {
            let msg = self.msg;
            rt.send(rto, msg.method, msg.params, msg.value)
        } else {
            let method = self.msg.method;
            let value = self.msg.value.clone();
            let params = RawBytes::serialize(ApplyMsgParams { cross_msg: self })?;
            rt.send(rto, method, params, value)
        }
    }
}

impl StorableMsg {
    pub fn new_release_msg(
        sub_id: &SubnetID,
        sig_addr: &Address,
        value: TokenAmount,
        nonce: u64,
    ) -> anyhow::Result<Self> {
        let to = IPCAddress::new(
            &match sub_id.parent() {
                Some(s) => s,
                None => return Err(anyhow!("error getting parent for subnet addr")),
            },
            sig_addr,
        )?;
        let from = IPCAddress::new(sub_id, &BURNT_FUNDS_ACTOR_ADDR)?;
        Ok(Self {
            from,
            to,
            method: METHOD_SEND,
            params: RawBytes::default(),
            value,
            nonce,
        })
    }

    pub fn new_fund_msg(
        sub_id: &SubnetID,
        sig_addr: &Address,
        value: TokenAmount,
    ) -> anyhow::Result<Self> {
        let from = IPCAddress::new(
            &match sub_id.parent() {
                Some(s) => s,
                None => return Err(anyhow!("error getting parent for subnet addr")),
            },
            sig_addr,
        )?;
        let to = IPCAddress::new(sub_id, sig_addr)?;
        // the nonce and the rest of message fields are set when the message is committed.
        Ok(Self {
            from,
            to,
            method: METHOD_SEND,
            params: RawBytes::default(),
            value,
            nonce: 0,
        })
    }

    pub fn new_reward_msg(
        curr_sub: &SubnetID,
        value: TokenAmount,
        nonce: u64,
    ) -> anyhow::Result<Self> {
        let to = IPCAddress::new(
            &match curr_sub.parent() {
                Some(s) => s,
                None => return Err(anyhow!("error getting parent for subnet addr")),
            },
            &curr_sub.subnet_actor(),
        )?;
        let from = IPCAddress::new(curr_sub, &REWARD_ACTOR_ADDR)?;
        Ok(Self {
            from,
            to,
            method: METHOD_SEND,
            params: RawBytes::default(),
            value,
            nonce,
        })
    }

    pub fn ipc_type(&self) -> anyhow::Result<IPCMsgType> {
        let sto = self.to.subnet()?;
        let sfrom = self.from.subnet()?;
        if is_bottomup(&sfrom, &sto) {
            return Ok(IPCMsgType::BottomUp);
        }
        Ok(IPCMsgType::TopDown)
    }

    pub fn apply_type(&self, curr: &SubnetID) -> anyhow::Result<IPCMsgType> {
        let sto = self.to.subnet()?;
        let sfrom = self.from.subnet()?;
        if curr.common_parent(&sto) == sfrom.common_parent(&sto)
            && self.ipc_type()? == IPCMsgType::BottomUp
        {
            return Ok(IPCMsgType::BottomUp);
        }
        Ok(IPCMsgType::TopDown)
    }
}

pub fn is_bottomup(from: &SubnetID, to: &SubnetID) -> bool {
    let index = match from.common_parent(to) {
        Some((ind, _)) => ind,
        None => return false,
    };
    let a = from.to_string();
    Path::new(&a).components().count() - 1 > index
}

#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossMsgs {
    // FIXME: Consider to make this an AMT if we expect
    // a lot of cross-messages to be propagated.
    pub msgs: Vec<CrossMsg>,
}
impl Cbor for CrossMsgs {}

impl CrossMsgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cid(&self) -> anyhow::Result<TCid<TLink<CrossMsgs>>> {
        TCid::new_link(&MemoryBlockstore::new(), &self)
    }

    pub(crate) fn add_msg(&mut self, msg: &CrossMsg) -> anyhow::Result<bool> {
        // FIXME: Consider a more efficient impl.
        if !self.msgs.contains(msg) {
            self.msgs.push(msg.clone());
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::cross::*;
    use std::str::FromStr;

    #[test]
    fn test_is_bottomup() {
        bottom_up("/root/f01", "/root/f01/f02", false);
        bottom_up("/root/f01", "/root", true);
        bottom_up("/root/f01", "/root/f01/f02", false);
        bottom_up("/root/f01", "/root/f02/f02", true);
        bottom_up("/root/f01/f02", "/root/f01/f02", false);
        bottom_up("/root/f01/f02", "/root/f01/f02/f03", false);
    }
    fn bottom_up(a: &str, b: &str, res: bool) {
        assert_eq!(
            is_bottomup(
                &SubnetID::from_str(a).unwrap(),
                &SubnetID::from_str(b).unwrap()
            ),
            res
        );
    }
}
