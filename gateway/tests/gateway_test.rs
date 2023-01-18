use cid::Cid;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::{BURNT_FUNDS_ACTOR_ADDR, REWARD_ACTOR_ADDR};
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::bigint::Zero;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::METHOD_SEND;
use ipc_gateway::Status::{Active, Inactive};
use ipc_gateway::{
    ext, get_bottomup_msg, get_topdown_msg, Checkpoint, CrossMsg, IPCAddress, State, StorableMsg,
    DEFAULT_CHECKPOINT_PERIOD,
};
use ipc_sdk::subnet_id::SubnetID;
use primitives::TCid;
use std::ops::Mul;
use std::str::FromStr;

use crate::harness::*;
mod harness;

#[test]
fn construct() {
    let mut rt = new_runtime();
    let h = new_harness(ROOTNET_ID.clone());
    h.construct_and_verify(&mut rt);
    h.check_state();
}

#[test]
fn register_subnet() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let mut value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Registering an already existing subnet should fail
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::USR_ILLEGAL_ARGUMENT)
        .unwrap();
    h.check_state();
    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);

    // Registering without enough collateral.
    value = TokenAmount::from_atto(10_u64.pow(17));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::USR_ILLEGAL_ARGUMENT)
        .unwrap();
    h.check_state();
    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);

    // Register additional subnet
    value = TokenAmount::from_atto(12_i128.pow(18));
    h.register(&mut rt, &SUBNET_TWO, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 2);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_TWO);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();
}

#[test]
fn add_stake() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Add some stake
    h.add_stake(&mut rt, &shid, &value, ExitCode::OK).unwrap();
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.stake, value.clone().mul(2));

    // Add to unregistered subnet
    h.add_stake(
        &mut rt,
        &SubnetID::new_from_parent(&h.net_name, *SUBNET_TWO),
        &value,
        ExitCode::USR_ILLEGAL_ARGUMENT,
    )
    .unwrap();

    // Add some more stake
    h.add_stake(&mut rt, &shid, &value, ExitCode::OK).unwrap();
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.stake, value.clone().mul(3));

    // Add with zero value
    h.add_stake(
        &mut rt,
        &shid,
        &TokenAmount::zero(),
        ExitCode::USR_ILLEGAL_ARGUMENT,
    )
    .unwrap();
}

#[test]
fn release_stake() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Add some stake
    h.add_stake(&mut rt, &shid, &value, ExitCode::OK).unwrap();
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.stake, value.clone().mul(2));

    // Release some stake
    h.release_stake(&mut rt, &shid, &value, ExitCode::OK)
        .unwrap();
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.stake, value.clone());
    assert_eq!(subnet.status, Active);

    // Release from unregistered subnet
    h.release_stake(
        &mut rt,
        &SubnetID::new_from_parent(&h.net_name, *SUBNET_TWO),
        &value,
        ExitCode::USR_ILLEGAL_ARGUMENT,
    )
    .unwrap();

    // Release with zero value
    h.release_stake(
        &mut rt,
        &shid,
        &TokenAmount::zero(),
        ExitCode::USR_ILLEGAL_ARGUMENT,
    )
    .unwrap();

    // Release enough to inactivate
    rt.set_balance(value.clone().mul(2));
    h.release_stake(
        &mut rt,
        &shid,
        &TokenAmount::from_atto(5u64.pow(17)),
        ExitCode::OK,
    )
    .unwrap();
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.stake, &value - TokenAmount::from_atto(5u64.pow(17)));
    assert_eq!(subnet.status, Inactive);

    // Not enough funds to release
    h.release_stake(&mut rt, &shid, &value, ExitCode::USR_ILLEGAL_STATE)
        .unwrap();

    // Balance is not enough to release
    //, ExitCode::OK).unwrap();
    rt.set_balance(TokenAmount::zero());
    h.release_stake(
        &mut rt,
        &shid,
        &TokenAmount::from_atto(5u64.pow(17)),
        ExitCode::USR_ILLEGAL_STATE,
    )
    .unwrap();
}

#[test]
fn test_kill() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Add some stake
    h.kill(&mut rt, &shid, &value, ExitCode::OK).unwrap();
    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 0);
    assert!(h.get_subnet(&rt, &shid).is_none());
}

#[test]
fn checkpoint_commit() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Commit first checkpoint for first window in first subnet
    let epoch: ChainEpoch = 10;
    rt.set_epoch(epoch);
    let ch = Checkpoint::new(shid.clone(), epoch + 9);

    h.commit_child_check(&mut rt, &shid, &ch, ExitCode::OK, TokenAmount::zero())
        .unwrap();
    let st: State = rt.get_state();
    let commit = st.get_window_checkpoint(rt.store(), epoch).unwrap();
    assert_eq!(commit.epoch(), DEFAULT_CHECKPOINT_PERIOD);
    let child_check = has_childcheck_source(&commit.data.children, &shid).unwrap();
    assert_eq!(&child_check.checks.len(), &1);
    assert_eq!(has_cid(&child_check.checks, &ch.cid()), true);

    // Commit a checkpoint for subnet twice
    h.commit_child_check(
        &mut rt,
        &shid,
        &ch,
        ExitCode::USR_ILLEGAL_ARGUMENT,
        TokenAmount::zero(),
    )
    .unwrap();
    let prev_cid = ch.cid();

    // Append a new checkpoint for the same subnet
    let mut ch = Checkpoint::new(shid.clone(), epoch + 11);
    ch.data.prev_check = TCid::from(prev_cid);
    h.commit_child_check(&mut rt, &shid, &ch, ExitCode::OK, TokenAmount::zero())
        .unwrap();
    let st: State = rt.get_state();
    let commit = st.get_window_checkpoint(rt.store(), epoch).unwrap();
    assert_eq!(commit.epoch(), DEFAULT_CHECKPOINT_PERIOD);
    let child_check = has_childcheck_source(&commit.data.children, &shid).unwrap();
    assert_eq!(&child_check.checks.len(), &2);
    assert_eq!(has_cid(&child_check.checks, &ch.cid()), true);

    // Register second subnet
    h.register(&mut rt, &SUBNET_TWO, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 2);
    let shid_two = SubnetID::new_from_parent(&h.net_name, *SUBNET_TWO);
    let subnet = h.get_subnet(&rt, &shid_two).unwrap();
    assert_eq!(subnet.id, shid_two);
    h.check_state();

    // Trying to commit from the wrong subnet
    let ch = Checkpoint::new(shid.clone(), epoch + 9);
    h.commit_child_check(
        &mut rt,
        &shid_two,
        &ch,
        ExitCode::USR_ILLEGAL_ARGUMENT,
        TokenAmount::zero(),
    )
    .unwrap();

    // Commit first checkpoint for first window in second subnet
    let epoch: ChainEpoch = 10;
    rt.set_epoch(epoch);
    let ch = Checkpoint::new(shid_two.clone(), epoch + 9);

    h.commit_child_check(&mut rt, &shid_two, &ch, ExitCode::OK, TokenAmount::zero())
        .unwrap();
    let st: State = rt.get_state();
    let commit = st.get_window_checkpoint(rt.store(), epoch).unwrap();
    assert_eq!(commit.epoch(), DEFAULT_CHECKPOINT_PERIOD);
    let child_check = has_childcheck_source(&commit.data.children, &shid_two).unwrap();
    assert_eq!(&child_check.checks.len(), &1);
    assert_eq!(has_cid(&child_check.checks, &ch.cid()), true);
}

#[test]
fn checkpoint_crossmsgs() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    // Commit first checkpoint for first window in first subnet
    let epoch: ChainEpoch = 10;
    rt.set_epoch(epoch);
    let mut ch = Checkpoint::new(shid.clone(), epoch + 9);
    // Directed to other subnets
    add_msg_meta(
        &mut ch,
        &shid,
        &SubnetID::from_str("/root/f0102/f0101").unwrap(),
        "rand1".as_bytes().to_vec(),
        TokenAmount::zero(),
    );
    add_msg_meta(
        &mut ch,
        &shid,
        &SubnetID::from_str("/root/f0102/f0102").unwrap(),
        "rand2".as_bytes().to_vec(),
        TokenAmount::zero(),
    );
    // And to this subnet
    add_msg_meta(
        &mut ch,
        &shid,
        &h.net_name,
        "rand1".as_bytes().to_vec(),
        TokenAmount::zero(),
    );
    add_msg_meta(
        &mut ch,
        &shid,
        &h.net_name,
        "rand2".as_bytes().to_vec(),
        TokenAmount::zero(),
    );
    add_msg_meta(
        &mut ch,
        &shid,
        &h.net_name,
        "rand3".as_bytes().to_vec(),
        TokenAmount::zero(),
    );
    // And to other child from the subnet
    add_msg_meta(
        &mut ch,
        &shid,
        &SubnetID::new_from_parent(&h.net_name, Address::new_id(100)),
        "rand1".as_bytes().to_vec(),
        TokenAmount::zero(),
    );

    h.commit_child_check(&mut rt, &shid, &ch, ExitCode::OK, TokenAmount::zero())
        .unwrap();
    let st: State = rt.get_state();
    let commit = st.get_window_checkpoint(rt.store(), epoch).unwrap();
    assert_eq!(commit.epoch(), DEFAULT_CHECKPOINT_PERIOD);
    let child_check = has_childcheck_source(&commit.data.children, &shid).unwrap();
    assert_eq!(&child_check.checks.len(), &1);
    let prev_cid = ch.cid();
    assert_eq!(has_cid(&child_check.checks, &prev_cid), true);

    let crossmsgs = st.bottomup_msg_meta.load(rt.store()).unwrap();
    for item in 0..=2 {
        get_bottomup_msg(&crossmsgs, item).unwrap().unwrap();
    }
    // Check that the ones directed to other subnets are aggregated in message-meta
    for to in vec![
        SubnetID::from_str("/root/f0102/f0101").unwrap(),
        SubnetID::from_str("/root/f0102/f0102").unwrap(),
    ] {
        commit.crossmsg_meta(&h.net_name, &to).unwrap();
    }

    // funding subnet so it has some funds
    let funder = Address::new_id(1001);
    let amount = TokenAmount::from_atto(10_u64.pow(18));
    h.fund(
        &mut rt,
        &funder,
        &shid,
        ExitCode::OK,
        amount.clone(),
        1,
        &amount,
    )
    .unwrap();

    let mut ch = Checkpoint::new(shid.clone(), epoch + 9);
    ch.data.prev_check = TCid::from(prev_cid);
    add_msg_meta(
        &mut ch,
        &shid,
        &SubnetID::from_str("/root/f0102/f0101").unwrap(),
        "rand1".as_bytes().to_vec(),
        TokenAmount::from_atto(5_u64.pow(18)),
    );
    add_msg_meta(
        &mut ch,
        &shid,
        &SubnetID::from_str("/root/f0102/f0102").unwrap(),
        "rand2".as_bytes().to_vec(),
        TokenAmount::from_atto(5_u64.pow(18)),
    );
    h.commit_child_check(
        &mut rt,
        &shid,
        &ch,
        ExitCode::OK,
        2 * TokenAmount::from_atto(5_u64.pow(18)),
    )
    .unwrap();
    let st: State = rt.get_state();
    let commit = st.get_window_checkpoint(rt.store(), epoch).unwrap();
    assert_eq!(commit.epoch(), DEFAULT_CHECKPOINT_PERIOD);
    let child_check = has_childcheck_source(&commit.data.children, &shid).unwrap();
    assert_eq!(&child_check.checks.len(), &2);
    assert_eq!(has_cid(&child_check.checks, &ch.cid()), true);

    let crossmsgs = &st.bottomup_msg_meta.load(rt.store()).unwrap();
    for item in 0..=2 {
        get_bottomup_msg(&crossmsgs, item).unwrap().unwrap();
    }
    for to in vec![
        SubnetID::from_str("/root/f0102/f0101").unwrap(),
        SubnetID::from_str("/root/f0102/f0102").unwrap(),
    ] {
        // verify that some value has been included in metas.
        let meta = commit.crossmsg_meta(&h.net_name, &to).unwrap();
        assert_eq!(true, meta.value > TokenAmount::zero());
    }

    // TODO: More extensive tests?
}

#[test]
fn test_fund() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();

    let st: State = rt.get_state();
    assert_eq!(st.total_subnets, 1);
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);
    let subnet = h.get_subnet(&rt, &shid).unwrap();
    assert_eq!(subnet.id, shid);
    assert_eq!(subnet.stake, value);
    assert_eq!(subnet.circ_supply, TokenAmount::zero());
    assert_eq!(subnet.status, Active);
    h.check_state();

    let funder = Address::new_id(1001);
    let amount = TokenAmount::from_atto(10_u64.pow(18));
    h.fund(
        &mut rt,
        &funder,
        &shid,
        ExitCode::OK,
        amount.clone(),
        1,
        &amount,
    )
    .unwrap();
    let funder = Address::new_id(1002);
    let mut exp_cs = amount.clone() * 2;
    h.fund(
        &mut rt,
        &funder,
        &shid,
        ExitCode::OK,
        amount.clone(),
        2,
        &exp_cs,
    )
    .unwrap();
    exp_cs += amount.clone();
    h.fund(
        &mut rt,
        &funder,
        &shid,
        ExitCode::OK,
        amount.clone(),
        3,
        &exp_cs,
    )
    .unwrap();
    // No funds sent
    h.fund(
        &mut rt,
        &funder,
        &shid,
        ExitCode::USR_ILLEGAL_ARGUMENT,
        TokenAmount::zero(),
        3,
        &exp_cs,
    )
    .unwrap();

    // Subnet doesn't exist
    h.fund(
        &mut rt,
        &funder,
        &SubnetID::new_from_parent(&h.net_name, *SUBNET_TWO),
        ExitCode::USR_ILLEGAL_ARGUMENT,
        TokenAmount::zero(),
        3,
        &exp_cs,
    )
    .unwrap();
}

#[test]
fn test_release() {
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(shid.clone());

    let releaser = Address::new_id(1001);
    // Release funds
    let r_amount = TokenAmount::from_atto(5_u64.pow(18));
    rt.set_balance(2 * r_amount.clone());
    let prev_cid = h
        .release(
            &mut rt,
            &releaser,
            ExitCode::OK,
            r_amount.clone(),
            0,
            &Cid::default(),
        )
        .unwrap();
    h.release(&mut rt, &releaser, ExitCode::OK, r_amount, 1, &prev_cid)
        .unwrap();
}

#[test]
fn test_send_cross() {
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(shid.clone());

    let from = Address::new_id(1001);
    let to = Address::new_id(1002);

    let value = TokenAmount::from_atto(10_u64.pow(18));

    // register subnet
    let reg_value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &reg_value, ExitCode::OK)
        .unwrap();

    // top-down
    let sub = SubnetID::from_str("/root/f0101/f0101").unwrap();
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        1,
        &value,
    )
    .unwrap();
    let sub = SubnetID::from_str("/root/f0101/f0101").unwrap();
    let circ_sup = 2 * &value;
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        2,
        &circ_sup,
    )
    .unwrap();
    let sub = SubnetID::from_str("/root/f0101/f0101/f01002").unwrap();
    let circ_sup = circ_sup.clone() + &value;
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        3,
        &circ_sup,
    )
    .unwrap();

    // bottom-up
    rt.set_balance(3 * &value);
    let sub = SubnetID::from_str("/root/f0102/f0101").unwrap();
    let zero = TokenAmount::zero();
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        0,
        &zero,
    )
    .unwrap();
    let sub = SubnetID::from_str("/root/f0102/f0101").unwrap();
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        1,
        &zero,
    )
    .unwrap();
    let sub = SubnetID::from_str("/root").unwrap();
    h.send_cross(
        &mut rt,
        &from,
        &shid,
        &to,
        sub,
        ExitCode::OK,
        value.clone(),
        0,
        &zero,
    )
    .unwrap();
}

/// This test covers the case where a bottom up cross_msg's target subnet is the SAME as that of
/// the gateway. It should directly commit the message and will not save in postbox.
#[test]
fn test_apply_msg_bu_target_subnet() {
    // ============== Register subnet ==============
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(ROOTNET_ID.clone());

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    let sub = shid.clone();

    // ================ Setup ===============
    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Bottom-Up ===============
    let ff = IPCAddress::new(&sub, &to).unwrap();
    let tt = IPCAddress::new(&ROOTNET_ID, &from).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };
    let sto = tt.raw_addr().unwrap();

    let cid = h
        .apply_cross_execute_only(
            &mut rt,
            value.clone(),
            params,
            Some(Box::new(move |rt| {
                rt.expect_send(
                    sto.clone(),
                    METHOD_SEND,
                    RawBytes::default(),
                    value.clone(),
                    RawBytes::default(),
                    ExitCode::OK,
                );
            })),
        )
        .unwrap();
    assert_eq!(cid.is_none(), true);
}

/// This test covers the case where a bottom up cross_msg's target subnet is NOT the same as that of
/// the gateway. It will save it in the postbox.
#[test]
fn test_apply_msg_bu_not_target_subnet() {
    // ============== Register subnet ==============
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(shid.clone());

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    let sub = shid.clone();

    // ================ Setup ===============
    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Bottom-Up ===============
    let ff = IPCAddress::new(&sub, &to).unwrap();
    let tt = IPCAddress::new(&ROOTNET_ID, &from).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };
    let cid = h
        .apply_cross_execute_only(&mut rt, value.clone(), params, None)
        .unwrap()
        .unwrap();

    // Part 1: test the message is stored in postbox
    let st: State = rt.get_state();
    assert_ne!(tt.subnet().unwrap(), st.network_name);

    // Check 1: `tt` is in `sub1`, which is not in that of `runtime` of gateway, will store in postbox
    let item = st.load_from_postbox(rt.store(), cid.clone()).unwrap();
    assert_eq!(item.owners, Some(vec![ff.clone().raw_addr().unwrap()]));
    let msg = item.cross_msg.msg;
    assert_eq!(msg.to, tt);
    // the nonce should not have changed at all
    assert_eq!(msg.nonce, msg_nonce);
    assert_eq!(msg.value, value);

    // Part 2: Now we propagate from postbox
    // get the original subnet nonce first
    let caller = ff.clone().raw_addr().unwrap();
    let old_state: State = rt.get_state();
    h.propagate(&mut rt, caller, cid.clone(), TokenAmount::zero())
        .unwrap();

    // state should be updated, load again
    let new_state: State = rt.get_state();

    // cid should be removed from postbox
    let r = new_state.load_from_postbox(rt.store(), cid.clone());
    assert_eq!(r.is_err(), true);
    let err = r.unwrap_err();
    assert_eq!(err.to_string(), "cid not found in postbox");
    assert_eq!(new_state.nonce, old_state.nonce + 1);
}

/// This test covers the case where the amount send in the propagate
/// message exceeds the required fee and the remainder is returned
/// to the caller.
#[test]
fn test_propagate_with_remainder() {
    // ============== Register subnet ==============
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(shid.clone());

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    let sub = shid.clone();

    // ================ Setup ===============
    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Bottom-Up ===============
    let ff = IPCAddress::new(&sub, &to).unwrap();
    let tt = IPCAddress::new(&ROOTNET_ID, &from).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };
    let cid = h
        .apply_cross_execute_only(&mut rt, value.clone(), params, None)
        .unwrap()
        .unwrap();

    // Part 1: test the message is stored in postbox
    let st: State = rt.get_state();
    assert_ne!(tt.subnet().unwrap(), st.network_name);

    // Check 1: `tt` is in `sub1`, which is not in that of `runtime` of gateway, will store in postbox
    let item = st.load_from_postbox(rt.store(), cid.clone()).unwrap();
    assert_eq!(item.owners, Some(vec![ff.clone().raw_addr().unwrap()]));
    let msg = item.cross_msg.msg;
    assert_eq!(msg.to, tt);
    // the nonce should not have changed at all
    assert_eq!(msg.nonce, msg_nonce);
    assert_eq!(msg.value, value);

    // Part 2: Now we propagate from postbox
    // get the original subnet nonce first with an
    // excess to check that there is a remainder
    // to be returned
    let caller = ff.clone().raw_addr().unwrap();
    let old_state: State = rt.get_state();
    h.propagate(&mut rt, caller, cid.clone(), value.clone())
        .unwrap();

    // state should be updated, load again
    let new_state: State = rt.get_state();

    // cid should be removed from postbox
    let r = new_state.load_from_postbox(rt.store(), cid.clone());
    assert_eq!(r.is_err(), true);
    let err = r.unwrap_err();
    assert_eq!(err.to_string(), "cid not found in postbox");
    assert_eq!(new_state.nonce, old_state.nonce + 1);
}

/// This test covers the case where a bottom up cross_msg's target subnet is NOT the same as that of
/// the gateway. It would save in postbox. Also, the gateway is the nearest parent, a switch to
/// top down cross msg should occur.
#[test]
fn test_apply_msg_bu_switch_td() {
    // ============== Register subnet ==============
    let parent_sub = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(parent_sub.clone());

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    // ================ Setup ===============
    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Bottom-Up ===============
    let reg_value = TokenAmount::from_atto(10_u64.pow(18));
    // ff: /root/f101/f102
    // to: /root/f101/f103
    // we are executing the message from, harness or the gateway is at: /root/f101
    let ff_sub = SubnetID::new_from_parent(&parent_sub, *SUBNET_TWO);
    let tt_sub = SubnetID::new_from_parent(&parent_sub, *SUBNET_THR);
    h.register(&mut rt, &SUBNET_TWO, &reg_value, ExitCode::OK)
        .unwrap();
    h.register(&mut rt, &SUBNET_THR, &reg_value, ExitCode::OK)
        .unwrap();

    let ff = IPCAddress::new(&ff_sub, &to).unwrap();
    let tt = IPCAddress::new(&tt_sub, &from).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };

    let caller = ff.clone().raw_addr().unwrap();

    // we directly insert message into postbox as we dont really care how it's got stored in queue
    let cid = rt
        .transaction(|st: &mut State, r| {
            Ok(st
                .insert_postbox(
                    r.store(),
                    Some(vec![caller.clone()]),
                    CrossMsg {
                        wrapped: false,
                        msg: params,
                    },
                )
                .unwrap())
        })
        .unwrap();

    let starting_nonce = get_subnet(&rt, &tt.subnet().unwrap().down(&h.net_name).unwrap())
        .unwrap()
        .nonce;

    // now we propagate
    h.propagate(&mut rt, caller, cid.clone(), TokenAmount::zero())
        .unwrap();

    // state should be updated, load again to perform the checks!
    let st: State = rt.get_state();

    // cid should be removed from postbox
    let r = st.load_from_postbox(rt.store(), cid.clone());
    assert_eq!(r.is_err(), true);
    let err = r.unwrap_err();
    assert_eq!(err.to_string(), "cid not found in postbox");

    // the cross msg should have been committed to the next subnet, check this!
    let sub = get_subnet(&rt, &tt.subnet().unwrap().down(&h.net_name).unwrap()).unwrap();
    assert_eq!(sub.nonce, starting_nonce + 1);
    let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
    let msg = get_topdown_msg(&crossmsgs, starting_nonce).unwrap();
    assert_eq!(msg.is_some(), true);
    let msg = msg.unwrap();
    assert_eq!(msg.to, tt);
    // the nonce should not have changed at all
    assert_eq!(msg.nonce, starting_nonce);
    assert_eq!(msg.value, value);
}

/// This test covers the case where the cross_msg's target subnet is the SAME as that of
/// the gateway. It would directly commit the message and will not save in postbox.
#[test]
fn test_apply_msg_tp_target_subnet() {
    // ============== Register subnet ==============
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);
    let (h, mut rt) = setup(shid.clone());

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    let sub = shid.clone();

    // ================ Setup ===============
    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Top-Down ===============
    let ff = IPCAddress::new(&ROOTNET_ID, &from).unwrap();
    let tt = IPCAddress::new(&sub, &to).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };
    let sto = tt.raw_addr().unwrap();
    let v = value.clone();
    let cid = h
        .apply_cross_execute_only(
            &mut rt,
            value.clone(),
            params,
            Some(Box::new(move |rt| {
                // expect to send reward message
                rt.expect_send(
                    *REWARD_ACTOR_ADDR,
                    ext::reward::EXTERNAL_FUNDING_METHOD,
                    RawBytes::serialize(ext::reward::FundingParams {
                        addr: *ACTOR,
                        value: v.clone(),
                    })
                    .unwrap(),
                    TokenAmount::zero(),
                    RawBytes::default(),
                    ExitCode::OK,
                );
                rt.expect_send(
                    sto.clone(),
                    METHOD_SEND,
                    RawBytes::default(),
                    v.clone(),
                    RawBytes::default(),
                    ExitCode::OK,
                );
            })),
        )
        .unwrap();
    assert_eq!(cid.is_none(), true);
}

/// This test covers the case where the cross_msg's target subnet is not the same as that of
/// the gateway.
#[test]
fn test_apply_msg_tp_not_target_subnet() {
    // ============== Define Parameters ==============
    // gateway: /root/sub1
    let shid = SubnetID::new_from_parent(&ROOTNET_ID, *SUBNET_ONE);

    let from = Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    let to = Address::new_bls(&[4; fvm_shared::address::BLS_PUB_LEN]).unwrap();

    // /root/sub1/sub1
    let sub = SubnetID::new_from_parent(&shid, *SUBNET_ONE);

    // ================ Setup ===============
    let reg_value = TokenAmount::from_atto(10_u64.pow(18));
    let (h, mut rt) = setup(shid.clone());
    h.register(&mut rt, &SUBNET_ONE, &reg_value, ExitCode::OK)
        .unwrap();
    // add some circulating supply to subnets
    let funder = Address::new_id(1002);
    h.fund(
        &mut rt,
        &funder,
        &sub,
        ExitCode::OK,
        reg_value.clone(),
        1,
        &reg_value,
    )
    .unwrap();

    let value = TokenAmount::from_atto(10_u64.pow(17));

    // ================= Top-Down ===============
    let ff = IPCAddress::new(&ROOTNET_ID, &from).unwrap();
    let tt = IPCAddress::new(&sub, &to).unwrap();
    let msg_nonce = 0;

    // Only system code is allowed to this method
    let params = StorableMsg {
        to: tt.clone(),
        from: ff.clone(),
        method: METHOD_SEND,
        value: value.clone(),
        params: RawBytes::default(),
        nonce: msg_nonce,
    };
    let v = value.clone();
    // cid is expected, should not be None
    let cid = h
        .apply_cross_execute_only(
            &mut rt,
            value.clone(),
            params,
            Some(Box::new(move |rt| {
                // expect to send reward message
                rt.expect_send(
                    *REWARD_ACTOR_ADDR,
                    ext::reward::EXTERNAL_FUNDING_METHOD,
                    RawBytes::serialize(ext::reward::FundingParams {
                        addr: *ACTOR,
                        value: v.clone(),
                    })
                    .unwrap(),
                    TokenAmount::zero(),
                    RawBytes::default(),
                    ExitCode::OK,
                );
            })),
        )
        .unwrap()
        .unwrap();

    // Part 1: test the message is stored in postbox
    let st: State = rt.get_state();
    assert_ne!(tt.subnet().unwrap(), st.network_name);

    // Check 1: `tt` is in `sub1`, which is not in that of `runtime` of gateway, will store in postbox
    let item = st.load_from_postbox(rt.store(), cid.clone()).unwrap();
    assert_eq!(item.owners, Some(vec![ff.clone().raw_addr().unwrap()]));
    let msg = item.cross_msg.msg;
    assert_eq!(msg.to, tt);
    // the nonce should not have changed at all
    assert_eq!(msg.nonce, msg_nonce);
    assert_eq!(msg.value, value);

    // Part 2: Now we propagate from postbox
    // get the original subnet nonce first
    let starting_nonce = get_subnet(&rt, &tt.subnet().unwrap().down(&h.net_name).unwrap())
        .unwrap()
        .nonce;
    let caller = ff.clone().raw_addr().unwrap();
    h.propagate(&mut rt, caller, cid.clone(), TokenAmount::zero())
        .unwrap();

    // state should be updated, load again
    let st: State = rt.get_state();

    // cid should be removed from postbox
    let r = st.load_from_postbox(rt.store(), cid.clone());
    assert_eq!(r.is_err(), true);
    let err = r.unwrap_err();
    assert_eq!(err.to_string(), "cid not found in postbox");

    // the cross msg should have been committed to the next subnet, check this!
    let sub = get_subnet(&rt, &tt.subnet().unwrap().down(&h.net_name).unwrap()).unwrap();
    assert_eq!(sub.nonce, starting_nonce + 1);
    let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
    let msg = get_topdown_msg(&crossmsgs, starting_nonce).unwrap();
    assert_eq!(msg.is_some(), true);
    let msg = msg.unwrap();
    assert_eq!(msg.to, tt);
    // the nonce should not have changed at all
    assert_eq!(msg.nonce, starting_nonce);
    assert_eq!(msg.value, value);
}

#[test]
fn test_apply_msg_match_target_subnet() {
    let (h, mut rt) = setup_root();

    // Register a subnet with 1FIL collateral
    let value = TokenAmount::from_atto(10_u64.pow(18));
    h.register(&mut rt, &SUBNET_ONE, &value, ExitCode::OK)
        .unwrap();
    let shid = SubnetID::new_from_parent(&h.net_name, *SUBNET_ONE);

    // inject some funds
    let funder_id = Address::new_id(1001);
    let funder = IPCAddress::new(
        &shid.parent().unwrap(),
        &Address::new_bls(&[3; fvm_shared::address::BLS_PUB_LEN]).unwrap(),
    )
    .unwrap();
    let amount = TokenAmount::from_atto(10_u64.pow(18));
    h.fund(
        &mut rt,
        &funder_id,
        &shid,
        ExitCode::OK,
        amount.clone(),
        1,
        &amount,
    )
    .unwrap();

    // Apply fund messages
    for i in 0..5 {
        h.apply_cross_msg(
            &mut rt,
            &funder,
            &funder,
            value.clone(),
            i,
            i,
            ExitCode::OK,
            false,
        )
        .unwrap();
    }
    // Apply release messages
    let from = IPCAddress::new(&shid, &BURNT_FUNDS_ACTOR_ADDR).unwrap();
    // with the same nonce
    for _ in 0..5 {
        h.apply_cross_msg(
            &mut rt,
            &from,
            &funder,
            value.clone(),
            0,
            0,
            ExitCode::OK,
            false,
        )
        .unwrap();
    }
    // with increasing nonce
    for i in 0..5 {
        h.apply_cross_msg(
            &mut rt,
            &from,
            &funder,
            value.clone(),
            i,
            i,
            ExitCode::OK,
            false,
        )
        .unwrap();
    }

    // trying to apply non-subsequent nonce.
    h.apply_cross_msg(
        &mut rt,
        &from,
        &funder,
        value.clone(),
        10,
        0,
        ExitCode::USR_ILLEGAL_STATE,
        false,
    )
    .unwrap();
    // trying already applied nonce
    h.apply_cross_msg(
        &mut rt,
        &from,
        &funder,
        value.clone(),
        0,
        0,
        ExitCode::USR_ILLEGAL_STATE,
        false,
    )
    .unwrap();

    // TODO: Trying to release over circulating supply
}

#[test]
fn test_noop() {
    // TODO: Implement tests of what happens if the application
}
