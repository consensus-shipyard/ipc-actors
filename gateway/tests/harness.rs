use anyhow::anyhow;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fil_actors_runtime::builtin::HAMT_BIT_WIDTH;
use fil_actors_runtime::deserialize_block;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::test_utils::expect_abort;
use fil_actors_runtime::test_utils::{
    MockRuntime, ACCOUNT_ACTOR_CODE_ID, INIT_ACTOR_CODE_ID, MULTISIG_ACTOR_CODE_ID,
    SUBNET_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID,
};
use fil_actors_runtime::{
    make_map_with_root_and_bitwidth, ActorError, Map, BURNT_FUNDS_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fil_actors_runtime::{Array, INIT_ACTOR_ADDR};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use fvm_shared::bigint::bigint_ser::BigIntDe;
use fvm_shared::bigint::Zero;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::MethodNum;
use fvm_shared::METHOD_SEND;
use ipc_gateway::checkpoint::ChildCheck;
use ipc_gateway::{
    ext, get_topdown_msg, is_bottomup, Actor, ApplyMsgParams, Checkpoint, ConstructorParams,
    CrossMsg, CrossMsgMeta, CrossMsgParams, CrossMsgs, FundParams, IPCAddress, IPCMsgType, Method,
    PropagateParams, State, StorableMsg, Subnet, SubnetID, CROSSMSG_AMT_BITWIDTH, CROSS_MSG_FEE,
    DEFAULT_CHECKPOINT_PERIOD, MAX_NONCE, MIN_COLLATERAL_AMOUNT,
};
use ipc_gateway::{CronCheckpoint, SUBNET_ACTOR_REWARD_METHOD};
use ipc_sdk::ValidatorSet;
use lazy_static::lazy_static;
use primitives::{TCid, TCidContent};
use std::str::FromStr;

lazy_static! {
    pub static ref ROOTNET_ID: SubnetID =
        SubnetID::new_from_parent(&SubnetID::from_str("/root").unwrap(), Address::new_id(0));
    pub static ref SUBNET_ONE: Address = Address::new_id(101);
    pub static ref SUBNET_TWO: Address = Address::new_id(102);
    pub static ref SUBNET_THR: Address = Address::new_id(103);
    pub static ref TEST_BLS: Address =
        Address::new_bls(&[1; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    pub static ref ACTOR: Address = Address::new_actor("actor".as_bytes());
    pub static ref SIG_TYPES: Vec<Cid> = vec![*ACCOUNT_ACTOR_CODE_ID, *MULTISIG_ACTOR_CODE_ID];
    pub static ref DEFAULT_CRON_PERIOD: ChainEpoch = 20;
    pub static ref DEFAULT_GENESIS_EPOCH: ChainEpoch = 1;
}

pub fn new_runtime() -> MockRuntime {
    MockRuntime {
        receiver: *ACTOR,
        caller: SYSTEM_ACTOR_ADDR,
        caller_type: *SYSTEM_ACTOR_CODE_ID,
        ..Default::default()
    }
}

pub fn new_harness(id: SubnetID) -> Harness {
    Harness { net_name: id }
}

pub fn setup_root() -> (Harness, MockRuntime) {
    setup(ROOTNET_ID.clone())
}

pub fn setup(id: SubnetID) -> (Harness, MockRuntime) {
    let mut rt = new_runtime();
    let h = new_harness(id);
    h.construct(&mut rt);
    (h, rt)
}

#[allow(dead_code)]
pub struct Harness {
    pub net_name: SubnetID,
}

impl Harness {
    pub fn construct(&self, rt: &mut MockRuntime) {
        rt.expect_validate_caller_addr(vec![INIT_ACTOR_ADDR]);
        let params = ConstructorParams {
            network_name: self.net_name.to_string(),
            checkpoint_period: 10,
            cron_period: *DEFAULT_CRON_PERIOD,
            genesis_epoch: *DEFAULT_GENESIS_EPOCH,
        };
        rt.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);
        rt.call::<Actor>(
            Method::Constructor as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
    }

    pub fn construct_and_verify(&self, rt: &mut MockRuntime) {
        self.construct(rt);

        let st: State = rt.get_state();
        let store = &rt.store;

        let empty_bottomup_array = Array::<(), _>::new_with_bit_width(store, CROSSMSG_AMT_BITWIDTH)
            .flush()
            .unwrap();

        assert_eq!(st.network_name, self.net_name);
        assert_eq!(st.min_stake, TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        assert_eq!(st.check_period, DEFAULT_CHECKPOINT_PERIOD);
        assert_eq!(st.applied_bottomup_nonce, MAX_NONCE);
        assert_eq!(st.bottomup_msg_meta.cid(), empty_bottomup_array);
        assert_eq!(st.cron_period, *DEFAULT_CRON_PERIOD);
        assert_eq!(st.genesis_epoch, *DEFAULT_GENESIS_EPOCH);
        verify_empty_map(rt, st.subnets.cid());
        verify_empty_map(rt, st.checkpoints.cid());
        verify_empty_map(rt, st.check_msg_registry.cid());
    }

    pub fn register(
        &self,
        rt: &mut MockRuntime,
        subnet_addr: &Address,
        value: &TokenAmount,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SUBNET_ACTOR_CODE_ID, *subnet_addr);
        rt.set_value(value.clone());
        rt.set_balance(value.clone());
        rt.expect_validate_caller_any();

        if code != ExitCode::OK {
            expect_abort(code, rt.call::<Actor>(Method::Register as MethodNum, None));
            rt.verify();
            return Ok(());
        }

        let register_ret = SubnetID::new_from_parent(&self.net_name, *subnet_addr);
        let ret = rt
            .call::<Actor>(Method::Register as MethodNum, None)
            .unwrap();
        rt.verify();
        let ret: SubnetID = deserialize_block(ret).unwrap();
        assert_eq!(ret, register_ret);
        Ok(())
    }

    pub fn add_stake(
        &self,
        rt: &mut MockRuntime,
        id: &SubnetID,
        value: &TokenAmount,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SUBNET_ACTOR_CODE_ID, id.subnet_actor());
        rt.set_value(value.clone());
        rt.expect_validate_caller_any();

        if code != ExitCode::OK {
            expect_abort(code, rt.call::<Actor>(Method::AddStake as MethodNum, None));
            rt.verify();
            return Ok(());
        }

        rt.call::<Actor>(Method::AddStake as MethodNum, None)
            .unwrap();
        rt.verify();

        Ok(())
    }

    pub fn release_stake(
        &self,
        rt: &mut MockRuntime,
        id: &SubnetID,
        value: &TokenAmount,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SUBNET_ACTOR_CODE_ID, id.subnet_actor());
        rt.expect_validate_caller_any();

        let params = FundParams {
            value: value.clone(),
        };

        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::ReleaseStake as MethodNum,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }

        rt.expect_send(
            id.subnet_actor(),
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::OK,
        );
        rt.call::<Actor>(
            Method::ReleaseStake as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
        rt.verify();

        Ok(())
    }

    pub fn kill(
        &self,
        rt: &mut MockRuntime,
        id: &SubnetID,
        release_value: &TokenAmount,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SUBNET_ACTOR_CODE_ID, id.subnet_actor());
        rt.expect_validate_caller_any();

        if code != ExitCode::OK {
            expect_abort(code, rt.call::<Actor>(Method::Kill as MethodNum, None));
            rt.verify();
            return Ok(());
        }

        rt.expect_send(
            id.subnet_actor(),
            METHOD_SEND,
            None,
            release_value.clone(),
            None,
            ExitCode::OK,
        );
        rt.call::<Actor>(Method::Kill as MethodNum, None).unwrap();
        rt.verify();

        Ok(())
    }

    pub fn commit_child_check(
        &self,
        rt: &mut MockRuntime,
        id: &SubnetID,
        ch: &Checkpoint,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SUBNET_ACTOR_CODE_ID, id.subnet_actor());
        rt.expect_validate_caller_any();

        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::CommitChildCheckpoint as MethodNum,
                    IpldBlock::serialize_cbor(&ch).unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }
        rt.call::<Actor>(
            Method::CommitChildCheckpoint as MethodNum,
            IpldBlock::serialize_cbor(&ch).unwrap(),
        )
        .unwrap();
        rt.verify();

        Ok(())
    }

    pub fn fund(
        &self,
        rt: &mut MockRuntime,
        funder: &Address,
        id: &SubnetID,
        code: ExitCode,
        value: TokenAmount,
        expected_nonce: u64,
        expected_circ_sup: &TokenAmount,
    ) -> Result<(), ActorError> {
        rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, *funder);
        rt.expect_validate_caller_type(SIG_TYPES.clone());

        // set value and include the cross_msg_fee
        set_rt_value_with_cross_fee(rt, &value);

        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::Fund as MethodNum,
                    IpldBlock::serialize_cbor(&id).unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }

        rt.expect_send(
            *funder,
            ext::account::PUBKEY_ADDRESS_METHOD,
            None,
            TokenAmount::zero(),
            IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
            ExitCode::OK,
        );
        rt.expect_send(
            id.subnet_actor(),
            SUBNET_ACTOR_REWARD_METHOD,
            None,
            CROSS_MSG_FEE.clone(),
            None,
            ExitCode::OK,
        );
        rt.call::<Actor>(
            Method::Fund as MethodNum,
            IpldBlock::serialize_cbor(&id).unwrap(),
        )
        .unwrap();
        rt.verify();

        let sub = self.get_subnet(rt, id).unwrap();
        let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
        let msg = get_topdown_msg(&crossmsgs, expected_nonce - 1)
            .unwrap()
            .unwrap();
        assert_eq!(&sub.circ_supply, expected_circ_sup);
        assert_eq!(sub.nonce, expected_nonce);
        let from = IPCAddress::new(&self.net_name, &*TEST_BLS).unwrap();
        let to = IPCAddress::new(&id, &TEST_BLS).unwrap();
        assert_eq!(msg.from, from);
        assert_eq!(msg.to, to);
        assert_eq!(msg.nonce, expected_nonce - 1);
        assert_eq!(msg.value, value);

        Ok(())
    }

    pub fn release(
        &self,
        rt: &mut MockRuntime,
        releaser: &Address,
        code: ExitCode,
        value: TokenAmount,
        expected_nonce: u64,
        prev_meta: &Cid,
        expected_fee: TokenAmount,
    ) -> Result<Cid, ActorError> {
        rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, *releaser);
        rt.expect_validate_caller_type(SIG_TYPES.clone());
        // set value and include the cross_msg_fee
        set_rt_value_with_cross_fee(rt, &value);

        if code != ExitCode::OK {
            expect_abort(code, rt.call::<Actor>(Method::Release as MethodNum, None));
            rt.verify();
            return Ok(Cid::default());
        }

        rt.expect_send(
            *releaser,
            ext::account::PUBKEY_ADDRESS_METHOD,
            None,
            TokenAmount::zero(),
            IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
            ExitCode::OK,
        );
        rt.expect_send(
            BURNT_FUNDS_ACTOR_ADDR,
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::OK,
        );
        rt.call::<Actor>(Method::Release as MethodNum, None)
            .unwrap();
        rt.verify();

        let st: State = rt.get_state();

        let parent = &self.net_name.parent().unwrap();
        let from = IPCAddress::new(&self.net_name, &BURNT_FUNDS_ACTOR_ADDR).unwrap();
        let to = IPCAddress::new(&parent, &TEST_BLS).unwrap();
        rt.set_epoch(0);
        let ch = st.get_window_checkpoint(rt.store(), 0).unwrap();
        let chmeta = ch.cross_msgs();

        let cross_reg = st.check_msg_registry.load(rt.store()).unwrap();
        let meta = get_cross_msgs(&cross_reg, &chmeta.msgs_cid.cid())
            .unwrap()
            .unwrap();
        let msg = meta.msgs[expected_nonce as usize].clone();

        assert_eq!(meta.msgs.len(), (expected_nonce + 1) as usize);
        assert_eq!(msg.msg.from, from);
        assert_eq!(msg.msg.to, to);
        assert_eq!(msg.msg.nonce, expected_nonce);
        assert_eq!(msg.msg.value, value);

        if prev_meta != &Cid::default() {
            match get_cross_msgs(&cross_reg, &prev_meta).unwrap() {
                Some(_) => panic!("previous meta should have been removed"),
                None => {}
            }
        }

        Ok(chmeta.msgs_cid.cid())
    }

    pub fn send_cross(
        &self,
        rt: &mut MockRuntime,
        from: &Address,
        source_sub: &SubnetID,
        to: &Address,
        sub: SubnetID,
        code: ExitCode,
        value: TokenAmount,
        nonce: u64,
        expected_circ_sup: &TokenAmount,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SYSTEM_ACTOR_CODE_ID, SYSTEM_ACTOR_ADDR);
        rt.expect_validate_caller_not_type(SIG_TYPES.clone());

        // set value and include the cross_msg_fee
        set_rt_value_with_cross_fee(rt, &value);

        let msg = StorableMsg {
            from: IPCAddress::new(source_sub, from).unwrap(),
            to: IPCAddress::new(&sub, to).unwrap(),
            nonce,
            method: METHOD_SEND,
            params: RawBytes::default(),
            value: value.clone() + &*CROSS_MSG_FEE,
        };
        let dest = sub.clone();
        let cross = CrossMsg {
            msg,
            wrapped: false,
        };
        let params = CrossMsgParams {
            destination: sub,
            cross_msg: cross,
        };
        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::SendCross as MethodNum,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }

        let is_bu = is_bottomup(&self.net_name, &dest);
        if is_bu {
            rt.expect_send(
                BURNT_FUNDS_ACTOR_ADDR,
                METHOD_SEND,
                None,
                value.clone(),
                None,
                ExitCode::OK,
            );
        } else {
            // if top-down, reward is distributed
            rt.expect_send(
                dest.down(&self.net_name).unwrap().subnet_actor(),
                SUBNET_ACTOR_REWARD_METHOD,
                None,
                CROSS_MSG_FEE.clone(),
                None,
                ExitCode::OK,
            );
        }
        rt.call::<Actor>(
            Method::SendCross as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
        rt.verify();

        let st: State = rt.get_state();
        if is_bu {
            let from = IPCAddress::new(&self.net_name, &SYSTEM_ACTOR_ADDR).unwrap();
            let to = IPCAddress::new(&dest, &to).unwrap();
            rt.set_epoch(0);
            let ch = st.get_window_checkpoint(rt.store(), 0).unwrap();
            let chmeta = ch.cross_msgs();

            let cross_reg = st.check_msg_registry.load(rt.store()).unwrap();
            let meta = get_cross_msgs(&cross_reg, &chmeta.unwrap().msgs_cid.cid())
                .unwrap()
                .unwrap();
            let msg = meta.msgs[nonce as usize].clone();

            assert_eq!(meta.msgs.len(), (nonce + 1) as usize);
            assert_eq!(msg.msg.from, from);
            assert_eq!(msg.msg.to, to);
            assert_eq!(msg.msg.nonce, nonce);
            assert_eq!(msg.msg.value, value);
        } else {
            // top-down
            let sub = self
                .get_subnet(rt, &dest.down(&self.net_name).unwrap())
                .unwrap();
            let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
            let msg = get_topdown_msg(&crossmsgs, nonce - 1).unwrap().unwrap();
            assert_eq!(&sub.circ_supply, expected_circ_sup);
            assert_eq!(sub.nonce, nonce);
            let from = IPCAddress::new(&self.net_name, &SYSTEM_ACTOR_ADDR).unwrap();
            let to = IPCAddress::new(&dest, &to).unwrap();
            assert_eq!(msg.from, from);
            assert_eq!(msg.to, to);
            assert_eq!(msg.nonce, nonce - 1);
            assert_eq!(msg.value, value);
        }

        Ok(())
    }

    pub fn apply_cross_execute_only(
        &self,
        rt: &mut MockRuntime,
        balance: TokenAmount,
        params: StorableMsg,
        append_expected_send: Option<Box<dyn Fn(&mut MockRuntime)>>,
    ) -> Result<Option<Cid>, ActorError> {
        rt.set_caller(*SYSTEM_ACTOR_CODE_ID, SYSTEM_ACTOR_ADDR);
        rt.expect_validate_caller_addr(vec![SYSTEM_ACTOR_ADDR.clone()]);
        rt.set_balance(balance);

        if let Some(f) = append_expected_send {
            f(rt)
        }
        let cid_blk = rt.call::<Actor>(
            Method::ApplyMessage as MethodNum,
            IpldBlock::serialize_cbor(&ApplyMsgParams {
                cross_msg: CrossMsg {
                    msg: params.clone(),
                    wrapped: false,
                },
            })?,
        )?;
        rt.verify();

        let cid: RawBytes = deserialize_block(cid_blk).unwrap();
        if cid.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Cid::try_from(cid.to_vec().as_slice()).unwrap()))
        }
    }

    pub fn propagate(
        &self,
        rt: &mut MockRuntime,
        owner: Address,
        cid: Cid,
        msg_value: &TokenAmount,
        excess: TokenAmount,
    ) -> Result<(), ActorError> {
        rt.set_caller(Default::default(), owner);
        rt.expect_validate_caller_any();
        rt.set_balance(msg_value.clone() + CROSS_MSG_FEE.clone() + excess.clone());
        rt.set_received(CROSS_MSG_FEE.clone() + excess.clone());

        if excess > TokenAmount::zero() {
            rt.expect_send(owner, METHOD_SEND, None, excess.clone(), None, ExitCode::OK);
        }

        rt.call::<Actor>(
            Method::Propagate as MethodNum,
            IpldBlock::serialize_cbor(&PropagateParams { postbox_cid: cid })?,
        )?;
        rt.verify();

        Ok(())
    }

    pub fn apply_cross_msg(
        &self,
        rt: &mut MockRuntime,
        from: &IPCAddress,
        to: &IPCAddress,
        value: TokenAmount,
        msg_nonce: u64,
        td_nonce: u64,
        code: ExitCode,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SYSTEM_ACTOR_CODE_ID, SYSTEM_ACTOR_ADDR);
        rt.expect_validate_caller_addr(vec![SYSTEM_ACTOR_ADDR.clone()]);

        rt.set_balance(value.clone());
        let params = StorableMsg {
            to: to.clone(),
            from: from.clone(),
            method: METHOD_SEND,
            value: value.clone(),
            params: RawBytes::default(),
            nonce: msg_nonce,
        };

        let st: State = rt.get_state();
        let sto = params.to.subnet().unwrap();
        let rto = to.raw_addr().unwrap();

        // if expected code is not ok
        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::ApplyMessage as MethodNum,
                    IpldBlock::serialize_cbor(&ApplyMsgParams {
                        cross_msg: CrossMsg {
                            msg: params.clone(),
                            wrapped: false,
                        },
                    })
                    .unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }

        if params.apply_type(&st.network_name).unwrap() == IPCMsgType::BottomUp {
            if sto == st.network_name {
                rt.expect_send(
                    rto,
                    METHOD_SEND,
                    None,
                    params.value.clone(),
                    None,
                    ExitCode::OK,
                );
            }

            rt.call::<Actor>(
                Method::ApplyMessage as MethodNum,
                IpldBlock::serialize_cbor(&ApplyMsgParams {
                    cross_msg: CrossMsg {
                        msg: params.clone(),
                        wrapped: false,
                    },
                })
                .unwrap(),
            )?;
            rt.verify();
            let st: State = rt.get_state();
            assert_eq!(st.applied_bottomup_nonce, msg_nonce);
        } else {
            if sto == st.network_name {
                rt.expect_send(
                    rto,
                    METHOD_SEND,
                    None,
                    params.value.clone(),
                    None,
                    ExitCode::OK,
                );
            }
            let cid_blk = rt.call::<Actor>(
                Method::ApplyMessage as MethodNum,
                IpldBlock::serialize_cbor(&ApplyMsgParams {
                    cross_msg: CrossMsg {
                        msg: params.clone(),
                        wrapped: false,
                    },
                })
                .unwrap(),
            )?;
            rt.verify();
            let st: State = rt.get_state();

            if sto != st.network_name {
                let sub = self
                    .get_subnet(rt, &sto.down(&self.net_name).unwrap())
                    .unwrap();
                assert_eq!(sub.nonce, td_nonce);
                let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
                let msg = get_topdown_msg(&crossmsgs, td_nonce).unwrap();
                assert_eq!(msg.is_none(), true);

                let cid: RawBytes = deserialize_block(cid_blk).unwrap();
                let cid_ref = cid.to_vec();
                let item = st
                    .load_from_postbox(rt.store(), Cid::try_from(cid_ref.as_slice()).unwrap())
                    .unwrap();
                assert_eq!(item.owners, Some(vec![from.clone().raw_addr().unwrap()]));
                let msg = item.cross_msg.msg;
                assert_eq!(&msg.to, to);
                assert_eq!(msg.nonce, msg_nonce);
                assert_eq!(msg.value, value);
            } else {
                assert_eq!(st.applied_topdown_nonce, msg_nonce + 1);
            }
        }
        Ok(())
    }

    pub fn check_state(&self) {
        // TODO: https://github.com/filecoin-project/builtin-actors/issues/44
    }

    pub fn get_subnet(&self, rt: &MockRuntime, id: &SubnetID) -> Option<Subnet> {
        get_subnet(rt, id)
    }

    pub fn set_membership(
        &self,
        rt: &mut MockRuntime,
        validator_set: ValidatorSet,
    ) -> Result<(), ActorError> {
        rt.set_caller(*SYSTEM_ACTOR_CODE_ID, SYSTEM_ACTOR_ADDR);
        rt.expect_validate_caller_addr(vec![SYSTEM_ACTOR_ADDR]);

        rt.call::<Actor>(
            Method::SetMembership as MethodNum,
            IpldBlock::serialize_cbor(&validator_set).unwrap(),
        )
        .unwrap();
        rt.verify();

        Ok(())
    }

    pub fn submit_cron(
        &self,
        rt: &mut MockRuntime,
        submitter: Address,
        checkpoint: CronCheckpoint,
    ) -> Result<(), ActorError> {
        rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, submitter);
        rt.expect_validate_caller_type(SIG_TYPES.clone());

        rt.call::<Actor>(
            Method::SubmitCron as MethodNum,
            IpldBlock::serialize_cbor(&checkpoint).unwrap(),
        )?;

        rt.verify();

        Ok(())
    }
}

pub fn get_subnet(rt: &MockRuntime, id: &SubnetID) -> Option<Subnet> {
    let st: State = rt.get_state();
    let subnets = st.subnets.load(rt.store()).unwrap();
    subnets.get(&id.to_bytes()).unwrap().cloned()
}

pub fn verify_empty_map(rt: &MockRuntime, key: Cid) {
    let map =
        make_map_with_root_and_bitwidth::<_, BigIntDe>(&key, &rt.store, HAMT_BIT_WIDTH).unwrap();
    map.for_each(|_key, _val| panic!("expected no keys"))
        .unwrap();
}

pub fn has_childcheck_source<'a>(
    children: &'a Vec<ChildCheck>,
    source: &SubnetID,
) -> Option<&'a ChildCheck> {
    children.iter().find(|m| source == &m.source)
}

pub fn has_cid<'a, T: TCidContent>(children: &'a Vec<TCid<T>>, cid: &Cid) -> bool {
    children.iter().any(|c| c.cid() == *cid)
}

pub fn get_cross_msgs<'m, BS: Blockstore>(
    registry: &'m Map<BS, CrossMsgs>,
    cid: &Cid,
) -> anyhow::Result<Option<&'m CrossMsgs>> {
    registry
        .get(&cid.to_bytes())
        .map_err(|e| anyhow!("error getting fross messages: {:?}", e))
}

fn set_rt_value_with_cross_fee(rt: &mut MockRuntime, value: &TokenAmount) {
    rt.set_value(if value.clone() != TokenAmount::zero() {
        value.clone() + &*CROSS_MSG_FEE
    } else {
        value.clone()
    });
}
