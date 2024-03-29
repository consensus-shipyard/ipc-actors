use cid::Cid;
use fil_actors_runtime::builtin::HAMT_BIT_WIDTH;
use fil_actors_runtime::deserialize_block;
use fil_actors_runtime::runtime::fvm::PUBLIC_RESOLVE_ADDRESS_METHOD;
use fil_actors_runtime::runtime::Runtime;
use fil_actors_runtime::test_utils::expect_abort;
use fil_actors_runtime::test_utils::{
    MockRuntime, ACCOUNT_ACTOR_CODE_ID, INIT_ACTOR_CODE_ID, MULTISIG_ACTOR_CODE_ID,
    SUBNET_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID,
};
use fil_actors_runtime::INIT_ACTOR_ADDR;
use fil_actors_runtime::{
    make_map_with_root_and_bitwidth, ActorError, BURNT_FUNDS_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::{Address, Protocol};
use fvm_shared::bigint::bigint_ser::BigIntDe;
use fvm_shared::bigint::Zero;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::MethodNum;
use fvm_shared::METHOD_SEND;
use ipc_gateway::checkpoint::ChildCheck;
use ipc_gateway::{
    get_topdown_msg, Actor, AmountParams, BottomUpCheckpoint, ConstructorParams, CrossMsg,
    CrossMsgParams, FundParams, IPCAddress, InitGenesisEpoch, Method, PropagateParams,
    ReleaseParams, State, StorableMsg, Subnet, SubnetID, TopDownCheckpoint, CROSS_MSG_FEE,
    DEFAULT_CHECKPOINT_PERIOD, MIN_COLLATERAL_AMOUNT, SUBNET_ACTOR_REWARD_METHOD,
};
use ipc_sdk::cross::is_bottomup;
use ipc_sdk::ValidatorSet;
use lazy_static::lazy_static;
use primitives::{TCid, TCidContent};

lazy_static! {
    pub static ref SUBNET_ONE: Address = Address::new_id(101);
    pub static ref SUBNET_TWO: Address = Address::new_id(102);
    pub static ref SUBNET_THR: Address = Address::new_id(103);
    pub static ref TEST_BLS: Address =
        Address::new_bls(&[1; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    pub static ref ACTOR: Address = Address::new_actor("actor".as_bytes());
    pub static ref SIG_TYPES: Vec<Cid> = vec![*ACCOUNT_ACTOR_CODE_ID, *MULTISIG_ACTOR_CODE_ID];
    pub static ref DEFAULT_TOPDOWN_PERIOD: ChainEpoch = 20;
    pub static ref DEFAULT_GENESIS_EPOCH: ChainEpoch = 1;
    pub static ref ROOTNET_ID: SubnetID = SubnetID::new(123, vec![]);
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
    let h = new_harness(id.clone());
    h.construct(&mut rt);
    // the rootnet doesn't need to be explicitly
    // initialized.
    if id != *ROOTNET_ID {
        h.initialize(&mut rt);
    }
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
            bottomup_check_period: 10,
            topdown_check_period: *DEFAULT_TOPDOWN_PERIOD,
        };
        rt.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);
        rt.call::<Actor>(
            Method::Constructor as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
    }

    pub fn initialize(&self, rt: &mut MockRuntime) {
        rt.expect_validate_caller_addr(vec![SYSTEM_ACTOR_ADDR]);
        let params = InitGenesisEpoch {
            genesis_epoch: *DEFAULT_GENESIS_EPOCH,
        };
        rt.set_caller(*SYSTEM_ACTOR_CODE_ID, SYSTEM_ACTOR_ADDR);
        rt.call::<Actor>(
            Method::InitGenesisEpoch as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
        let st: State = rt.get_state();
        assert_eq!(st.initialized, true);
        assert_eq!(
            st.topdown_checkpoint_voting.genesis_epoch,
            DEFAULT_GENESIS_EPOCH.clone()
        );
    }

    pub fn construct_and_verify(&self, rt: &mut MockRuntime) {
        self.construct(rt);

        let st: State = rt.get_state();

        assert_eq!(st.network_name, self.net_name);
        assert_eq!(st.min_stake, TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        assert_eq!(st.bottomup_check_period, DEFAULT_CHECKPOINT_PERIOD);
        assert_eq!(
            st.topdown_checkpoint_voting.submission_period(),
            *DEFAULT_TOPDOWN_PERIOD
        );
        assert_eq!(
            st.topdown_checkpoint_voting.genesis_epoch(),
            if st.network_name == *ROOTNET_ID {
                0
            } else {
                *DEFAULT_GENESIS_EPOCH
            }
        );
        verify_empty_map(rt, st.subnets.cid());
        verify_empty_map(rt, st.bottomup_checkpoints.cid());
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

        let params = AmountParams {
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
        ch: &BottomUpCheckpoint,
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
        to: &Address,
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

        let params = FundParams {
            subnet: id.clone(),
            to: to.clone(),
        };

        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::Fund as MethodNum,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                ),
            );
            rt.verify();
            return Ok(());
        }
        if to.protocol() == Protocol::ID {
            rt.expect_send(
                *to,
                PUBLIC_RESOLVE_ADDRESS_METHOD,
                None,
                TokenAmount::zero(),
                IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
                ExitCode::OK,
            );
        }
        if funder.protocol() == Protocol::ID && funder != to {
            rt.expect_send(
                *funder,
                PUBLIC_RESOLVE_ADDRESS_METHOD,
                None,
                TokenAmount::zero(),
                IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
                ExitCode::OK,
            );
        }
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
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
        rt.verify();

        let sub = self.get_subnet(rt, id).unwrap();
        let crossmsgs = sub.top_down_msgs.load(rt.store()).unwrap();
        let msg = get_topdown_msg(&crossmsgs, expected_nonce - 1)
            .unwrap()
            .unwrap();
        assert_eq!(&sub.circ_supply, expected_circ_sup);
        assert_eq!(sub.topdown_nonce, expected_nonce);
        let mut from = IPCAddress::new(&self.net_name, &funder).unwrap();
        if funder.protocol() == Protocol::ID {
            from = IPCAddress::new(&self.net_name, &*TEST_BLS).unwrap();
        }
        let mut comp_to = IPCAddress::new(&id, &to).unwrap();
        if to.protocol() == Protocol::ID {
            comp_to = IPCAddress::new(&id, &TEST_BLS).unwrap();
        }
        assert_eq!(msg.from, from);
        assert_eq!(msg.to, comp_to);
        assert_eq!(msg.nonce, expected_nonce - 1);
        assert_eq!(msg.value, value);

        Ok(())
    }

    pub fn release(
        &self,
        rt: &mut MockRuntime,
        releaser: &Address,
        to: &Address,
        code: ExitCode,
        value: TokenAmount,
        epoch: ChainEpoch,
        expected_nonce: u64,
        expected_msg_index: usize,
    ) -> Result<Cid, ActorError> {
        rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, *releaser);
        rt.expect_validate_caller_type(SIG_TYPES.clone());
        // set value and include the cross_msg_fee
        set_rt_value_with_cross_fee(rt, &value);

        rt.set_epoch(epoch);

        let params = ReleaseParams { to: to.clone() };

        if code != ExitCode::OK {
            expect_abort(
                code,
                rt.call::<Actor>(
                    Method::Release as MethodNum,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                ),
            );
            rt.verify();
            return Ok(Cid::default());
        }

        if to.protocol() == Protocol::ID {
            rt.expect_send(
                *to,
                PUBLIC_RESOLVE_ADDRESS_METHOD,
                None,
                TokenAmount::zero(),
                IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
                ExitCode::OK,
            );
        }
        if releaser.protocol() == Protocol::ID && releaser != to {
            rt.expect_send(
                *releaser,
                PUBLIC_RESOLVE_ADDRESS_METHOD,
                None,
                TokenAmount::zero(),
                IpldBlock::serialize_cbor(&*TEST_BLS).unwrap(),
                ExitCode::OK,
            );
        }
        rt.expect_send(
            BURNT_FUNDS_ACTOR_ADDR,
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::OK,
        );
        rt.call::<Actor>(
            Method::Release as MethodNum,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap();
        rt.verify();

        let st: State = rt.get_state();

        let parent = &self.net_name.parent().unwrap();
        let ch = st.get_window_checkpoint(rt.store(), epoch).unwrap();
        // check that is included in the next checkpoint to be committed and not
        // in a checkpoint template of the past
        assert_eq!(ch.data.epoch > epoch, true);

        let msg = ch.data.cross_msgs.cross_msgs.unwrap()[expected_msg_index].clone();

        let mut from = IPCAddress::new(&self.net_name, &releaser).unwrap();
        if releaser.protocol() == Protocol::ID {
            from = IPCAddress::new(&self.net_name, &*TEST_BLS).unwrap();
        }
        let mut comp_to = IPCAddress::new(&parent, &to).unwrap();
        if to.protocol() == Protocol::ID {
            comp_to = IPCAddress::new(&parent, &TEST_BLS).unwrap();
        }
        assert_eq!(msg.msg.from, from);
        assert_eq!(msg.msg.to, comp_to);
        assert_eq!(msg.msg.nonce, expected_nonce);
        assert_eq!(msg.msg.value, value);

        Ok(Cid::default())
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

            let msg = ch.data.cross_msgs.cross_msgs.unwrap()[nonce as usize].clone();
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
            assert_eq!(sub.topdown_nonce, nonce);
            let from = IPCAddress::new(&self.net_name, &SYSTEM_ACTOR_ADDR).unwrap();
            let to = IPCAddress::new(&dest, &to).unwrap();
            assert_eq!(msg.from, from);
            assert_eq!(msg.to, to);
            assert_eq!(msg.nonce, nonce - 1);
            assert_eq!(msg.value, value);
        }

        Ok(())
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

    pub fn submit_topdown_check(
        &self,
        rt: &mut MockRuntime,
        submitter: Address,
        checkpoint: TopDownCheckpoint,
    ) -> Result<(), ActorError> {
        rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, submitter);
        rt.expect_validate_caller_type(SIG_TYPES.clone());

        rt.call::<Actor>(
            Method::SubmitTopDownCheckpoint as MethodNum,
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

fn set_rt_value_with_cross_fee(rt: &mut MockRuntime, value: &TokenAmount) {
    rt.set_value(if value.clone() != TokenAmount::zero() {
        value.clone() + &*CROSS_MSG_FEE
    } else {
        value.clone()
    });
}
