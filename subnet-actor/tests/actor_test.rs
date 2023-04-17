#[cfg(test)]
mod test {
    use cid::Cid;
    use fil_actors_runtime::runtime::Runtime;
    use fil_actors_runtime::test_utils::{
        expect_abort, expect_abort_contains_message, MockRuntime, ACCOUNT_ACTOR_CODE_ID,
        INIT_ACTOR_CODE_ID, MULTISIG_ACTOR_CODE_ID,
    };
    use fil_actors_runtime::{ActorError, INIT_ACTOR_ADDR};
    use fvm_ipld_encoding::ipld_block::IpldBlock;
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;
    use fvm_shared::clock::ChainEpoch;
    use fvm_shared::crypto::signature::Signature;
    use fvm_shared::econ::TokenAmount;
    use fvm_shared::error::ExitCode;
    use fvm_shared::METHOD_SEND;
    use ipc_gateway::{
        BottomUpCheckpoint, FundParams, SubnetID, CHECKPOINT_GENESIS_CID, MIN_COLLATERAL_AMOUNT,
    };
    use ipc_subnet_actor::{
        Actor, ConsensusType, ConstructParams, JoinParams, Method, State, Status,
    };
    use lazy_static::lazy_static;
    use num::BigInt;
    use num_traits::FromPrimitive;
    use num_traits::Zero;
    use primitives::TCid;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    // just a test address
    const IPC_GATEWAY_ADDR: u64 = 1024;
    const NETWORK_NAME: &'static str = "test";
    const DEFAULT_GENESIS_EPOCH: ChainEpoch = 0;

    lazy_static! {
        pub static ref SIG_TYPES: Vec<Cid> = vec![*ACCOUNT_ACTOR_CODE_ID, *MULTISIG_ACTOR_CODE_ID];
    }
    fn std_construct_param() -> ConstructParams {
        ConstructParams {
            parent: SubnetID::from_str("/root").unwrap(),
            name: NETWORK_NAME.to_string(),
            ipc_gateway_addr: IPC_GATEWAY_ADDR,
            consensus: ConsensusType::Dummy,
            min_validator_stake: Default::default(),
            min_validators: 0,
            topdown_check_period: 0,
            bottomup_check_period: 0,
            genesis: vec![],
        }
    }

    pub fn new_runtime(receiver: Address) -> MockRuntime {
        MockRuntime {
            receiver,
            caller: INIT_ACTOR_ADDR,
            caller_type: *INIT_ACTOR_CODE_ID,
            ..Default::default()
        }
    }

    fn construct_runtime_with_receiver(receiver: Address) -> MockRuntime {
        let mut runtime = new_runtime(receiver);
        runtime.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);

        let params = std_construct_param();

        runtime.expect_validate_caller_addr(vec![INIT_ACTOR_ADDR]);

        runtime.set_epoch(DEFAULT_GENESIS_EPOCH);

        runtime
            .call::<Actor>(
                Method::Constructor as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        runtime
    }

    fn construct_runtime() -> MockRuntime {
        let receiver = Address::new_id(1);
        construct_runtime_with_receiver(receiver)
    }

    #[test]
    fn test_constructor() {
        let runtime = construct_runtime();
        assert_eq!(runtime.state.is_some(), true);

        let state: State = runtime.get_state();
        assert_eq!(state.name, NETWORK_NAME);
        assert_eq!(state.ipc_gateway_addr, Address::new_id(IPC_GATEWAY_ADDR));
        assert_eq!(state.total_stake, TokenAmount::zero());
        assert_eq!(state.validator_set.validators().is_empty(), true);
    }

    #[test]
    fn test_join_fail_no_min_collateral() {
        let mut runtime = construct_runtime();

        let validator = Address::new_id(100);
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, validator.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        expect_abort(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            runtime.call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            ),
        );
    }

    #[test]
    fn test_set_net_addr_works() {
        let mut runtime = construct_runtime();

        let caller = Address::new_id(10);
        let validator = Address::new_id(100);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };
        let gateway = Address::new_id(IPC_GATEWAY_ADDR);

        // join
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        runtime.set_value(value.clone());
        runtime.set_balance(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            gateway.clone(),
            ipc_gateway::Method::Register as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // modify net address
        let new_addr = String::from("test_addr");
        let params = JoinParams {
            validator_net_addr: new_addr.clone(),
        };

        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime
            .call::<Actor>(
                Method::SetValidatorNetAddr as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        let st: State = runtime.get_state();

        if let Some(val) = st
            .validator_set
            .validators()
            .iter()
            .find(|x| x.addr == caller)
        {
            assert_eq!(val.net_addr, new_addr);
        } else {
            panic!("validator address not set correctly")
        }

        // user which is not a validator tries to change address
        let caller = Address::new_id(11);
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort(
            ExitCode::USR_FORBIDDEN,
            runtime.call::<Actor>(
                Method::SetValidatorNetAddr as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            ),
        );
    }

    #[test]
    fn test_join_works() {
        let mut runtime = construct_runtime();

        let caller = Address::new_id(10);
        let validator = Address::new_id(100);
        let gateway = Address::new_id(IPC_GATEWAY_ADDR);
        let start_token_value = 5_u64.pow(18);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        // Part 1. join without enough to be activated

        // execution
        let value = TokenAmount::from_atto(start_token_value);
        runtime.set_value(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // reward fails because there is no validators.
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), gateway.clone());
        runtime.expect_validate_caller_addr(vec![gateway.clone()]);
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(Method::Reward as u64, None),
        );

        // verify state.
        // as the value is less than min collateral, state is initiated
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 0);
        assert_eq!(st.validator_set.config_number(), 0);
        assert_eq!(st.status, Status::Instantiated);
        assert_eq!(st.total_stake, value);
        let stake = st.get_stake(runtime.store(), &caller).unwrap();
        assert_eq!(stake.unwrap(), value);

        // Part 2. miner adds stake and activates it
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT - start_token_value);
        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            gateway.clone(),
            ipc_gateway::Method::Register as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is active
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 1);
        assert_eq!(st.validator_set.config_number(), 1);
        assert_eq!(st.status, Status::Active);
        assert_eq!(
            st.total_stake,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT)
        );
        let stake = st.get_stake(runtime.store(), &caller).unwrap();
        assert_eq!(
            stake.unwrap(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT)
        );
        runtime.verify();

        // Part 3. miner joins already active subnet
        let caller = Address::new_id(11);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            gateway.clone(),
            ipc_gateway::Method::AddStake as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is active
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 2);
        assert_eq!(st.validator_set.config_number(), 2);
        assert_eq!(st.status, Status::Active);
        assert_eq!(
            st.total_stake,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT * 2)
        );
        let stake = st.get_stake(runtime.store(), &caller).unwrap();
        assert_eq!(
            stake.unwrap(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT)
        );
        runtime.verify();

        // Part 4. miner tries to join twice
        let caller = Address::new_id(11);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            gateway.clone(),
            ipc_gateway::Method::AddStake as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is active
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 2);
        assert_eq!(st.validator_set.config_number(), 3);
        assert_eq!(st.status, Status::Active);
        assert_eq!(
            st.total_stake,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT * 3)
        );
        let stake = st.get_stake(runtime.store(), &caller).unwrap();
        assert_eq!(
            stake.unwrap(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT * 2)
        );
        assert_eq!(
            st.validator_set
                .validators()
                .iter()
                .filter(|x| x.addr == caller)
                .next()
                .unwrap()
                .weight,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT * 2)
        );
        runtime.verify();

        // reward is fairly distribute among all validators,
        // and fails if no tokens are sent.
        runtime.set_value(TokenAmount::zero());
        runtime.set_caller(Cid::default(), gateway.clone());
        runtime.expect_validate_caller_addr(vec![gateway.clone()]);
        expect_abort(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            runtime.call::<Actor>(Method::Reward as u64, None),
        );

        let total_reward = TokenAmount::from_atto(2);
        runtime.set_value(total_reward.clone());
        runtime.set_caller(Cid::default(), gateway.clone());
        runtime.expect_validate_caller_addr(vec![gateway.clone()]);
        runtime.set_balance(TokenAmount::from_atto(3));
        let st: State = runtime.get_state();
        let rew_amount = total_reward
            .div_floor(BigInt::from_usize(st.validator_set.validators().len()).unwrap());
        for v in st.validator_set.validators().into_iter() {
            runtime.expect_send(
                v.addr,
                METHOD_SEND,
                None,
                rew_amount.clone(),
                None,
                ExitCode::new(0),
            );
        }
        runtime.call::<Actor>(Method::Reward as u64, None).unwrap();
        runtime.verify();
    }

    #[test]
    fn test_leave_and_kill() {
        let mut runtime = construct_runtime();

        let caller = Address::new_id(10);
        let validator = Address::new_id(100);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        // first miner joins the subnet
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        let mut total_stake = value.clone();

        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::Register as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        // Just some santity check here as it should have been tested by previous methods
        let st: State = runtime.get_state();
        assert_eq!(st.status, Status::Active);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT)
        );

        // second miner joins the subnet
        let caller = Address::new_id(20);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        let params = JoinParams {
            validator_net_addr: caller.clone().to_string(),
        };
        total_stake = total_stake + &value;
        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::AddStake as u64,
            None,
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(st.validator_set.validators().len(), 2);
        assert_eq!(st.validator_set.config_number(), 2);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT)
        );

        // non-miner joins
        let caller = Address::new_id(30);
        let params = JoinParams {
            validator_net_addr: caller.clone().to_string(),
        };
        let value = TokenAmount::from_atto(5u64.pow(18));
        total_stake = total_stake + &value;

        runtime.set_value(value.clone());
        runtime.set_balance(TokenAmount::from_atto(5u64.pow(18)));
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::AddStake as u64,
            None,
            value.clone(),
            None,
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                IpldBlock::serialize_cbor(&params).unwrap(),
            )
            .unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(st.validator_set.validators().len(), 2);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            value
        );

        // one miner leaves the subnet
        let caller = Address::new_id(10);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        runtime.set_balance(total_stake.clone());
        total_stake = total_stake - &value;
        runtime.set_value(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            IpldBlock::serialize_cbor(&FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::new(0),
        );
        runtime.expect_send(
            caller,
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::new(0),
        );
        runtime.call::<Actor>(Method::Leave as u64, None).unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 1);
        assert_eq!(st.validator_set.config_number(), 3);
        assert_eq!(st.status, Status::Active);
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::zero()
        );

        // subnet can't be killed if there are still miners
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(Method::Kill as u64, None),
        );

        // // next miner inactivates the subnet
        let caller = Address::new_id(20);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        total_stake = total_stake - &value;
        runtime.set_value(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            IpldBlock::serialize_cbor(&FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::new(0),
        );
        runtime.expect_send(
            caller,
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::new(0),
        );
        runtime.call::<Actor>(Method::Leave as u64, None).unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 0);
        assert_eq!(st.validator_set.config_number(), 4);
        assert_eq!(st.status, Status::Inactive);
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::zero()
        );

        // last joiner gets the stake and kills the subnet
        let caller = Address::new_id(30);
        let value = TokenAmount::from_atto(5u64.pow(18));
        total_stake = total_stake - &value;
        runtime.set_value(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            IpldBlock::serialize_cbor(&FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::new(0),
        );
        runtime.expect_send(
            caller,
            METHOD_SEND,
            None,
            value.clone(),
            None,
            ExitCode::new(0),
        );
        runtime.call::<Actor>(Method::Leave as u64, None).unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 0);
        assert_eq!(st.status, Status::Inactive);
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::zero()
        );

        // to kill the subnet
        runtime.set_value(value.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::Kill as u64,
            None,
            TokenAmount::zero(),
            None,
            ExitCode::new(0),
        );
        runtime.call::<Actor>(Method::Kill as u64, None).unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, TokenAmount::zero());
        assert_eq!(st.status, Status::Killed);
    }

    #[test]
    fn test_submit_checkpoint_works() {
        let test_actor_address = Address::new_id(9999);
        let mut runtime = construct_runtime_with_receiver(test_actor_address.clone());

        let miners = vec![
            Address::new_id(10),
            Address::new_id(20),
            Address::new_id(30),
            Address::new_id(40),
        ];

        // first miner joins the subnet
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);

        let mut i = 0;
        for caller in &miners {
            runtime.set_value(value.clone());
            runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
            runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
            runtime.expect_validate_caller_type(SIG_TYPES.clone());
            if i == 0 {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::Register as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            } else {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::AddStake as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            }

            let params = JoinParams {
                validator_net_addr: caller.to_string(),
            };

            runtime
                .call::<Actor>(
                    Method::Join as u64,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                )
                .unwrap();

            i += 1;
        }

        // verify that we have an active subnet with 4 validators.
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.validators().len(), 4);
        assert_eq!(st.status, Status::Active);

        // Generate the check point
        let root_subnet = SubnetID::from_str("/root").unwrap();
        let subnet = SubnetID::new_from_parent(&root_subnet, test_actor_address);
        // we are targeting the next submission period
        let epoch = DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period;
        let mut checkpoint_0 = BottomUpCheckpoint::new(subnet.clone(), epoch);
        checkpoint_0.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );

        // Only validators should be entitled to submit checkpoints.
        let non_miner = Address::new_id(50);
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, non_miner.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                IpldBlock::serialize_cbor(&checkpoint_0).unwrap(),
            ),
        );

        // Send first checkpoint
        let sender = miners.get(0).cloned().unwrap();
        send_checkpoint(&mut runtime, sender.clone(), &checkpoint_0, false).unwrap();

        // Already voted, should not vote again
        expect_abort_contains_message(
            ExitCode::USR_ILLEGAL_STATE,
            "already submitted",
            send_checkpoint(&mut runtime, sender.clone(), &checkpoint_0, false),
        );

        // Send second checkpoint
        let sender2 = miners.get(1).cloned().unwrap();

        // This should have triggered commit
        send_checkpoint(&mut runtime, sender2.clone(), &checkpoint_0, false).unwrap();
        send_checkpoint(
            &mut runtime,
            miners.get(2).cloned().unwrap(),
            &checkpoint_0,
            true,
        )
        .unwrap();

        // Trying to submit an already committed checkpoint should fail, i.e. if the epoch is already
        // committed, then we should not allow voting again
        let sender2 = miners.get(3).cloned().unwrap();
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, sender2.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                IpldBlock::serialize_cbor(&checkpoint_0).unwrap(),
            ),
        );

        // If the epoch is wrong in the next checkpoint, it should be rejected. Not multiple of the
        // execution period.
        let prev_cid = checkpoint_0.cid();
        let mut checkpoint_1 = BottomUpCheckpoint::new(subnet.clone(), epoch + 1);
        checkpoint_1.data.prev_check = TCid::from(prev_cid.clone());
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, sender.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                IpldBlock::serialize_cbor(&checkpoint_1).unwrap(),
            ),
        );

        // Start the voting for a new epoch, checking we can proceed with new epoch number.
        let epoch = DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2;
        let prev_cid = checkpoint_0.cid();
        let mut checkpoint_4 = BottomUpCheckpoint::new(subnet.clone(), epoch);
        checkpoint_4.data.prev_check = TCid::from(prev_cid);
        checkpoint_4.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );
        send_checkpoint(&mut runtime, sender.clone(), &checkpoint_4, false).unwrap();
    }

    /// Tests the checkpoint will abort when checkpoints are not chained and the submitted epoch is the
    /// next executable epoch, we stop the epoch from submission
    #[test]
    fn test_submit_checkpoint_aborts_not_chained_early_termination() {
        let test_actor_address = Address::new_id(9999);
        let mut runtime = construct_runtime_with_receiver(test_actor_address.clone());

        let miners = vec![
            Address::new_id(10),
            Address::new_id(20),
            Address::new_id(30),
            Address::new_id(40),
        ];

        // first miner joins the subnet
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);

        let mut i = 0;
        for caller in &miners {
            runtime.set_value(value.clone());
            runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
            runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
            runtime.expect_validate_caller_type(SIG_TYPES.clone());
            if i == 0 {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::Register as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            } else {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::AddStake as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            }

            let params = JoinParams {
                validator_net_addr: caller.to_string(),
            };

            runtime
                .call::<Actor>(
                    Method::Join as u64,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                )
                .unwrap();

            i += 1;
        }

        // verify that we have an active subnet with 3 validators.
        let st: State = runtime.get_state();

        // Generate the check point
        let root_subnet = SubnetID::from_str("/root").unwrap();
        let subnet = SubnetID::new_from_parent(&root_subnet, test_actor_address);
        // we are targeting the next submission period
        let epoch = DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period;
        let mut checkpoint_0 = BottomUpCheckpoint::new(subnet.clone(), epoch);
        checkpoint_0.data.prev_check = TCid::default();
        checkpoint_0.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );

        // Reject the submission as checkpoints are not chained
        let s = Address::new_id(10);
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, s.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        expect_abort_contains_message(
            ExitCode::USR_ILLEGAL_STATE,
            "checkpoint not chained",
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                IpldBlock::serialize_cbor(&checkpoint_0).unwrap(),
            ),
        );
    }

    /// Tests the checkpoint will abort when checkpoints are not chained and the submitted epoch is NOT the
    /// next executable epoch, we need to reset the epoch.
    ///
    /// Test flows like the below:
    /// 1. Create 4 validators and register them to the subnet with equal weight
    ///
    /// 2. Submit to epoch `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2`, we are skipping
    ///    the first epoch and ensure this is executable. The previous checkpoint cid is set to some value `cid_a`.
    ///    We should see the epoch number being stored in the next executable queue.
    ///    Checks at step 2:
    ///    - executable_queue should contain `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2`
    ///    - last_executed_epoch is still `DEFAULT_GENESIS_EPOCH`
    ///
    /// 3. Submit to epoch `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 1`, i.e. the previous
    ///    epoch in step 2. This would lead to the epoch being committed. The key is the checkpoint cid of the current
    ///    epoch should be different from that in step 2, i.e. any value other than `cid_a`
    ///    Checks at step 3:
    ///    - executable_queue should contain `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2`
    ///    - last_executed_epoch is still `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 1`
    ///
    /// 4. Submit to any epoch after `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 1`, should
    ///    trigger a reset in submission of epoch `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2`.
    ///    Checks at step 4:
    ///    - executable_queue should have removed `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2`
    ///    - last_executed_epoch is still `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 1`
    ///    - submission at `DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2` is cleared
    #[test]
    fn test_submit_checkpoint_aborts_not_chained_reset_epoch() {
        let test_actor_address = Address::new_id(9999);
        let mut runtime = construct_runtime_with_receiver(test_actor_address.clone());

        // Step 1
        let miners = vec![
            Address::new_id(10),
            Address::new_id(20),
            Address::new_id(30),
            Address::new_id(40),
        ];

        // first miner joins the subnet
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);

        let mut i = 0;
        for caller in &miners {
            runtime.set_value(value.clone());
            runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
            runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, caller.clone());
            runtime.expect_validate_caller_type(SIG_TYPES.clone());
            if i == 0 {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::Register as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            } else {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::AddStake as u64,
                    None,
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    None,
                    ExitCode::new(0),
                );
            }

            let params = JoinParams {
                validator_net_addr: caller.to_string(),
            };

            runtime
                .call::<Actor>(
                    Method::Join as u64,
                    IpldBlock::serialize_cbor(&params).unwrap(),
                )
                .unwrap();

            i += 1;
        }

        let root_subnet = SubnetID::from_str("/root").unwrap();
        let subnet = SubnetID::new_from_parent(&root_subnet, test_actor_address);

        // Step 2
        let st: State = runtime.get_state();
        let epoch_2 = DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2;
        let prev_cid = Cid::default();
        let mut checkpoint_2 = BottomUpCheckpoint::new(subnet.clone(), epoch_2);
        checkpoint_2.data.prev_check = TCid::from(prev_cid);
        checkpoint_2.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );

        send_checkpoint(&mut runtime, miners[0].clone(), &checkpoint_2, false).unwrap();
        send_checkpoint(&mut runtime, miners[1].clone(), &checkpoint_2, false).unwrap();
        send_checkpoint(&mut runtime, miners[2].clone(), &checkpoint_2, false).unwrap();

        // performing checks
        let st: State = runtime.get_state();
        assert_eq!(
            st.previous_executed_checkpoint_cid,
            CHECKPOINT_GENESIS_CID.clone()
        );
        assert_eq!(
            st.bottomup_checkpoint_voting.last_voting_executed_epoch,
            DEFAULT_GENESIS_EPOCH
        );
        assert_eq!(
            st.bottomup_checkpoint_voting.executable_epoch_queue,
            Some(BTreeSet::from([epoch_2]))
        );
        assert_eq!(
            st.bottomup_checkpoint_voting
                .load_most_voted_submission(runtime.store(), epoch_2)
                .unwrap(),
            Some(checkpoint_2.clone())
        );
        assert_eq!(
            st.bottomup_checkpoint_voting
                .load_most_voted_weight(runtime.store(), epoch_2)
                .unwrap(),
            Some(TokenAmount::from_whole(3))
        );

        // Step 3
        let epoch_1 = DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 1;
        let mut checkpoint_1 = BottomUpCheckpoint::new(subnet.clone(), epoch_1);
        checkpoint_1.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );

        send_checkpoint(&mut runtime, miners[0].clone(), &checkpoint_1, false).unwrap();
        send_checkpoint(&mut runtime, miners[1].clone(), &checkpoint_1, false).unwrap();
        send_checkpoint(&mut runtime, miners[2].clone(), &checkpoint_1, true).unwrap();

        // performing checks
        let st: State = runtime.get_state();
        assert_eq!(st.previous_executed_checkpoint_cid, checkpoint_1.cid());
        assert_eq!(
            st.bottomup_checkpoint_voting.last_voting_executed_epoch,
            epoch_1
        );
        assert_eq!(
            st.bottomup_checkpoint_voting.executable_epoch_queue,
            Some(BTreeSet::from([
                DEFAULT_GENESIS_EPOCH + st.bottomup_checkpoint_voting.submission_period * 2
            ]))
        );
        assert_eq!(
            st.bottomup_checkpoint_voting
                .load_most_voted_weight(runtime.store(), epoch_2)
                .unwrap(),
            Some(TokenAmount::from_whole(3))
        );
        assert_eq!(
            st.bottomup_checkpoint_voting
                .load_most_voted_weight(runtime.store(), epoch_1)
                .unwrap(),
            None
        );

        // Step 4
        checkpoint_2.data.prev_check = TCid::from(checkpoint_1.cid());
        send_checkpoint(&mut runtime, miners[3].clone(), &checkpoint_2, false).unwrap();

        // perform checks
        let st: State = runtime.get_state();
        assert_eq!(st.previous_executed_checkpoint_cid, checkpoint_1.cid());
        assert_eq!(
            st.bottomup_checkpoint_voting.last_voting_executed_epoch,
            epoch_1
        );
        assert_eq!(st.bottomup_checkpoint_voting.executable_epoch_queue, None);
    }

    fn send_checkpoint(
        runtime: &mut MockRuntime,
        sender: Address,
        checkpoint: &BottomUpCheckpoint,
        is_commit: bool,
    ) -> Result<Option<IpldBlock>, ActorError> {
        runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, sender.clone());
        runtime.expect_validate_caller_type(SIG_TYPES.clone());
        // runtime.expect_send(
        //     sender.clone(),
        //     ipc_sdk::account::PUBKEY_ADDRESS_METHOD as u64,
        //     None,
        //     TokenAmount::zero(),
        //     IpldBlock::serialize_cbor(&sender).unwrap(),
        //     ExitCode::new(0),
        // );
        // NOTE: For M2 we are removing the explicit signature
        // verification from checkpoints.
        // runtime.expect_verify_signature(ExpectedVerifySig {
        //     sig: Signature::new_secp256k1(vec![1, 2, 3, 4]),
        //     signer: sender.clone(),
        //     plaintext: checkpoint.cid().to_bytes(),
        //     result: Ok(()),
        // });

        if is_commit {
            runtime.expect_send(
                Address::new_id(IPC_GATEWAY_ADDR),
                ipc_gateway::Method::CommitChildCheckpoint as u64,
                IpldBlock::serialize_cbor(&checkpoint).unwrap(),
                TokenAmount::zero(),
                IpldBlock::serialize_cbor(&sender).unwrap(),
                ExitCode::new(0),
            )
        }
        runtime.call::<Actor>(
            Method::SubmitCheckpoint as u64,
            IpldBlock::serialize_cbor(&checkpoint).unwrap(),
        )
    }
}
