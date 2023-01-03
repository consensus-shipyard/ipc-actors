#[cfg(test)]
mod test {
    use cid::Cid;
    use fil_actors_runtime::runtime::Runtime;
    use fil_actors_runtime::test_utils::{expect_abort, ExpectedVerifySig, MockRuntime};
    use fil_actors_runtime::{cbor, ActorError, INIT_ACTOR_ADDR};
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;
    use fvm_shared::crypto::signature::Signature;
    use fvm_shared::econ::TokenAmount;
    use fvm_shared::error::ExitCode;
    use ipc_gateway::{Checkpoint, FundParams, SubnetID, MIN_COLLATERAL_AMOUNT};
    use ipc_subnet_actor::{
        ext, Actor, ConsensusType, ConstructParams, JoinParams, Method, State, Status,
    };
    use num_traits::Zero;
    use primitives::TCid;
    use std::str::FromStr;

    // just a test address
    const IPC_GATEWAY_ADDR: u64 = 1024;
    const NETWORK_NAME: &'static str = "test";

    fn std_construct_param() -> ConstructParams {
        ConstructParams {
            parent: SubnetID::from_str("/root").unwrap(),
            name: NETWORK_NAME.to_string(),
            ipc_gateway_addr: IPC_GATEWAY_ADDR,
            consensus: ConsensusType::Dummy,
            min_validator_stake: Default::default(),
            min_validators: 0,
            finality_threshold: 0,
            check_period: 0,
            genesis: vec![],
        }
    }

    fn construct_runtime_with_receiver(receiver: Address) -> MockRuntime {
        let caller = *INIT_ACTOR_ADDR;
        let mut runtime = MockRuntime::new(receiver, caller);

        let params = std_construct_param();

        runtime.expect_validate_caller_addr(vec![caller]);

        runtime
            .call::<Actor>(
                Method::Constructor as u64,
                &cbor::serialize(&params, "test").unwrap(),
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
        assert_eq!(state.validator_set.is_empty(), true);
    }

    #[test]
    fn test_join_fail_no_min_collateral() {
        let mut runtime = construct_runtime();
        runtime.expect_validate_caller_any();

        let validator = Address::new_id(100);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        expect_abort(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            runtime.call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            ),
        );
    }

    #[test]
    fn test_join_works() {
        let mut runtime = construct_runtime();

        let caller = Address::new_id(10);
        let validator = Address::new_id(100);
        let start_token_value = 5_u64.pow(18);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        // Part 1. join without enough to be activated

        // execution
        let value = TokenAmount::from_atto(start_token_value);
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is initiated
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 0);
        assert_eq!(st.status, Status::Instantiated);
        assert_eq!(st.total_stake, value);
        let stake = st.get_stake(runtime.store(), &caller).unwrap();
        assert_eq!(stake.unwrap(), value);

        // Part 2. miner adds stake and activates it
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT - start_token_value);
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::Register as u64,
            RawBytes::default(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is active
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 1);
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
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::AddStake as u64,
            RawBytes::default(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            )
            .unwrap();

        // verify state.
        // as the value is less than min collateral, state is active
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 2);
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
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::Register as u64,
            RawBytes::default(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
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
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::AddStake as u64,
            RawBytes::default(),
            TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            )
            .unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(st.validator_set.len(), 2);
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
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::AddStake as u64,
            RawBytes::default(),
            value.clone(),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(
                Method::Join as u64,
                &cbor::serialize(&params, "test").unwrap(),
            )
            .unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(st.validator_set.len(), 2);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            value
        );

        // one miner leaves the subnet
        let caller = Address::new_id(10);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        total_stake = total_stake - &value;
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            RawBytes::serialize(FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(Method::Leave as u64, &RawBytes::default())
            .unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 1);
        assert_eq!(st.status, Status::Active);
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::zero()
        );

        // subnet can't be killed if there are still miners
        runtime.expect_validate_caller_any();
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(Method::Kill as u64, &RawBytes::default()),
        );

        // // next miner inactivates the subnet
        let caller = Address::new_id(20);
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);
        total_stake = total_stake - &value;
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            RawBytes::serialize(FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(Method::Leave as u64, &RawBytes::default())
            .unwrap();

        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 0);
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
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::ReleaseStake as u64,
            RawBytes::serialize(FundParams {
                value: value.clone(),
            })
            .unwrap(),
            TokenAmount::zero(),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(Method::Leave as u64, &RawBytes::default())
            .unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 0);
        assert_eq!(st.status, Status::Inactive);
        assert_eq!(st.total_stake, total_stake);
        assert_eq!(
            st.get_stake(runtime.store(), &caller).unwrap().unwrap(),
            TokenAmount::zero()
        );

        // to kill the subnet
        runtime.set_value(value.clone());
        runtime.set_caller(Cid::default(), caller.clone());
        runtime.expect_validate_caller_any();
        runtime.expect_send(
            Address::new_id(IPC_GATEWAY_ADDR),
            ipc_gateway::Method::Kill as u64,
            RawBytes::default(),
            TokenAmount::zero(),
            RawBytes::default(),
            ExitCode::new(0),
        );
        runtime
            .call::<Actor>(Method::Kill as u64, &RawBytes::default())
            .unwrap();
        let st: State = runtime.get_state();
        assert_eq!(st.total_stake, TokenAmount::zero());
        assert_eq!(st.status, Status::Killed);
    }

    #[test]
    fn test_submit_checkpoint() {
        let test_actor_address = Address::new_id(9999);
        let mut runtime = construct_runtime_with_receiver(test_actor_address.clone());

        let miners = vec![
            Address::new_id(10),
            Address::new_id(20),
            Address::new_id(30),
        ];
        let validator = Address::new_id(100);
        let params = JoinParams {
            validator_net_addr: validator.to_string(),
        };

        // first miner joins the subnet
        let value = TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT);

        let mut i = 0;
        for caller in &miners {
            runtime.set_value(value.clone());
            runtime.set_balance(TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT));
            runtime.set_caller(Cid::default(), caller.clone());
            runtime.expect_validate_caller_any();
            if i == 0 {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::Register as u64,
                    RawBytes::default(),
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    RawBytes::default(),
                    ExitCode::new(0),
                );
            } else {
                runtime.expect_send(
                    Address::new_id(IPC_GATEWAY_ADDR),
                    ipc_gateway::Method::AddStake as u64,
                    RawBytes::default(),
                    TokenAmount::from_atto(MIN_COLLATERAL_AMOUNT),
                    RawBytes::default(),
                    ExitCode::new(0),
                );
            }

            runtime
                .call::<Actor>(
                    Method::Join as u64,
                    &cbor::serialize(&params, "test").unwrap(),
                )
                .unwrap();

            i += 1;
        }

        // verify that we have an active subnet with 3 validators.
        let st: State = runtime.get_state();
        assert_eq!(st.validator_set.len(), 3);
        assert_eq!(st.status, Status::Active);

        // Generate the check point
        let root_subnet = SubnetID::from_str("/root").unwrap();
        let subnet = SubnetID::new(&root_subnet, test_actor_address);
        let epoch = 10;
        let mut checkpoint_0 = Checkpoint::new(subnet.clone(), epoch);
        checkpoint_0.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );

        // Only validators should be entitled to submit checkpoints.
        let non_miner = Address::new_id(40);
        runtime.set_caller(Cid::default(), non_miner.clone());
        runtime.expect_validate_caller_any();
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                &cbor::serialize(&checkpoint_0, "test").unwrap(),
            ),
        );

        // Send first checkpoint
        let sender = miners.get(0).cloned().unwrap();
        send_checkpoint(&mut runtime, sender.clone(), &checkpoint_0, false).unwrap();

        let st: State = runtime.get_state();
        let votes = st
            .get_votes(runtime.store(), &checkpoint_0.cid())
            .unwrap()
            .unwrap();
        assert_eq!(votes.validators, vec![sender.clone()]);
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            send_checkpoint(&mut runtime, sender.clone(), &checkpoint_0, false),
        );

        // Send second checkpoint
        let sender2 = miners.get(1).cloned().unwrap();
        send_checkpoint(&mut runtime, sender2.clone(), &checkpoint_0, true).unwrap();

        let st: State = runtime.get_state();
        let votes = st.get_votes(runtime.store(), &checkpoint_0.cid()).unwrap();
        assert_eq!(votes.is_none(), true);

        // Trying to submit an already committed checkpoint should fail
        let sender2 = miners.get(2).cloned().unwrap();
        runtime.set_caller(Cid::default(), sender2.clone());
        runtime.expect_validate_caller_any();
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                &cbor::serialize(&checkpoint_0, "test").unwrap(),
            ),
        );

        // If the epoch is wrong in the next checkpoint, it should be rejected.
        let prev_cid = checkpoint_0.cid();
        let mut checkpoint_1 = Checkpoint::new(subnet.clone(), epoch + 1);
        checkpoint_1.data.prev_check = TCid::from(prev_cid.clone());
        runtime.set_caller(Cid::default(), sender.clone());
        runtime.expect_validate_caller_any();
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                &cbor::serialize(&checkpoint_1, "test").unwrap(),
            ),
        );

        // Submit checkpoint with invalid previous cid
        let epoch = 20;
        let mut checkpoint_3 = Checkpoint::new(subnet.clone(), epoch);
        checkpoint_3.data.prev_check = TCid::from(Cid::default());
        runtime.set_caller(Cid::default(), sender.clone());
        runtime.expect_validate_caller_any();
        expect_abort(
            ExitCode::USR_ILLEGAL_STATE,
            runtime.call::<Actor>(
                Method::SubmitCheckpoint as u64,
                &cbor::serialize(&checkpoint_3, "test").unwrap(),
            ),
        );

        // Send correct payload
        let epoch = 20;
        let prev_cid = checkpoint_0.cid();
        let mut checkpoint_4 = Checkpoint::new(subnet.clone(), epoch);
        checkpoint_4.data.prev_check = TCid::from(prev_cid);
        checkpoint_4.set_signature(
            RawBytes::serialize(Signature::new_secp256k1(vec![1, 2, 3, 4]))
                .unwrap()
                .bytes()
                .to_vec(),
        );
        send_checkpoint(&mut runtime, sender.clone(), &checkpoint_4, false).unwrap();
        let st: State = runtime.get_state();
        let votes = st
            .get_votes(runtime.store(), &checkpoint_4.cid())
            .unwrap()
            .unwrap();
        assert_eq!(votes.validators, vec![sender.clone()]);
    }

    fn send_checkpoint(
        runtime: &mut MockRuntime,
        sender: Address,
        checkpoint: &Checkpoint,
        is_commit: bool,
    ) -> Result<RawBytes, ActorError> {
        runtime.set_caller(Cid::default(), sender.clone());
        runtime.expect_send(
            sender.clone(),
            ext::account::PUBKEY_ADDRESS_METHOD as u64,
            RawBytes::default(),
            TokenAmount::zero(),
            cbor::serialize(&sender.clone(), "test").unwrap(),
            ExitCode::new(0),
        );
        runtime.expect_validate_caller_any();
        runtime.expect_verify_signature(ExpectedVerifySig {
            sig: Signature::new_secp256k1(vec![1, 2, 3, 4]),
            signer: sender.clone(),
            plaintext: checkpoint.cid().to_bytes(),
            result: Ok(()),
        });

        if is_commit {
            runtime.expect_send(
                Address::new_id(IPC_GATEWAY_ADDR),
                ipc_gateway::Method::CommitChildCheckpoint as u64,
                RawBytes::serialize(checkpoint)?,
                TokenAmount::zero(),
                cbor::serialize(&sender.clone(), "test").unwrap(),
                ExitCode::new(0),
            )
        }
        runtime.call::<Actor>(
            Method::SubmitCheckpoint as u64,
            &cbor::serialize(checkpoint, "test").unwrap(),
        )
    }
}
