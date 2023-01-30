use crate::{
    AbortAtomicTransferParams, Actor, ConstructorParams, InitAtomicTransferParams, Method,
    PrepareAtomicTransferParams, TransferParams, TransferReturn,
};
use cid::Cid;
use fvm_actors_runtime::{
    test_utils::{
        expect_abort_contains_message, MockRuntime, ACCOUNT_ACTOR_CODE_ID, INIT_ACTOR_CODE_ID,
    },
    ActorError, INIT_ACTOR_ADDR,
};
use fvm_ipld_encoding::{ipld_block::IpldBlock, RawBytes};
use fvm_shared::{address::Address, econ::TokenAmount, error::ExitCode, MethodNum};
use ipc_atomic_execution::AtomicExecID;
use ipc_atomic_execution_primitives::{AtomicExecRegistry, AtomicInputID};
use ipc_gateway::{CrossMsg, IPCAddress, StorableMsg, SubnetID};
use ipc_sdk::subnet_id::ROOTNET_ID;
use num_traits::Zero;
use std::collections::HashMap;

#[test]
fn test_constructor() {
    let runtime = &mut construct_runtime();

    // Check token name
    assert_eq!(name(runtime).unwrap(), CONSTRUCTOR_PARAMS.name);

    // Check token symbol
    assert_eq!(symbol(runtime).unwrap(), CONSTRUCTOR_PARAMS.symbol);

    // Check total supply
    assert_eq!(total_supply(runtime).unwrap(), *TOTAL_SUPPLY);

    // Check initial balances
    check_balances(runtime, &*INITIAL_BALANCES);
}

#[test]
fn test_transfer() {
    let runtime = &mut construct_runtime();
    let mut balances = INITIAL_BALANCES.clone();

    // Do transfer
    let (from_balance, to_balance) =
        transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();

    // Adjust local balance table accordingly
    *balances.get_mut(&*ACCOUNT_X).unwrap() -= TokenAmount::from_whole(1);
    *balances.get_mut(&*ACCOUNT_Y).unwrap() += TokenAmount::from_whole(1);

    // Check the result of method invocation
    assert_eq!(from_balance, balances[&*ACCOUNT_X]);
    assert_eq!(to_balance, balances[&*ACCOUNT_Y]);

    // Check the resulting balances
    check_balances(runtime, &balances);

    // Try to overdraw
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "insufficient balance",
        transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)),
    );
}

#[test]
fn test_init_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let balances = INITIAL_BALANCES.clone();

    // Initiate atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();

    // Check that balances have not changed yet
    check_balances(runtime, &balances);

    // Try to initiate atomic transfer from locked account
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "state already locked",
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)),
    );

    // Cancel the atomic transfer
    cancel_atomic_transfer(runtime, *ACCOUNT_X, &input_id).unwrap();
    check_balances(runtime, &balances);

    // Check that an identical but newly initiated atomic transfer
    // yields a fresh input ID
    assert_ne!(
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap(),
        input_id,
    );

    // Check that balances have not changed yet
    check_balances(runtime, &balances);
}

#[test]
fn test_prepare_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let balances = INITIAL_BALANCES.clone();

    // Initiate atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();

    // Cancel the atomic transfer
    cancel_atomic_transfer(runtime, *ACCOUNT_X, &input_id).unwrap();

    let own_input_id = (OWN_IPC_ADDR.clone(), input_id.clone());
    let other_input_id = (
        TOKEN_ACTOR_B.clone(),
        AtomicInputID::from(Vec::from("other input ID")),
    );

    // Try to prepare canceled atomic transfer
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "unexpected own input ID",
        prepare_atomic_transfer(
            runtime,
            *ACCOUNT_X,
            vec![own_input_id, other_input_id.clone()],
            false,
        ),
    );

    // Initiate atomic transfer again
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];

    // Try to prepare foreign atomic transfer
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "unexpected sender address",
        prepare_atomic_transfer(runtime, *ACCOUNT_Y, input_ids.clone(), false),
    );

    // Prepare the atomic transfer
    let exec_id = prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids, true).unwrap();

    // Check that balances have not changed yet
    check_balances(runtime, &balances);

    // Rollback the atomic transfer
    rollback_atomic_transfer(runtime, COORD_ACTOR.clone(), exec_id.clone()).unwrap();

    // Check that balances have not changed
    check_balances(runtime, &balances);

    // Initiate identical atomic transfer again
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];

    // Check that an identical but newly initiated atomic transfer
    // yields a fresh atomic execution ID
    assert_ne!(
        prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids, true).unwrap(),
        exec_id,
    );
}

#[test]
fn test_cancel_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let balances = INITIAL_BALANCES.clone();

    // Initiate atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();

    // Try to cancel foreign atomic transfer
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "unexpected sender address",
        cancel_atomic_transfer(runtime, *ACCOUNT_Y, &input_id),
    );

    // Cancel own atomic transfer
    cancel_atomic_transfer(runtime, *ACCOUNT_X, &input_id).unwrap();

    // Check that balances have not changed
    check_balances(runtime, &balances);
}

#[test]
fn test_commit_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let mut balances = INITIAL_BALANCES.clone();

    let other_input_id = (
        TOKEN_ACTOR_B.clone(),
        AtomicInputID::from(Vec::from("other input ID")),
    );

    // Initiate and prepare atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];
    let exec_id = prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids, true).unwrap();

    // Rollback the atomic transfer
    rollback_atomic_transfer(runtime, COORD_ACTOR.clone(), exec_id.clone()).unwrap();

    // Try to commit aborted atomic transfer
    expect_abort_contains_message(
        ExitCode::USR_UNSPECIFIED,
        "unexpected exec ID",
        commit_atomic_transfer(runtime, COORD_ACTOR.clone(), exec_id),
    );

    // Initiate and prepare atomic transfer again
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];
    let exec_id = prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids, true).unwrap();

    // Check that balances have not changed yet
    check_balances(runtime, &balances);

    // Commit atomic transfer
    commit_atomic_transfer(runtime, COORD_ACTOR.clone(), exec_id).unwrap();

    // Adjust local balance table accordingly
    *balances.get_mut(&*ACCOUNT_X).unwrap() -= TokenAmount::from_whole(1);
    *balances.get_mut(&*ACCOUNT_Y).unwrap() += TokenAmount::from_whole(1);

    // Check the resulting balances
    check_balances(runtime, &balances);
}

#[test]
fn test_abort_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let balances = INITIAL_BALANCES.clone();

    let other_input_id = (
        TOKEN_ACTOR_B.clone(),
        AtomicInputID::from(Vec::from("other input ID")),
    );

    // Initiate and prepare atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];
    let exec_id = prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids.clone(), true).unwrap();

    // Try to abort foreign atomic transfer
    expect_abort_contains_message(
        ExitCode::USR_FORBIDDEN,
        "unexpected sender address",
        abort_atomic_transfer(
            runtime,
            *ACCOUNT_Y,
            input_ids.clone(),
            exec_id.clone(),
            false,
        ),
    );

    // Abort the atomic transfer
    abort_atomic_transfer(runtime, *ACCOUNT_X, input_ids, exec_id, true).unwrap();

    // Check that balances have not changed
    check_balances(runtime, &balances);
}

#[test]
fn test_rollback_atomic_transfer() {
    let runtime = &mut construct_runtime();
    let balances = INITIAL_BALANCES.clone();

    let other_input_id = (
        TOKEN_ACTOR_B.clone(),
        AtomicInputID::from(Vec::from("other input ID")),
    );

    // Initiate and prepare atomic transfer
    let input_id =
        init_atomic_transfer(runtime, *ACCOUNT_X, *ACCOUNT_Y, TokenAmount::from_whole(1)).unwrap();
    let own_input_id = (OWN_IPC_ADDR.clone(), input_id);
    let input_ids = vec![own_input_id, other_input_id.clone()];
    let exec_id = prepare_atomic_transfer(runtime, *ACCOUNT_X, input_ids.clone(), true).unwrap();

    // Rollback the atomic transfer
    rollback_atomic_transfer(runtime, COORD_ACTOR.clone(), exec_id.clone()).unwrap();

    // Check that balances have not changed
    check_balances(runtime, &balances);
}

lazy_static::lazy_static! {
    static ref IPC_ADDR_PLACEHOLDER: IPCAddress = IPCAddress::new(
        &SubnetID::default(),
        &Address::new_bls(&[0; fvm_shared::address::BLS_PUB_LEN]).unwrap(),
    ).unwrap();

    static ref IPC_GATEWAY_ADDR: Address = Address::new_id(64);

    static ref INITIAL_BALANCES: HashMap<Address, TokenAmount> = HashMap::from([
        (*ACCOUNT_X, TokenAmount::from_whole(1)),
        (*ACCOUNT_Y, TokenAmount::from_whole(2)),
    ]);
    static ref TOTAL_SUPPLY: TokenAmount = INITIAL_BALANCES.iter().fold(
        TokenAmount::zero(),
        |t, (_a, b)| t + b
    );
    static ref CONSTRUCTOR_PARAMS: ConstructorParams = ConstructorParams {
        ipc_gateway: *IPC_GATEWAY_ADDR,
        subnet_id: SUBNET_A.clone(),
        name: String::from("TestCoin"),
        symbol: String::from("TST"),
        balances: INITIAL_BALANCES.iter().map(
            |(a, b)| (a.to_string(), b.clone())
        ).collect(),
    };
    static ref OWN_IPC_ADDR: IPCAddress =
        IPCAddress::new(&CONSTRUCTOR_PARAMS.subnet_id, &TOKEN_ACTOR_A.raw_addr().unwrap()).unwrap();

    static ref COORD_ACTOR: IPCAddress = IPCAddress::new(&ROOTNET_ID, &Address::new_id(1)).unwrap();

    static ref SUBNET_A: SubnetID = SubnetID::new_from_parent(&ROOTNET_ID, Address::new_id('A' as u64));
    static ref TOKEN_ACTOR_A: IPCAddress = IPCAddress::new(&*SUBNET_A, &Address::new_id(100)).unwrap();
    static ref ACCOUNT_X: Address = Address::new_id('X' as u64);
    static ref ACCOUNT_Y: Address = Address::new_id('Y' as u64);

    static ref SUBNET_B: SubnetID = SubnetID::new_from_parent(&ROOTNET_ID, Address::new_id('B' as u64));
    static ref TOKEN_ACTOR_B: IPCAddress = IPCAddress::new(&*SUBNET_B, &Address::new_id(100)).unwrap();
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

    runtime.expect_validate_caller_addr(vec![INIT_ACTOR_ADDR]);

    runtime
        .call::<Actor>(
            Method::Constructor as u64,
            IpldBlock::serialize_cbor(&*CONSTRUCTOR_PARAMS).unwrap(),
        )
        .unwrap();

    runtime
}

fn construct_runtime() -> MockRuntime {
    let receiver = OWN_IPC_ADDR.raw_addr().unwrap();
    construct_runtime_with_receiver(receiver)
}

fn check_balances(runtime: &mut MockRuntime, balances: &HashMap<Address, TokenAmount>) {
    for (a, b) in balances {
        assert_eq!(balance(runtime, a).unwrap(), *b);
    }
}

fn balance(runtime: &mut MockRuntime, address: &Address) -> Result<TokenAmount, ActorError> {
    runtime
        .call::<Actor>(
            Method::Balance as u64,
            IpldBlock::serialize_cbor(&address).unwrap(),
        )
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn name(runtime: &mut MockRuntime) -> Result<String, ActorError> {
    runtime
        .call::<Actor>(Method::Name as u64, None)
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn symbol(runtime: &mut MockRuntime) -> Result<String, ActorError> {
    runtime
        .call::<Actor>(Method::Symbol as u64, None)
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn total_supply(runtime: &mut MockRuntime) -> Result<TokenAmount, ActorError> {
    runtime
        .call::<Actor>(Method::TotalSupply as u64, None)
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn transfer(
    runtime: &mut MockRuntime,
    from: Address,
    to: Address,
    amount: TokenAmount,
) -> Result<(TokenAmount, TokenAmount), ActorError> {
    runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, from);
    runtime
        .call::<Actor>(
            Method::Transfer as u64,
            IpldBlock::serialize_cbor(&TransferParams { to, amount }).unwrap(),
        )
        .map(|ret| {
            let TransferReturn {
                from_balance,
                to_balance,
            } = ret.unwrap().deserialize().unwrap();
            (from_balance, to_balance)
        })
}

fn init_atomic_transfer(
    runtime: &mut MockRuntime,
    from: Address,
    to: Address,
    amount: TokenAmount,
) -> Result<AtomicInputID, ActorError> {
    runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, from);
    runtime
        .call::<Actor>(
            Method::InitAtomicTransfer as u64,
            IpldBlock::serialize_cbor(&InitAtomicTransferParams {
                coordinator: COORD_ACTOR.clone(),
                transfer: TransferParams { to, amount },
            })
            .unwrap(),
        )
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn cancel_atomic_transfer(
    runtime: &mut MockRuntime,
    from: Address,
    input_id: &AtomicInputID,
) -> Result<(), ActorError> {
    runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, from);
    runtime
        .call::<Actor>(
            Method::CancelAtomicTransfer as u64,
            IpldBlock::serialize_cbor(&input_id).unwrap(),
        )
        .map(|ret| assert_eq!(ret, None))
}

fn prepare_atomic_transfer(
    runtime: &mut MockRuntime,
    from: Address,
    input_ids: Vec<(IPCAddress, AtomicInputID)>,
    expect_ok: bool,
) -> Result<AtomicExecID, ActorError> {
    if expect_ok {
        let exec_id = AtomicExecRegistry::compute_exec_id(&input_ids);
        runtime.expect_send(
            *IPC_GATEWAY_ADDR,
            ipc_gateway::Method::SendCross as u64,
            pre_commit_params(
                input_ids.iter().map(|(a, _)| a.clone()).collect(),
                exec_id.clone(),
                Method::CommitAtomicTransfer as MethodNum,
            ),
            TokenAmount::default(),
            None,
            ExitCode::OK,
        );
    }

    runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, from);
    runtime
        .call::<Actor>(
            Method::PrepareAtomicTransfer as u64,
            IpldBlock::serialize_cbor(&PrepareAtomicTransferParams { input_ids }).unwrap(),
        )
        .map(|ret| ret.unwrap().deserialize().unwrap())
}

fn abort_atomic_transfer(
    runtime: &mut MockRuntime,
    from: Address,
    input_ids: Vec<(IPCAddress, AtomicInputID)>,
    exec_id: AtomicExecID,
    expect_ok: bool,
) -> Result<(), ActorError> {
    let actors: Vec<_> = input_ids.iter().map(|(a, _)| a.clone()).collect();
    if expect_ok {
        let exec_id = AtomicExecRegistry::compute_exec_id(&input_ids);
        runtime.expect_send(
            *IPC_GATEWAY_ADDR,
            ipc_gateway::Method::SendCross as u64,
            revoke_params(
                actors.clone(),
                exec_id.clone(),
                Method::RollbackAtomicTransfer as MethodNum,
            ),
            TokenAmount::default(),
            None,
            ExitCode::OK,
        );
    }

    runtime.set_caller(*ACCOUNT_ACTOR_CODE_ID, from);
    runtime
        .call::<Actor>(
            Method::AbortAtomicTransfer as u64,
            IpldBlock::serialize_cbor(&AbortAtomicTransferParams { actors, exec_id }).unwrap(),
        )
        .map(|ret| assert_eq!(ret, None))
}

fn commit_atomic_transfer(
    runtime: &mut MockRuntime,
    from: IPCAddress,
    exec_id: AtomicExecID,
) -> Result<(), ActorError> {
    runtime.set_caller(Cid::default(), IPC_GATEWAY_ADDR.clone());
    runtime.expect_validate_caller_addr(vec![IPC_GATEWAY_ADDR.clone()]);
    runtime
        .call::<Actor>(
            Method::CommitAtomicTransfer as u64,
            commit_params(from, OWN_IPC_ADDR.clone(), exec_id),
        )
        .map(|ret| assert_eq!(ret, None))
}

fn rollback_atomic_transfer(
    runtime: &mut MockRuntime,
    from: IPCAddress,
    exec_id: AtomicExecID,
) -> Result<(), ActorError> {
    runtime.set_caller(Cid::default(), IPC_GATEWAY_ADDR.clone());
    runtime.expect_validate_caller_addr(vec![IPC_GATEWAY_ADDR.clone()]);
    runtime
        .call::<Actor>(
            Method::RollbackAtomicTransfer as u64,
            rollback_params(from, OWN_IPC_ADDR.clone(), exec_id),
        )
        .map(|ret| assert_eq!(ret, None))
}

fn pre_commit_params(
    actors: Vec<IPCAddress>,
    exec_id: AtomicExecID,
    commit: MethodNum,
) -> Option<IpldBlock> {
    IpldBlock::serialize_cbor(&wrap_cross_msg(
        IPC_ADDR_PLACEHOLDER.clone(),
        COORD_ACTOR.clone(),
        ipc_atomic_execution::Method::PreCommit as MethodNum,
        RawBytes::serialize(
            &(ipc_atomic_execution::PreCommitParams {
                actors,
                exec_id,
                commit,
            }),
        )
        .unwrap(),
    ))
    .unwrap()
}

fn revoke_params(
    actors: Vec<IPCAddress>,
    exec_id: AtomicExecID,
    rollback: MethodNum,
) -> Option<IpldBlock> {
    IpldBlock::serialize_cbor(&wrap_cross_msg(
        IPC_ADDR_PLACEHOLDER.clone(),
        COORD_ACTOR.clone(),
        ipc_atomic_execution::Method::Revoke as MethodNum,
        RawBytes::serialize(
            &(ipc_atomic_execution::RevokeParams {
                actors,
                exec_id,
                rollback,
            }),
        )
        .unwrap(),
    ))
    .unwrap()
}

fn rollback_params(from: IPCAddress, to: IPCAddress, exec_id: AtomicExecID) -> Option<IpldBlock> {
    IpldBlock::serialize_cbor(&ipc_gateway::ApplyMsgParams {
        cross_msg: wrap_cross_msg(
            from,
            to,
            Method::RollbackAtomicTransfer as MethodNum,
            exec_id,
        ),
    })
    .unwrap()
}

fn commit_params(from: IPCAddress, to: IPCAddress, exec_id: AtomicExecID) -> Option<IpldBlock> {
    IpldBlock::serialize_cbor(&ipc_gateway::ApplyMsgParams {
        cross_msg: wrap_cross_msg(from, to, Method::CommitAtomicTransfer as MethodNum, exec_id),
    })
    .unwrap()
}

fn wrap_cross_msg(
    from: IPCAddress,
    to: IPCAddress,
    method: MethodNum,
    params: RawBytes,
) -> CrossMsg {
    CrossMsg {
        msg: StorableMsg {
            from,
            to,
            method,
            params,
            value: TokenAmount::default(),
            nonce: 0,
        },
        wrapped: true,
    }
}
