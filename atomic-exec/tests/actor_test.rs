use cid::Cid;
use fil_actors_runtime::{
    test_utils::{expect_abort, MockRuntime},
    INIT_ACTOR_ADDR,
};
use fvm_ipld_encoding::RawBytes;
use fvm_shared::{address::Address, econ::TokenAmount, error::ExitCode, MethodNum};
use ipc_atomic_execution::{Actor, AtomicExecID, ConstructorParams, Method, PreCommitParams};
use ipc_gateway::{ApplyMsgParams, CrossMsg, IPCAddress, StorableMsg, SubnetID};
use ipc_sdk::subnet_id::ROOTNET_ID;

#[test]
fn test_pre_commit_wrong_origin() {
    let mut runtime = construct_runtime();
    runtime.set_caller(Cid::default(), *IPC_GATEWAY_ADDR);
    runtime.expect_validate_caller_addr(vec![*IPC_GATEWAY_ADDR]);

    expect_abort(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        runtime.call::<Actor>(
            Method::PreCommit as u64,
            &pre_commit_params(
                ACTOR_B2.clone(),
                [&*ACTOR_A1, &*ACTOR_B1],
                AtomicExecID::default(),
            ),
        ),
    );
}

#[test]
fn test_pre_commit_works() {
    let mut runtime = construct_runtime();
    runtime.set_caller(Cid::default(), *IPC_GATEWAY_ADDR);

    let actors = [&*ACTOR_A1, &*ACTOR_B1];
    let exec_id = RawBytes::from(Vec::from("exec_id"));

    let mut actors_iter = actors.iter().cloned().peekable();
    while let Some(from) = actors_iter.next() {
        let last = actors_iter.peek().is_none();

        if last {
            for to in actors.iter().cloned() {
                runtime.expect_send(
                    *IPC_GATEWAY_ADDR,
                    ipc_gateway::Method::SendCross as MethodNum,
                    commit_params(to.clone(), exec_id.clone()),
                    TokenAmount::default(),
                    RawBytes::default(),
                    ExitCode::OK,
                );
            }
        }

        runtime.expect_validate_caller_addr(vec![*IPC_GATEWAY_ADDR]);
        let res: bool = runtime
            .call::<Actor>(
                Method::PreCommit as u64,
                &pre_commit_params(from.clone(), actors.iter().cloned(), exec_id.clone()),
            )
            .unwrap()
            .deserialize()
            .unwrap();
        assert_eq!(res, last);

        runtime.verify();
    }
}

lazy_static::lazy_static! {
    static ref IPC_ADDR_PLACEHOLDER: IPCAddress = IPCAddress::new(
        &SubnetID::default(),
        &Address::new_bls(&[0; fvm_shared::address::BLS_PUB_LEN]).unwrap(),
    ).unwrap();

    static ref IPC_GATEWAY_ADDR: Address = *ipc_gateway::SCA_ACTOR_ADDR;

    static ref CONSTRUCTOR_PARAMS: ConstructorParams = ConstructorParams {
        ipc_gateway_address: *IPC_GATEWAY_ADDR,
    };

    static ref COORD_ACTOR: IPCAddress = IPCAddress::new(&ROOTNET_ID, &Address::new_id(1)).unwrap();

    static ref SUBNET_A: SubnetID = SubnetID::new(&ROOTNET_ID, Address::new_id('A' as u64));
    static ref ACTOR_A1: IPCAddress = IPCAddress::new(&SUBNET_A, &Address::new_id(1)).unwrap();
    static ref ACTOR_A2: IPCAddress = IPCAddress::new(&SUBNET_A, &Address::new_id(2)).unwrap();

    static ref SUBNET_B: SubnetID = SubnetID::new(&ROOTNET_ID, Address::new_id('B' as u64));
    static ref ACTOR_B1: IPCAddress = IPCAddress::new(&SUBNET_B, &Address::new_id(1)).unwrap();
    static ref ACTOR_B2: IPCAddress = IPCAddress::new(&SUBNET_B, &Address::new_id(2)).unwrap();
}

const COMMIT_METHOD: MethodNum = 2;

fn construct_runtime_with_receiver(receiver: Address) -> MockRuntime {
    let caller = *INIT_ACTOR_ADDR;
    let mut runtime = MockRuntime::new(receiver, caller);

    runtime.expect_validate_caller_addr(vec![caller]);
    runtime
        .call::<Actor>(
            Method::Constructor as u64,
            &RawBytes::serialize(&*CONSTRUCTOR_PARAMS).unwrap(),
        )
        .unwrap();

    runtime
}

fn construct_runtime() -> MockRuntime {
    let receiver = COORD_ACTOR.raw_addr().unwrap();
    construct_runtime_with_receiver(receiver)
}

fn pre_commit_params<'a>(
    from: IPCAddress,
    actors: impl IntoIterator<Item = &'a IPCAddress>,
    exec_id: AtomicExecID,
) -> RawBytes {
    let actors = actors.into_iter().cloned().collect();
    RawBytes::serialize(ApplyMsgParams {
        cross_msg: wrap_cross_msg(
            from,
            COORD_ACTOR.clone(),
            Method::PreCommit as MethodNum,
            RawBytes::serialize(&PreCommitParams {
                actors: actors,
                exec_id,
                commit: COMMIT_METHOD,
            })
            .unwrap(),
        ),
    })
    .unwrap()
}

fn commit_params(to: IPCAddress, exec_id: AtomicExecID) -> RawBytes {
    RawBytes::serialize(wrap_cross_msg(
        IPC_ADDR_PLACEHOLDER.clone(),
        to,
        COMMIT_METHOD,
        exec_id,
    ))
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
