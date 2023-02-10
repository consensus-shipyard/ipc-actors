#!/bin/bash
OUTPUT_DIR="${IPC_OUTPUT_DIR:=output}"  

rm -rf $OUTPUT_DIR/*
echo "Cleaning output directory $OUTPUT_DIR"
WASM_FLAGS="-Z unstable-options --target=wasm32-unknown-unknown --profile=wasm --locked --out-dir ${OUTPUT_DIR}"

echo "building IPC gateway"
GATEWAY_FLAGS="-p=ipc-gateway --features=fil-gateway-actor"
cargo build $WASM_FLAGS $GATEWAY_FLAGS

echo "building the rest of ipc-actors"
IPC_FLAGS="-p=ipc-subnet-actor -p=ipc_atomic_execution --features=fil-actor"
cargo build $WASM_FLAGS $IPC_FLAGS
