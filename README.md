# IPC Actors
> The IPC actors are still under-development, and this README is a work-in-progress (so expect bugs, typos, et. al). A final version of the README will be provided once the development of the actors is finalized.

This repository includes the reference implementation of all the actors responsible for the operation of the IPC (InterPlanerary Consensus) protocol. These actors are written in Rust to be compiled in web assembly, and they target the FVM. This project is conformed by the following crates:
- `gateway`: Implementation of the IPC gateway.
- `subnet-actor`: Reference implementation of an IPC subnet actor.
- `atomic-exec`: Implementation of the atomic-execution coordinator actor along with all the basic primitives to run an atomic execution, and a sample fungible token contract implementing these primitives.
- `sdk`: SDK with convenient types and methods to interact with IPC.

## Building the actors
Building the actors in wasm is as simple as running `make build`. This command outputs the wasm bytecode for all of the actors in the `output/` directory.

### Bundling into the builtin-actors bundle
The FVM does not currently support the deployment of user-defined native actors, so in order to deploy these native IPC actors, they need to be conveniently bundled into the builtin-actors bundle. To create a builtin-actors bundle including the IPC actors you can follow these steps: 
```bash
# Compile IPC actors
make build
# Clone our fork of builtin-actors including custom bundling code.
git https://github.com/adlrocha/builtin-actors
# We are currently building the v10 bundle from the `next` branch
git checkout next
# We need to point to the directory where the IPC actors have been compiled so they can be picked update
# by the builtin-actors bundling script
export IPC_ACTORS_PATH="<path_to>/ipc-actors/output"
# Build the bundle
BUILD_FIL_NETWORK="devnet" cargo build
```
The build command should return a similar output to the following, indicating all the actors that have been bundled and the path of the resulting `.car` file with the bundle.
```
warning: "    Finished wasm [optimized] target(s) in 0.17s"
warning: added system (1) to bundle with CID bafk2bzacec54dumnosca6raux5ncumxztwpvzwco77yxyscljx4lfh23qhwrq
warning: added init (2) to bundle with CID bafk2bzacebutdlfcln3fqv567o5uqkyjhhkt7nx57qoca7ldaqinibdw6xdja
warning: added cron (3) to bundle with CID bafk2bzacebk3jbp7k7swbh6yhefjs6ohoux4jeiv2uzuqe3kw7tjqijhz5i22
warning: added account (4) to bundle with CID bafk2bzacecdc55oowmhaox7fec3vuve7l3izzyz5g6g7obrlnj35kftswqmim
warning: added storagepower (5) to bundle with CID bafk2bzaceae7klvc7taedumgwp5vsyz3ema4hzrdalzdcovfioey5qewl4ade
warning: added storageminer (6) to bundle with CID bafk2bzaced77vio3dxdnkfj33zqt3zlrpav3kxs2h7hqijmtvfbuxaakfofmc
warning: added storagemarket (7) to bundle with CID bafk2bzacecakhmuqp4nnmjfesa7epzkxlcesn35b3qiinykhbi425kjlylrq6
warning: added paymentchannel (8) to bundle with CID bafk2bzacecogm6lvoy3noi7fki673sh6xhidg4qrmvm5wblbo4k5sraedjvru
warning: added multisig (9) to bundle with CID bafk2bzacecw5wsymf4hdj2w4g4did46rmgvbz7vzighaeib6fllrsv22g2ffo
warning: added reward (10) to bundle with CID bafk2bzacecvlh7qzoymct2bh7tpto7stbknoovso6ubvkegiksihsak4f3qha
warning: added verifiedregistry (11) to bundle with CID bafk2bzacedap2nybmduf57shz4jq4otgpfmuetxcz3elv5yvr3xmut3ux6252
warning: added datacap (12) to bundle with CID bafk2bzacecvnqex5gbizbjkbtzi5fkvli2gzv4nfb72kg6g5ovrfmbb4o4h22
warning: added placeholder (13) to bundle with CID bafk2bzacecvfsdi3lix4fnwhhov6krl5jevplcuzxj75ctxyjtcxphobhst54
warning: added evm (14) to bundle with CID bafk2bzacebcguwmy54idds6ta5j6hyg3ucrch2bkrqf3wlyqwqp4vqb7bxdhk
warning: added eam (15) to bundle with CID bafk2bzacecy4rxlebx77uv2kxmefbwfmwtxaadykwb32h3js55dbqagqadrfo
warning: added ethaccount (16) to bundle with CID bafk2bzacedaf7y2oltgsfs5fehcmgcmcup4u6de7uhk5nmssiqhezrbatixeg
warning: added ipc_gateway (17) to bundle with CID bafk2bzacecfdx72pqpgrtu7ssac72pfxalwyu7ikd64dgdnv77dnh3pwvovho
warning: added ipc_subnet_actor (18) to bundle with CID bafk2bzacecjsllbq7746oraqrmnbzpeh3k22l6sqwtvrgp3xw4urv6jaqeoci
warning: added ipc_atomic_execution (19) to bundle with CID bafk2bzacecfdx72pqpgrtu7ssac72pfxalwyu7ikd64dgdnv77dnh3pwvovho
warning: bundle=/home/workspace/pl/builtin-actors/target/debug/build/fil_builtin_actors_bundle-26e03a20c6387edc/out/bundle/bundle.car
```
Finally, to load the bundle into Lotus, the following env variable need to be set pointing to the car of our custom bundle:
```
export LOTUS_BUILTIN_ACTORS_V10_BUNDLE=<path_to_custom_car>
```
