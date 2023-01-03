# IPC Subnet Actor
Reference implementation of the InterPlanetary Consensus (IPC) subnet actor. This implementation
targets the Filecoin FVM. Subnet actors are responsible for implementing the logic
that governs the operation of subnets. 

Subnet actors are deployed in the parent network from which the subnet wants to be
spawned, and it interacts with the Subnet Coordinator Actor for its operation. In order
to deploy your own subnet you can either deploy this reference implementation, or implement
your own actor with your own custom policies to fit the needs of your subnet and applications.

_Disclaimer: The subnet actor is a user-defined actor that target the Filecoin FVM. IPC
is being ported to target FVM, if you are looking to use IPC in its full potential
in the meantime have a look at the current MVP [here](https://github.com/filecoin-project/eudico)__
