# IPC Subnet Actor
Reference implementation of the InterPlanetary Consensus (IPC) subnet actor. This implementation
targets the Filecoin FVM. Subnet actors are responsible for implementing the logic
that governs the operation of subnets. 

Subnet actors are deployed in the parent network from which the subnet wants to be
spawned, and it interacts with the Subnet Coordinator Actor for its operation. In order
to deploy your own subnet you can either deploy this reference implementation, or implement
your own actor with your own custom policies to fit the needs of your subnet and applications.
