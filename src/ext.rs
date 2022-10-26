pub mod account {
    pub const PUBKEY_ADDRESS_METHOD: u64 = 2;
}

pub mod reward {
    use fvm_shared::address::Address;
    use fvm_shared::econ::TokenAmount;
    use serde::{Deserialize, Serialize};

    pub const EXTERNAL_FUNDING_METHOD: u64 = 5;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct FundingParams {
        pub value: TokenAmount,
        pub addr: Address,
    }
}
