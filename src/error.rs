use log::Level::Error;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error("invalid subnet id")]
    InvalidID,
    #[error("invalid hierarchical address")]
    InvalidHierarchicalAddr,
    #[error("fvm shared address error")]
    FVMAddressError(fvm_shared::address::Error),
}

impl From<fvm_shared::address::Error> for Error {
    fn from(e: fvm_shared::address::Error) -> Self {
        Error::FVMAddressError(e)
    }
}
