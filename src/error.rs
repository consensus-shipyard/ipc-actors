use fil_actors_runtime::ActorError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error("invalid address payload")]
    InvalidPayload,
    #[error("invalid subnet id")]
    InvalidID,
    #[error("invalid IPC address")]
    InvalidIPCAddr,
    #[error("fvm shared address error")]
    FVMAddressError(fvm_shared::address::Error),
    #[error("unsigned variant decode error")]
    UnsignedVariantDecodeError(unsigned_varint::decode::Error),
    #[error("unknown network")]
    UnknownNetwork,
    #[error("hex encoding error")]
    HexEncoding(FromHexError),
    #[error("actor error")]
    Actor(ActorError),
}

impl From<ActorError> for Error {
    fn from(e: ActorError) -> Self {
        Self::Actor(e)
    }
}
impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        Self::HexEncoding(e)
    }
}

impl From<fvm_shared::address::Error> for Error {
    fn from(e: fvm_shared::address::Error) -> Self {
        Error::FVMAddressError(e)
    }
}

impl From<unsigned_varint::decode::Error> for Error {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        Error::UnsignedVariantDecodeError(e)
    }
}
