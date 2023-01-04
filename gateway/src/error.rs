use fil_actors_runtime::ActorError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("fvm shared address error")]
    FVMAddress(fvm_shared::address::Error),
    #[error("unsigned variant decode error")]
    UnsignedVariantDecode(unsigned_varint::decode::Error),
    #[error("actor error")]
    Actor(ActorError),
}

impl From<ActorError> for Error {
    fn from(e: ActorError) -> Self {
        Self::Actor(e)
    }
}

impl From<fvm_shared::address::Error> for Error {
    fn from(e: fvm_shared::address::Error) -> Self {
        Error::FVMAddress(e)
    }
}

impl From<unsigned_varint::decode::Error> for Error {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        Error::UnsignedVariantDecode(e)
    }
}
