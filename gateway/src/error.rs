use fil_actors_runtime::ActorError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

impl From<unsigned_varint::decode::Error> for Error {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        Error::UnsignedVariantDecode(e)
    }
}
