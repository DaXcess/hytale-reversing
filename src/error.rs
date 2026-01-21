use thiserror::Error;

#[derive(Error, Debug)]
pub enum AotError {
    #[error("This image/blob is corrupt or malformed")]
    BadImage,

    #[error("The value for the metadata handle is invalid")]
    InvalidMetaHandle,
}

pub type Result<T> = ::core::result::Result<T, AotError>;
