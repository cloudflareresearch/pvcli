use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerretError {
    // TODO
    #[error("TODO: {0}")]
    Todo(String),

    // HPKE Error wrapper
    #[error("HPKE error: {0}")]
    HpkeError(String),

    // response validation
    #[error("Unexpected status {status}: {message}")]
    UnexpectedStatus { status: u16, message: String },
}

impl From<hpke::HpkeError> for FerretError {
    fn from(e: hpke::HpkeError) -> Self {
        FerretError::HpkeError(format!("{:?}", e))
    }
}
