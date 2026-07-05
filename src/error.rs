use thiserror::Error;

#[derive(Error, Debug)]
pub enum PvcliError {
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

impl From<hpke::HpkeError> for PvcliError {
    fn from(e: hpke::HpkeError) -> Self {
        PvcliError::HpkeError(format!("{:?}", e))
    }
}
