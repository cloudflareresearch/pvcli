use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerretError {
    // argument parsing
    #[error("invalid argument: {0}")]
    InvalidArg(String),

    // URL/URI parsing
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("invalid URI: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    // HTTP/network
    #[error("client error: {0}")]
    ClientError(#[from] hyper_util::client::legacy::Error),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::Error),

    // TLS
    #[error("TLS error: {0}")]
    TlsError(String),

    // response validation
    #[error("unexpected status {status}: {message}")]
    UnexpectedStatus { status: u16, message: String },
}

pub type Result<T> = std::result::Result<T, FerretError>;
