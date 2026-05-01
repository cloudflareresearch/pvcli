use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerretError {
    // TODO
    #[error("TODO: {0}")]
    Todo(String),

    // argument parsing
    #[error("invalid argument: {0}")]
    InvalidArg(String),

    // URL/URI parsing
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    // HTTP/network
    #[error("client error: {0}")]
    ClientError(#[from] hyper_util::client::legacy::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::Error),

    // TLS
    #[error("TLS Certificate error: {0}")]
    CertificateError(String),

    // response validation
    #[error("unexpected status {status}: {message}")]
    UnexpectedStatus { status: u16, message: String },
}

impl From<rustls_pemfile::Error> for FerretError {
    fn from(e: rustls_pemfile::Error) -> Self {
        FerretError::CertificateError(format!("{:?}", e))
    }
}

pub type Result<T> = std::result::Result<T, FerretError>;
