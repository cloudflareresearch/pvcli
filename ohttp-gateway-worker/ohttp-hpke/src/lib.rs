use std::{error, io};

mod config;
mod decapsulated;
mod encapsulated;
mod header;
mod instance;
mod response;

pub mod client;
pub mod keys;
pub mod server;

pub use self::config::{AeadId, KdfId, KemId};
pub use stream_buf::StreamBuf;

fn invalid_data(e: impl Into<Box<dyn error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
