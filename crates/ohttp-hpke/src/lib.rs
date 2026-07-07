// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

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
