// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use std::{error, io};

mod decoder;
mod encoder;

pub use self::decoder::{decode_request, decode_response, DecodedBody};
pub use self::encoder::{encode_request, encode_response, EncodedMessage, EncodedMessageKind};
pub use stream_buf::StreamBuf;

fn invalid_data(e: impl Into<Box<dyn error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
