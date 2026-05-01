use std::{error, io};

mod decoder;
mod encoder;

pub use self::decoder::{decode_request, decode_response, DecodedBody};
pub use self::encoder::{encode_request, encode_response, EncodedMessage, EncodedMessageKind};
pub use stream_buf::StreamBuf;

fn invalid_data(e: impl Into<Box<dyn error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
