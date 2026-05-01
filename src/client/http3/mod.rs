pub mod chaussette;

use super::{HttpClient, HttpResponse};
use crate::{args::RequestArgs, error::FerretError};
use color_eyre::eyre::Result;

pub struct Http3Client {}

impl HttpClient for Http3Client {
    async fn send_request(&self, _args: RequestArgs) -> Result<HttpResponse> {
        Err(FerretError::Todo(
            "HTTP3 client not implemented yet".to_string(),
        ))?
    }
}

impl Http3Client {
    async fn new() -> Result<Self> {
        Ok(Self {})
    }
}
