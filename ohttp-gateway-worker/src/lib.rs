use ohttp_hpke::server::{
    decode_request_header, RequestReceivingContext, ResponseSendingContext, ServerConfig,
};
use stream_buf::StreamBuf;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use worker::*;

const MESSAGE_BHTTP_REQUEST: &str = "message/bhttp request";
const MESSAGE_BHTTP_RESPONSE: &str = "message/bhttp response";

const MESSAGE_BHTTP_CHUNKED_REQUEST: &str = "message/bhttp chunked request";
const MESSAGE_BHTTP_CHUNKED_RESPONSE: &str = "message/bhttp chunked response";

#[derive(Clone, Copy, Debug)]
pub enum ObliviousGatewayReqKind {
    OhttpReq,
    OhttpChunkedReq,
}

impl ObliviousGatewayReqKind {
    pub(crate) fn from_req(req: &HttpRequest) -> Option<ObliviousGatewayReqKind> {
        if req.method() != http::Method::POST {
            return None;
        }

        let content_type = req.headers().get(http::header::CONTENT_TYPE)?;

        match content_type.as_bytes() {
            b"message/ohttp-req" => Some(Self::OhttpReq),
            b"message/ohttp-chunked-req" => Some(Self::OhttpChunkedReq),
            _ => None,
        }
    }

    pub(crate) fn response_content_type(self) -> &'static str {
        match self {
            Self::OhttpReq => "message/ohttp-res",
            Self::OhttpChunkedReq => "message/ohttp-chunked-res",
        }
    }
}

async fn extract_receiving_hpke_context(
    stream: &mut StreamBuf<http_body_util::BodyDataStream<worker::Body>>,
    hpke_config: &ServerConfig,
    req_kind: ObliviousGatewayReqKind,
) -> worker::Result<(RequestReceivingContext, ResponseSendingContext)> {
    let (request_info_str, response_info_str) = match req_kind {
        ObliviousGatewayReqKind::OhttpReq => (MESSAGE_BHTTP_REQUEST, MESSAGE_BHTTP_RESPONSE),
        ObliviousGatewayReqKind::OhttpChunkedReq => (
            MESSAGE_BHTTP_CHUNKED_REQUEST,
            MESSAGE_BHTTP_CHUNKED_RESPONSE,
        ),
    };

    let ctxts =
        decode_request_header(hpke_config, request_info_str, response_info_str, stream).await?;

    Ok(ctxts)
}

async fn convert_hpke_bhttp_stream_into_request(
    request_receiving_hpke_context: RequestReceivingContext,
    req_kind: ObliviousGatewayReqKind,
    mut stream: StreamBuf<http_body_util::BodyDataStream<worker::Body>>,
) -> worker::Result<web_sys::Request> {
    match req_kind {
        ObliviousGatewayReqKind::OhttpReq => {
            let bhttp_req_bytes = request_receiving_hpke_context
                .decapsulate_non_chunked_content(&mut stream)
                .await?;

            // Some type shenanigans to fool the compiler. It complains because the type of E is unknown
            // for `EmptyStreamBuf<E> where E: From<io::Error>`, but the implementation can never actually
            // throw an error.
            struct InfallibleType;
            impl From<std::io::Error> for InfallibleType {
                fn from(_: std::io::Error) -> Self {
                    InfallibleType
                }
            }

            impl From<InfallibleType> for worker::Error {
                fn from(_: InfallibleType) -> Self {
                    worker::Error::Infallible
                }
            }

            let request = Box::new(
                hyper_binary::decode_request::<_, _, InfallibleType>(StreamBuf::from(
                    bhttp_req_bytes,
                ))
                .await?,
            );

            to_wasm(*request)
        }
        ObliviousGatewayReqKind::OhttpChunkedReq => {
            let bhttp_req_stream =
                request_receiving_hpke_context.decapsulate_chunked_content(stream);

            let stream = StreamBuf::new(bhttp_req_stream);
            let request = Box::new(hyper_binary::decode_request(stream).await?);
            to_wasm(*request)
        }
    }
}

pub(crate) async fn get_inner_oblivious_gateway_request(
    req_body: worker::Body,
    req_kind: ObliviousGatewayReqKind,
    hpke_config: &ServerConfig,
) -> worker::Result<(web_sys::Request, ResponseSendingContext)> {
    let mut stream = StreamBuf::new(http_body_util::BodyDataStream::new(req_body));

    let (request_receiving_context, response_sending_context) =
        extract_receiving_hpke_context(&mut stream, hpke_config, req_kind).await?;

    let inner_req =
        convert_hpke_bhttp_stream_into_request(request_receiving_context, req_kind, stream).await?;

    Ok((inner_req, response_sending_context))
}

// Caution: `dyn_into()` is a dynamic runtime cast. We are basically doing Javascript from Rust.
async fn fetch_with_request(request: &web_sys::Request) -> Result<worker::Body> {
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let promise = worker.fetch_with_request(request);
    let resp = JsFuture::from(promise).await?;
    let edge_response: web_sys::Response = resp.dyn_into()?;
    edge_response
        .body()
        .ok_or(worker::Error::BodyUsed)
        .map(|stream| worker::Body::new(stream))
}

#[derive(Clone, Debug)]
struct ObliviousGatewayReqExt {
    req_kind: ObliviousGatewayReqKind,
    response_sending_context: ResponseSendingContext,
}

fn wrap_inner_oblivious_gateway_response(
    inner_res: worker::HttpResponse,
    req_ext: ObliviousGatewayReqExt,
) -> Result<worker::HttpResponse> {
    let binary_encoded_res = hyper_binary::encode_response(inner_res);

    let encoded_res_stream = StreamBuf::new(binary_encoded_res);

    let encapsulated_res_stream = match req_ext.req_kind {
        ObliviousGatewayReqKind::OhttpReq => req_ext
            .response_sending_context
            .encapsulate_non_chunked_content(encoded_res_stream),
        ObliviousGatewayReqKind::OhttpChunkedReq => req_ext
            .response_sending_context
            .encapsulate_chunked_content(encoded_res_stream),
    };

    Ok(worker::HttpResponse::new(worker::Body::from_stream(
        encapsulated_res_stream,
    )?))
}

fn get_hpke_config() -> &'static ServerConfig {
    static CONFIG: std::sync::OnceLock<ServerConfig> = std::sync::OnceLock::new();

    CONFIG.get_or_init(|| {
        let mut server_config = ohttp_hpke::server::ServerConfig::default();
        let key_pair = ohttp_hpke::keys::derive_key_pair(
            ohttp_hpke::KemId::X25519HkdfSha256,
            "abcdefghijklmnopqrstuvwxyz012345".as_bytes(),
        );

        server_config
            .add_key_config(
                key_pair,
                vec![(ohttp_hpke::KdfId::HkdfSha256, ohttp_hpke::AeadId::AesGcm128)],
            )
            .unwrap();

        server_config
    })
}

/// `fetch` in V8 will fail if a GET or HEAD request has a body. By default `request_to_wasm`
/// will *always* set a body, so we transform our request by creating an empty body, which uses
/// an implementation detail in `request_to_wasm` to avoid setting the body.
fn to_wasm<B: http_body::Body<Data = bytes::Bytes> + 'static>(
    req: http::Request<B>,
) -> Result<web_sys::Request> {
    let method = req.method();
    if method == http::method::Method::GET || method == http::method::Method::HEAD {
        let (parts, _) = req.into_parts();
        let request_without_body =
            http::Request::from_parts(parts, http_body_util::Empty::<bytes::Bytes>::new());
        return request_to_wasm(request_without_body);
    }
    request_to_wasm(req)
}

#[event(fetch)]
async fn fetch(req: HttpRequest, _env: Env, _ctx: Context) -> Result<HttpResponse> {
    let server_config = get_hpke_config();

    match req.uri().path() {
        "/gateway" => {
            let kind = ObliviousGatewayReqKind::from_req(&req).ok_or(worker::Error::RustError(
                String::from("not a gateway request"),
            ))?;

            let body = req.into_body();
            let (web_request, sending_context) =
                get_inner_oblivious_gateway_request(body, kind, &server_config).await?;

            let req_ext = ObliviousGatewayReqExt {
                req_kind: kind,
                response_sending_context: sending_context,
            };

            let content_type = req_ext.req_kind.response_content_type();

            let unencapsulated_response = fetch_with_request(&web_request).await?;
            let mut encapsulated_response = wrap_inner_oblivious_gateway_response(
                HttpResponse::new(unencapsulated_response),
                req_ext,
            )?;

            let status = encapsulated_response.status_mut();
            *status = http::StatusCode::OK;
            let headers = encapsulated_response.headers_mut();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(content_type),
            );

            Ok(encapsulated_response)
        }
        "/ohttp-config" => worker::ResponseBuilder::new()
            .with_status(http::StatusCode::OK.into())
            .with_header("content-type", "application/ohttp-keys")?
            .body(worker::ResponseBody::Body(
                ohttp_hpke::server::encode_config(&server_config),
            ))
            .try_into(),
        _ => worker::ResponseBuilder::new()
            .with_status(http::StatusCode::OK.into())
            .body(worker::ResponseBody::Empty)
            .try_into(),
    }
}
