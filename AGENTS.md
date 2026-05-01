# AGENTS.md — ferret

A curl-like client for OHTTP, supporting GET and POST requests over HTTP/2 and HTTP/3 with TLS.

## STRUCTURE
```
ferret/
├── src/
│   ├── bin/
│   │   └── ferret/
│   │       └── main.rs         # Binary entry point (calls tunnel())
│   ├── client/
│   │   ├── mod.rs              # HttpClient trait, HttpClientKind enum, HttpResponse struct
│   │   ├── cert.rs             # X509ConnectionHook, CertSettings, build_ssl_context_builder
│   │   ├── http2.rs            # Http2Client: direct HTTP/2 requests with BoringSSL (hyper-boring)
│   │   ├── http3/              # HTTP/3 client module
│   │   │   ├── mod.rs          # Http3Client: QUIC/H3 requests via tokio-quiche
│   │   │   ├── body.rs         # H3Body type for streaming response bodies
│   │   │   ├── connection.rs   # QUIC connection management, SendRequest handle
│   │   │   └── logging.rs      # H3ConnectionLogger: structured logging for H3 connections
│   │   ├── ohttp.rs            # OHttpClient: OHTTP-encrypted requests via proxy (H2 or H3)
│   │   └── request.rs          # RequestHandler trait: shared request building/dispatch logic
│   ├── lib.rs                  # Core logic: run(), select_http_client(), logging setup
│   ├── args.rs                 # CLI argument definitions (clap), Args validation
│   └── error.rs                # FerretError enum (thiserror)
├── tests/
│   ├── integration_tests.rs    # Integration tests for HTTP2, HTTP3, and OHTTP clients
│   ├── common/
│   │   └── mod.rs              # Mock server setup, test constants
│   └── testdata.txt            # Test fixture file
├── ohttp-gateway-worker/       # Local OHTTP gateway worker
│   ├── hyper-binary/           # BHTTP encoding/decoding
│   ├── ohttp-hpke/             # OHTTP HPKE client implementation
│   ├── stream-buf/             # Stream buffer utilities
│   └── stream-octets/          # Octet stream utilities
└── docker-compose.test.yml     # Docker config for integration testing
```

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add/change CLI flags | `src/args.rs` |
| Add new HTTP client type | `src/client/mod.rs` (add to `HttpClientKind` enum) |
| Modify HTTP/2 behavior | `src/client/http2.rs` |
| Modify HTTP/3 behavior | `src/client/http3/mod.rs` |
| Modify QUIC connection logic | `src/client/http3/connection.rs` |
| Modify OHTTP behavior | `src/client/ohttp.rs` |
| QUIC/H3 TLS cert configuration | `src/client/cert.rs` (`X509ConnectionHook`) |
| Shared request building/dispatch | `src/client/request.rs` (`RequestHandler` trait) |
| Add new error variants | `src/error.rs` |
| Arg validation logic | `src/args.rs` (`Args::validate`) |
| Client selection logic | `src/lib.rs` (`select_http_client`) |
| Logging configuration | `src/lib.rs` (`configure_logging`) |
| Mock server routes | `tests/common/mod.rs` |
| Integration test cases | `tests/integration_tests.rs` |
| TLS configuration | `src/args.rs` (`TlsConfig`) |
| TLS cert configuration (H2 + H3) | `src/client/cert.rs` (`build_ssl_context_builder`, `X509ConnectionHook`) |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| `tunnel` | fn | `src/lib.rs` | Top-level async entry: parse args, configure logging, dispatch request |
| `run` | fn | `src/lib.rs` | Core request flow: validate args, select client, return body as string |
| `raw_run` | fn | `src/lib.rs` | Like `run` but returns `HttpResponse` instead of body string |
| `run_handle_error` | fn | `src/lib.rs` | Wrapper that handles errors and returns response body or logs error |
| `select_http_client` | fn | `src/lib.rs` | Returns `HttpClientKind` based on args (OHTTP vs HTTP/2 vs HTTP/3) |
| `Args` | struct | `src/args.rs` | Clap-parsed CLI arguments |
| `TlsConfig` | struct | `src/args.rs` | TLS configuration holder (cacert path) |
| `Args::validate` | method | `src/args.rs` | Calls setup_args, validates basic and proxy args |
| `RequestArgs` | struct | `src/args.rs` | Validated request parameters (method, url, headers, body) |
| `Method` | enum | `src/args.rs` | `Get` \| `Post` — case-insensitive via clap |
| `HttpClient` | trait | `src/client/mod.rs` | Trait for `send_request()` — implemented by client types |
| `HttpClientKind` | enum | `src/client/mod.rs` | `OHttp(OHttpClient)` \| `Http2(Http2Client)` \| `Http3(Http3Client)` |
| `ProxyClientKind` | enum | `src/client/mod.rs` | `Http2(Http2Client)` \| `Http3(Http3Client)` — proxy transport used by `OHttpClient` |
| `HttpResponse` | struct | `src/client/mod.rs` | `{ version, status, headers, body }` with helper methods |
| `HttpBody` | type alias | `src/client/mod.rs` | `BoxBody<Bytes, std::io::Error>` — unified body type |
| `X509ConnectionHook` | struct | `src/client/cert.rs` | `ConnectionHook` impl: configures BoringSSL TLS context for QUIC (custom CA, optional mTLS) |
| `build_ssl_context_builder` | fn | `src/client/cert.rs` | Shared TLS builder: sets PEER verify mode, loads custom CA or system defaults into an `SslContextBuilder` |
| `RequestHandler` | trait | `src/client/request.rs` | Shared `create_request()` and `dispatch_request()` logic |
| `build_request` | fn | `src/client/request.rs` | Builds `Request<HttpBody>` from method, url, headers, body |
| `consume_headers` | fn | `src/client/request.rs` | Parses `"Key:Value"` header strings onto request builder |
| `Http2Client` | struct | `src/client/http2.rs` | Direct HTTP/2 client using hyper + BoringSSL (`hyper-boring`, `boring`) |
| `Http3Client` | struct | `src/client/http3/mod.rs` | HTTP/3 client using tokio-quiche (QUIC transport) |
| `Http3Client::start_connection` | method | `src/client/http3/mod.rs` | Sets up UDP socket, QUIC connection, spawns connection task |
| `SendRequest` | struct | `src/client/http3/connection.rs` | Handle for sending requests over established H3 connection |
| `Connection` | struct | `src/client/http3/connection.rs` | Manages QUIC/H3 connection lifecycle |
| `H3Body` | struct | `src/client/http3/body.rs` | Streaming body type for H3 responses (impls AsyncRead/AsyncWrite) |
| `H3ConnectionLogger` | struct | `src/client/http3/logging.rs` | Structured logging wrapper for H3 connections using `foundations::telemetry::log` |
| `OHttpClient` | struct | `src/client/ohttp.rs` | OHTTP client: fetches key, encrypts, proxies via H2 or H3, decrypts |
| `CertSettings` | struct | `src/client/cert.rs` | Client cert + key paths for mTLS in `X509ConnectionHook` |
| `FerretError` | enum | `src/error.rs` | Error variants; implements `thiserror::Error` |
## CONVENTIONS
- **Header format**: Headers are `"Key:Value"` strings (colon-separated). See `consume_headers`.
- **HTTP/2 default**: Use `--http3` flag for QUIC/H3 transport.
- **Data from file**: `--data @filename` reads from file; `--data string` passes literal.
- **Logging**: Use `foundations::telemetry::log` macros, not `println!`.
- **Error propagation**: Use `color_eyre::eyre::Result` with `.wrap_err()` for context.
- **OHTTP flow**: `fetch_proxy_key()` → `encrypt()` → `dispatch_outer_request()` → `decrypt()`
- **RequestHandler pattern**: Both `Http2Client` and `Http3Client` implement `RequestHandler` for shared request logic.
- **TLS**: HTTP/2 uses BoringSSL via `hyper-boring` + `boring` crates (not rustls). Custom CA certs loaded via `X509StoreBuilder`.
## COMMANDS
```bash
cargo build                                      # build all
cargo test                                       # run unit tests
cargo test --test integration_tests              # run integration tests
cargo test -- --nocapture                        # tests with stdout visible
cargo run --bin ferret -- <url>                  # HTTP/2 request
cargo run --bin ferret -- --http3 <url>          # HTTP/3 request
cargo run --bin ferret -- --ohttp -x <proxy> <url>  # OHTTP request
```

## ANTI-PATTERNS
- NEVER use println! for diagnostic output — use foundations::telemetry::log macros; println! is reserved for the response body output in tunnel().
- NEVER skip Args::validate() — arg validation is required before send_request; skipping it can pass None as method.
- NEVER use .unwrap() in library code — add appropriate FerretError variants and propagate with ?.
- NEVER mix anyhow and eyre — use color_eyre exclusively

## NOTES
- The foundations crate is sourced from a GitHub fork. See Cargo.toml [workspace.dependencies].
- POST requests without an explicit Content-Type header will have application/x-www-form-urlencoded injected automatically by Args::validate().
- Integration tests require a running OHTTP gateway. Use GATEWAY_URL env var to override default http://localhost:8787.
- OHTTP client uses workspace crates from ohttp-gateway-worker/ for HPKE encryption and BHTTP encoding.
- Body responses are buffered fully into memory — not streamed.
- The HttpResponse struct provides multiple body output formats: body_as_string_lossy(), body_as_string_escaped(), body_as_hex().
- `--cacert` is ignored when using `--ohttp` (the gateway handles target TLS); use `--proxy-cacert` for proxy CA certs.
- HTTP/3 uses tokio-quiche with quiche (Cloudflare's QUIC impl). Connection spawned as background task.
- `--proxy-http3` flag makes the OHTTP outer request use HTTP/3; without it, outer request defaults to HTTP/2.
- verify_peer defaults to false in QuicSettings for dev/testing.
