# AGENTS.md — ferret

A curl-like client for OHTTP, supporting GET and POST requests with TLS.

## STRUCTURE
```
ferret/
├── src/
│   ├── bin/
│   │   └── ferret/
│   │       └── main.rs         # Binary entry point (calls tunnel())
│   ├── client/
│   │   ├── mod.rs              # HttpClient trait, HttpClientKind enum, HttpResponse struct
│   │   ├── http2.rs            # Http2Client: direct HTTP/2 requests with TLS
│   │   └── ohttp.rs            # OHttpClient: OHTTP-encrypted requests via proxy
│   ├── lib.rs                  # Core logic: run(), select_http_client(), logging setup
│   ├── args.rs                 # CLI argument definitions (clap), Args validation
│   └── error.rs                # FerretError enum (thiserror)
├── tests/
│   ├── integration_tests.rs    # Integration tests for HTTP2 and OHTTP clients
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
| Modify OHTTP behavior | `src/client/ohttp.rs` |
| Add new error variants | `src/error.rs` |
| Arg validation logic | `src/args.rs` (`Args::validate`) |
| Client selection logic | `src/lib.rs` (`select_http_client`) |
| Logging configuration | `src/lib.rs` (`configure_logging`) |
| Mock server routes | `tests/common/mod.rs` (`setup_mock_server`) |
| Integration test cases | `tests/integration_tests.rs` |
| TLS configuration | `src/args.rs` (`TlsConfig`) |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| `tunnel` | fn | `src/lib.rs` | Top-level async entry: parse args, configure logging, dispatch request |
| `run` | fn | `src/lib.rs` | Core request flow: validate args, select client, send request |
| `select_http_client` | fn | `src/lib.rs` | Returns `HttpClientKind` based on args (OHTTP vs HTTP/2) |
| `Args` | struct | `src/args.rs` | Clap-parsed CLI arguments |
| `TlsConfig` | struct | `src/args.rs` | TLS configuration holder (cacert path) |
| `Args::tls_config` | method | `src/args.rs` | Returns `TlsConfig` for target server TLS |
| `Args::proxy_tls_config` | method | `src/args.rs` | Returns `TlsConfig` for proxy TLS |
| `Args::validate` | method | `src/args.rs` | Infers method, adds default headers, validates POST has data |
| `RequestArgs` | struct | `src/args.rs` | Validated request parameters (method, url, headers, body) |
| `Method` | enum | `src/args.rs` | `Get` \| `Post` — case-insensitive via clap |
| `HttpClient` | trait | `src/client/mod.rs` | Trait for `send_request()` — implemented by client types |
| `HttpClientKind` | enum | `src/client/mod.rs` | `OHttp(OHttpClient)` \| `Http2(Http2Client)` |
| `HttpResponse` | struct | `src/client/mod.rs` | `{ version, status, headers, body }` with helper methods |
| `Http2Client` | struct | `src/client/http2.rs` | Direct HTTP/2 client using hyper + rustls |
| `OHttpClient` | struct | `src/client/ohttp.rs` | OHTTP client: fetches key, encrypts, proxies, decrypts |
| `FerretError` | enum | `src/error.rs` | All error variants; implements `thiserror::Error` |
| `consume_headers` | fn | `src/client/http2.rs` | Parses `"Key:Value"` header strings onto hyper request builder |


## CONVENTIONS
- **Header format**: Headers are passed as `"Key:Value"` strings (colon-separated). See `src/client/http2.rs` `consume_headers`.
- **HTTP/2 preferred**: `Http2Client` supports both HTTP/1.1 and HTTP/2 but prefers HTTP/2 when available.
- **Data from file**: `--data @filename` reads from file; `--data string` passes literal. See `src/args.rs` `parse_data`.
- **Logging via foundations**: Use `foundations::telemetry::log` macros (`log::info!`, `log::debug!`, etc.), not `println!` or standard `log` crate.
- **Error propagation**: Use `?` with `FerretError` variants; add new variants to `src/error.rs` rather than using `.unwrap()` in library code.
- **OHTTP flow**: `fetch_proxy_key()` → `encrypt()` → `dispatch_outer_request()` → `decrypt()`
- **TLS config**: Use `--cacert` for target server CA, `--proxy-cacert` for proxy CA (only with `--proxy`)

## COMMANDS
```bash
cargo build                                      # build all (includes workspace crates)
cargo build --bin ferret                         # build CLI binary only
cargo test                                       # run unit tests
cargo test --test integration_tests              # run integration tests (requires local gateway)
cargo run --bin ferret -- <url>                  # run CLI
cargo run --bin ferret -- --ohttp -x <proxy> <url>  # run with OHTTP
npx wrangler dev --cwd ./ohttp-gateway-worker    # start local OHTTP gateway at localhost:8787
cargo clippy                                     # lint
cargo fmt                                        # format

ANTI-PATTERNS
- NEVER use println! for diagnostic output — use foundations::telemetry::log macros; println! is reserved for the response body output in tunnel().
- NEVER skip Args::validate() — arg validation is required before send_request; skipping it can pass None as method.
- NEVER use .unwrap() in library code — add appropriate FerretError variants and propagate with ?.

NOTES
- The foundations crate is sourced from a GitHub fork. See Cargo.toml [workspace.dependencies].
- POST requests without an explicit Content-Type header will have application/x-www-form-urlencoded injected automatically by Args::validate().
- Integration tests require a running OHTTP gateway. Use GATEWAY_URL env var to override default http://localhost:8787.
- OHTTP client uses workspace crates from ohttp-gateway-worker/ for HPKE encryption and BHTTP encoding.
- Body responses are buffered fully into memory — not streamed.
- The HttpResponse struct provides multiple body output formats: body_as_string_lossy(), body_as_string_escaped(), body_as_hex().
- `--cacert` is ignored when using `--ohttp` (the gateway handles target TLS); use `--proxy-cacert` for proxy CA certs.