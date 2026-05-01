# AGENTS.md — ferret

A curl-like HTTP/2 client for OHTTP, supporting GET and POST requests with TLS.

## STRUCTURE
```
ferret/
├── src/
│   ├── main.rs         # Binary entry point (calls tunnel())
│   ├── lib.rs          # Core logic: arg validation, request dispatch, logging setup
│   ├── args.rs         # CLI argument definitions (clap)
│   ├── http.rs         # HttpClient and HttpResponse implementation
│   ├── error.rs        # FerretError enum (thiserror)
│   └── bin/
│       └── mock_server.rs  # Dev/test mock HTTP server binary
└── tests/
    └── integration.sh  # Integration test runner script
```

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add/change CLI flags | `src/args.rs` |
| Add new HTTP methods | `src/http.rs` (add method on `HttpClient`) |
| Add new error variants | `src/error.rs` |
| Arg validation logic | `src/lib.rs` (`validate_args`) |
| Logging configuration | `src/lib.rs` (`configure_logging`) |
| Mock server routes | `src/bin/mock_server.rs` (`setup_mock_server`) |
| Integration test cases | `tests/integration.sh` |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| `tunnel` | fn | `src/lib.rs` | Top-level async entry: parse args, configure logging, dispatch request |
| `Args` | struct | `src/args.rs` | Clap-parsed CLI arguments |
| `Method` | enum | `src/args.rs` | `Get` \| `Post` — case-insensitive via clap |
| `HttpClient` | struct | `src/http.rs` | Wraps hyper legacy client; HTTP/2-only with TLS |
| `HttpResponse` | struct | `src/http.rs` | `{ status: u16, body: String }` |
| `FerretError` | enum | `src/error.rs` | All error variants; implements `thiserror::Error` |
| `validate_args` | fn | `src/lib.rs` | Infers method, warns on missing Content-Type, errors on POST without data |
| `consume_headers` | fn | `src/http.rs` | Parses `"Key: Value"` header strings onto hyper request builder |

## CONVENTIONS
- **Header format**: Headers are passed as `"Key: Value"` strings (colon-separated). See `src/http.rs` `consume_headers`.
- **HTTP/2 only**: `HttpClient` is configured `http2_only(true)`. Do not add HTTP/1.1 paths without updating the connector.
- **Data from file**: `--data @filename` reads from file; `--data string` passes literal. See `src/args.rs` `parse_data`.
- **Logging via foundations**: Use `foundations::telemetry::log` macros (`log::info!`, `log::debug!`, etc.), not `println!` or standard `log` crate.
- **Error propagation**: Use `?` with `FerretError` variants; add new variants to `src/error.rs` rather than using `.unwrap()` in library code.

## COMMANDS
```bash
cargo build                          # build all
cargo build --bin ferret             # build CLI binary only
cargo build --bin mock_server        # build mock server binary
cargo test                           # run unit tests (in src/lib.rs)
cargo run --bin ferret -- <url>      # run CLI
cargo run --bin mock_server          # start mock server (prints base URL to stdout)
bash tests/integration.sh            # run integration tests (builds + starts mock server automatically)
cargo clippy                         # lint
cargo fmt                            # format
```

## ANTI-PATTERNS
- **NEVER use `println!` for diagnostic output** — use `foundations::telemetry::log` macros; `println!` is reserved for the response body output in `tunnel()`.
- **NEVER add HTTP/1.1 support** without replacing the `http2_only(true)` client config — the client will panic or silently fail on HTTP/1.1 servers otherwise.
- **NEVER call `validate_args` after `Args::parse()`** is skipped — arg validation is required before `send_request`; skipping it can pass `None` as method.

## NOTES
- The `foundations` crate is patched from a fork (`AkshatM/foundations` on GitHub) due to a logger shutdown bug. See the comment in `src/lib.rs` and `Cargo.toml` `[patch.crates-io]`.
- POST requests without an explicit `Content-Type` header will have `application/x-www-form-urlencoded` injected automatically by `validate_args`.
- Integration tests use two binaries: `mock_server` (starts an httpmock server, prints its base URL) and `ferret` (the CLI). The script handles build and lifecycle automatically.
- Body responses are buffered fully into memory — not streamed. See TODO in `src/http.rs:105`.