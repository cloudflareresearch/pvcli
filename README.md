# ferret

A curl-like HTTP/2 client for OHTTP, supporting GET and POST requests with TLS.

## Setup

To clone ferret locally:
```
git clone <ferret-url>
```

We utilize packages from ohttp-gateway-worker for much of the OHTTP client.

## Setting up local mock gateway from ohttp-gateway-worker

```
npm install wrangler
npx wrangler dev --cwd ./ohttp-gateway-worker
```

This should build and run the gateway at http://localhost:8787

## Examples

Use -v for INFO logs, -vv for DEBUG, and -vvv for TRACE.
See -h, --help for more options.

### Basic HTTP2 query

```
$ cargo run --bin ferret -- https://example.com
```

### Basic OHTTP query to local ohttp-gateway-worker booted up with `npx wrangler dev`

This tests basic proxying and HPKE encapsulation.

```
$ cargo run --bin ferret -- --ohttp -x http://localhost:8787 https://example.com
```

## License

This project has the [MIT License](./LICENCE).
