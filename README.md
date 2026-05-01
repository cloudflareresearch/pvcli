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

Use -v for INFO logs and -vv for DEBUG logging. -s for silent

### Basic HTTP2 query

```
$ cargo run --bin ferret -- https://example.com
```

## License

This project has the [MIT License](./LICENCE).
