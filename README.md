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

# Credit
- We utilize packages from ohttp-gateway-worker for much of the OHTTP client. Thank you to Akshat Mahajan (@akshat) for the ohttp-gateway-worker crates! (Based on commit: 1e5a05acb87833170063e2a4a06c957da14650fb)
- We utilize packages from chaussette at src/client/http3/chaussette for much of the HTTP3 client. Thank you to the team for these crates! (Based on commit: 35472d736b5695a933ee8c20af959506abc8922b)

## License

This project has the [MIT License](./LICENCE).
