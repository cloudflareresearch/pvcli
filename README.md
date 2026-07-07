> [!WARNING]  
> This software is experimental and has not been audited. It is provided as is,
and is not eligible for any bounty program. The underlying protocol is defined
by the IETF in RFC 9458 and in draft-ietf-ohai-chunked-ohttp-00. Use at your own
risk.

# pvcli

A curl-like HTTP/2 and HTTP/3 client for OHTTP, supporting GET and POST requests with TLS.

## Setting up local mock gateway from ohttp-gateway-worker

```
npm install wrangler
npx wrangler dev --cwd ./crates/ohttp-gateway-worker
```

This should build and run the gateway at http://localhost:8787

## Examples

Use -v for INFO logs, -vv for DEBUG, and -vvv for TRACE.
See -h, --help for more options.

### Basic HTTP/2 query

```
$ cargo run -- https://cloudflare.com/cdn-cgi/trace
fl=974f57
h=cloudflare.com
ip=104.28.197.122
ts=1772043750.807
visit_scheme=https
uag=
colo=DFW
sliver=none
http=http/2
loc=US
tls=TLSv1.3
sni=plaintext
warp=on
gateway=on
rbi=off
kex=X25519MLKEM768
```

### Basic HTTP/3 query

```
$ cargo run -- --http3 https://cloudflare.com/cdn-cgi/trace
```

### OHTTP request through a relay and gateway
```
$ cargo run -- -vvv --ohttp \
    --first-hop https://relay-cloudflare.ohttp.info \
    --proxy https://gateway.ohttp.info \
    -X POST \
    --header "content-type: application/json" \
    --data '{"test":1}' \
    https://target.ohttp.info/anything
```

### HTTP/2 CONNECT Proxying

Use `-x` to proxy requests through an HTTP/2 CONNECT proxy:

```
$ cargo run -- -x https://your-proxy.example.com https://target.example.com
```

You can add custom headers to the proxy request with `--proxy-header`:

```
$ cargo run -- -x https://your-proxy.example.com \
  --proxy-header "Proxy-Authorization: Bearer <token>" \
  https://target.example.com
```

### Basic OHTTP query to local ohttp-gateway-worker booted up with `npx wrangler dev`

This tests basic proxying and HPKE encapsulation.

```
$ cargo run -- --ohttp -x http://localhost:8787 https://cloudflare.com/cdn-cgi/trace
fl=974f54
h=cloudflare.com
ip=104.28.197.122
ts=1771610608.288
visit_scheme=https
uag=
colo=DFW
sliver=none
http=http/1.1
loc=US
tls=TLSv1.3
sni=plaintext
warp=on
gateway=on
rbi=off
kex=X25519MLKEM768
```

### OHTTP with HTTP/3 proxy transport

Use `--proxy-http3` to send the outer OHTTP request over HTTP/3 instead of HTTP/2:

```
$ cargo run -- --ohttp --proxy-http3 -x https://your-h3-gateway https://example.com
```

# Notes
Running pvcli on mac may warn ```<jemalloc>: option background_thread currently supports pthread only```, but this memory cleanup overhead doesn't really affect pvcli's short-lived processes.

# Security Considerations

This software has not been audited. Please use at your sole discretion. With
this in mind, this repository security relies on the following:

1. RFC 9458, drafts [draft-ietf-ohai-chunked-ohttp-00](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-00.html)
2. rust dependencies: `hpke`, `boring`, `hyper-boring`, `tokio-quiche`, and `quiche`
3. cryptography: [RFC 9180 (HPKE)](https://datatracker.ietf.org/doc/rfc9180/) and TLS 1.3.

Limitations
1. pvcli does not support PQC HPKE (yet!)
2. some specification are not yet RFC

## License

This project has the [Apache License 2.0](./LICENSE).
