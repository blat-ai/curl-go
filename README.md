# curl-go

Go bindings to [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate),
with a `net/http` client modeled on
[curl_cffi](https://github.com/lexiforest/curl_cffi).
Requests use the actual patched libcurl and BoringSSL, including the browser's
TLS handshake, HTTP/2 settings, pseudoheader ordering, and default headers.

The native release is pinned to **v2.2.3**. All **38 public browser profiles** and
**17 aliases** are tested against source-derived TLS and HTTP/2 expectations.
Integration tests also compare the Go client with the independent native
executable using JSON captures of TLS, headers, HTTP/2, and HTTP/3/QUIC parameters.

## Quick start

Requires Go 1.25+, a C compiler, and `CGO_ENABLED=1`.

```sh
go run ./cmd/curl-go-install -with-cli
go test ./...
go run ./examples/basic https://example.com
```

The installer downloads the official shared library, verifies its SHA-256, and
places it in `.lib/`. For deployed applications, set `CURL_IMPERSONATE_LIB` to
the library's absolute path. The Go library never downloads files at runtime.
`-with-cli` also installs the independent native executable required by the
integration parity tests; applications only need the shared library.
macOS arm64/amd64, Linux GNU/musl, Windows, and FreeBSD release assets are
available; [TESTING.md](TESTING.md) describes platform verification and CI.

```go
package main

import (
    "context"
    "io"
    "log"
    "net/http"
    "os"
    "time"

    curlgo "github.com/blat-ai/curl-go"
)

func main() {
    client, err := curlgo.NewClient(curlgo.Chrome)
    if err != nil { log.Fatal(err) }
    defer client.Close()
    client.Timeout = 20 * time.Second

    req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://example.com", nil)
    resp, err := client.Do(req)
    if err != nil { log.Fatal(err) }
    defer resp.Body.Close()
    if _, err := io.Copy(os.Stdout, resp.Body); err != nil { log.Fatal(err) }
}
```

`Client` embeds `*http.Client`, so `Get`, `Post`, `PostForm`, `CheckRedirect`,
`Timeout`, and `Jar` behave as standard Go APIs. Its cookie jar persists cookies
across requests. Bodies stream in both directions; errors occurring after headers
arrive are returned by `resp.Body.Read`. Close response bodies and the client.
Native authentication retries replay uploads through `Request.GetBody` when
available, without requiring buffering. Request paths retain dot segments.
Goroutines provide concurrent and asynchronous requests, bounded by `MaxHandles`.

## Transport configuration

Use `Transport` with your own `http.Client`, or configure `client.CurlTransport`
before its first request:

```go
tr := &curlgo.Transport{
    Profile: curlgo.Firefox147,
    Proxy: "http://127.0.0.1:8080",
    ConnectTimeout: 5 * time.Second,
    MaxHandles: 20,
    CurlOptions: map[curlgo.Option]any{
        curlgo.OptHTTPVersion: curlgo.HTTPVersion2TLS,
    },
}
defer tr.Close()
client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
```

Certificate verification is enabled by default. `CAFile`, `CAPath`,
`ClientCertFile`, and `ClientKeyFile` configure trust and client certificates.
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `REQUESTS_CA_BUNDLE` are honored.
An empty `Proxy` selects a direct connection; set `ProxyFunc: http.ProxyFromEnvironment`
to use Go's proxy environment behavior. Explicit proxy selections take precedence
over environment `NO_PROXY` exclusions. SOCKS proxies use native curl semantics.

Set `DefaultHeaders` to a pointer to `false` to disable browser headers.
`WithOrderedHeaders(req, []curlgo.Header{...})` sets explicit header ordering,
and `WithProfile(req, curlgo.Safari)` selects a profile per request.
Different profiles use separate native connection caches.

## Profiles

`Profiles()` returns every concrete profile; `ProfileAliases()` returns a copy of
the alias table. Aliases select the latest pinned target:

| Alias | Target |
| --- | --- |
| `chrome` | `chrome150` |
| `chrome_android` | `chrome131_android` |
| `edge` | `edge101` |
| `safari`, `safari_beta` | `safari2601` |
| `safari_ios`, `safari_ios_beta` | `safari260_ios` |
| `firefox` | `firefox147` |
| `tor` | `tor145` |

Concrete Chrome profiles: 99, 100, 101, 104, 107, 110, 116, 119, 120, 123,
124, 131, 133a, 136, 142, 145, 146, 150, plus Android 99 and 131.
Edge: 99 and 101. Safari: 153, 155, 170, 172_ios, 180, 180_ios, 184,
184_ios, 260, 2601, 260_ios. Firefox: 133, 135, 144, 147. Tor: 145.
Deprecated Safari aliases match curl_cffi. Unknown profiles return an error.

## Custom fingerprints

`Transport.Fingerprint` or `ApplyFingerprint(curl, fingerprint)` configures JA3,
Akamai HTTP/2 fingerprints, Perk HTTP/3 settings, and optional extra controls:

```go
tr.Fingerprint = curlgo.Fingerprint{
    JA3: "771,4865-4866-4867-49195,0-10-11-13-16-23-43-45-51-65281,29-23-24,0",
    Akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
}
```

Include a supported TLS 1.2 cipher such as `49195` alongside TLS 1.3 suites;
the native cipher-list API rejects lists containing only TLS 1.3 suites.

Extra fields use pointers: omitted values preserve native profile defaults,
including randomized extension order; explicit `false` and `0` take effect.
Malformed fingerprints are rejected before changing the handle. Request-specific
curl options apply last. `ExtraFingerprints.FormBoundary` accepts the native
styles `"webkit"` and `"firefox"`.

HTTP/3 is selectable with `OptHTTPVersion: HTTPVersion3Only`. Native browser
QUIC fingerprints exist for Chrome 145, 146, 150, and Firefox 147. Earlier
profiles may use generic native HTTP/3 behavior. The native Firefox 133/135/144
and Tor 145 presets omit the QUIC TLS extension; explicit custom
`HTTP3TLSExtensionOrder` is required for HTTP/3 with these targets.
Their default TLS and HTTP/2 profiles are fully tested.

## Low-level API

`NewCurl`, `SetOpt`, `GetInfo`, `Impersonate`, `Perform(ctx)`, `Reset`,
`Duplicate`, `Upkeep`, and `Close` expose the native easy-handle interface.
`OptWriteFunction`/`OptHeaderFunction` accept `io.Writer`, `OptReadFunction`
accepts `io.Reader`, slists accept `[]string`, and binary options accept `[]byte`.
Callbacks never pass Go pointers to C. Arbitrary native pointers and callbacks
are rejected. `CurlError` exposes the native error code and diagnostic text;
callback and context errors retain their original causes.

`NewMime` and `Mime.AddPart` use native multipart generation, including browser
boundary styles. Standard Go multipart writers also work with `Client.Do`.
Native WebSocket operations are exposed by `WSRecv`, `WSSend`, and
`WSSendFrame`. The higher-level API supports browser profiles, concurrent
sending and receiving, fragmented messages, automatic pong replies, and
context deadlines:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
ws, err := curlgo.DialWebSocket(ctx, "wss://example.com/socket", curlgo.WebSocketOptions{
    Profile: curlgo.Chrome,
    MaxMessageSize: 16 << 20,
})
if err != nil { log.Fatal(err) }
defer ws.Close()
if err := ws.SendText(ctx, "hello"); err != nil { log.Fatal(err) }
message, flags, err := ws.Recv(ctx)
if err != nil { log.Fatal(err) }
log.Printf("received flags=%d message=%q", flags, message)
```

Handshake timeouts use `WebSocketOptions.Timeout` and `ConnectTimeout`;
subsequent operations use their context deadlines. `Recv` reassembles messages
and preserves partial messages across a receive timeout. It returns a peer's
close frame with `WSClose`; later operations return `ErrWebSocketClosed`.
An interrupted `Send` closes the connection after native framing starts;
later operations return `ErrWebSocketClosed`.
`CloseWithStatus` sends an explicit close status and reason. Every public browser
profile is also tested through a local TLS WebSocket handshake and binary echo.

`Curl` serializes operations; callbacks must not call methods on their owning
handle. Blocking user callbacks must arrange to unblock on cancellation.
`Reset` retains native connection/DNS caches and native cookie state.
`Duplicate` copies request configuration into a new independent handle;
connections are not copied; cookie behavior follows native `curl_easy_duphandle`.
Attached MIME forms cannot be
duplicated. Request trailers are currently rejected by the HTTP transport.

See [TESTING.md](TESTING.md) for checks and [UPSTREAM.md](UPSTREAM.md) for
provenance and the mapping from Python tests. This port covers browser requests,
native controls, concurrency, multipart, and WebSockets; Python CLI/framework
adapters and paid Pro services are outside its scope.
