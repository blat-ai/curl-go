# Upstream provenance and test mapping

This is a Go binding to the public native API, with an idiomatic `net/http`
transport and session conveniences modeled on curl_cffi's requests layer.
Browser impersonation is performed by curl-impersonate itself.

The native ABI, browser registry, and wire expectations are pinned to
[curl-impersonate v2.2.3](https://github.com/lexiforest/curl-impersonate/releases/tag/v2.2.3),
commit `6e8f87760a4dd96771e96fc9d55440dcd8845243`. The vendored headers come from
the official native release archive. The installer stores the release assets'
official SHA-256 digests; no unverified system libcurl fallback is downloaded.

[The pinned native profile implementation](https://github.com/lexiforest/curl-impersonate/blob/v2.2.3/patches/curl.patch)
is authoritative for the profile fixtures. That patch's SHA-256 is
`b198abcd1e7ad065d5fc1d9d68ce99226ebc89bc7e1fa23c6aa9304b7e265bf1`.
`tools/generate_profile_signatures.py` extracts its `lib/impersonate.c` entries
into `testdata/profile_signatures.json`; those values are not recorded from a
Go test run. `browsers.json` omits newer profiles and is not used as the registry.

The 38 public browser profiles and 17 Python-compatible aliases follow
[curl_cffi's impersonation definitions](https://github.com/lexiforest/curl_cffi/blob/58b48f6b214962fd7dd1927583be74a798b85d92/curl_cffi/requests/impersonate.py).
The native patch also contains an unadvertised `okhttp4_android` target marked
"not working"; curl_cffi does not expose it and this library does not list it as
a supported browser profile.

The tests preserve the behavioral assertions using Go's test framework and
local servers. Python-only fixtures and framework plumbing are replaced by Go
equivalents:

| Upstream tests | Go equivalents |
| --- | --- |
| Native `tests/test_impersonate.py`: TLS, HTTP/2, and HTTP/3 browser signatures | `profiles_test.go`: all 38 public profiles and 17 aliases perform real TLS/HTTP2 requests; `http3_test.go`: real QUIC requests, captured HTTP/3 frames and received transport parameters |
| curl_cffi `test_impersonate.py`, `test_fingerprint_application.py`, `test_fingerprints.py` | Browser alias tests and `fingerprint_test.go`: JA3, Akamai, additional fingerprint fields, precedence, malformed inputs, native custom fingerprints; `http3_test.go`: custom Perk SETTINGS, pseudo-header order, and transport parameters |
| `test_curl.py`, `test_setopt.py`, `test_upload.py` | Low-level easy-handle, callback, typed option/info, native reset/duplicate, MIME, binary upload, ownership and body-length tests |
| `test_requests.py`, `test_response.py`, `test_cookies.py` | `transport_test.go`: methods, bodies, forms/JSON/multipart, redirects/auth/cookies, response headers/trailers, TLS, proxies, compression |
| `test_async.py`, `test_async_session.py` | Go goroutine concurrency, context cancellation, handle pool limits, shutdown and connection reuse tests |
| `test_sync_websockets.py`, `test_websockets.py` | Native WebSocket send/receive and frame metadata; WSS handshakes/message exchanges for all 38 profiles; fragmentation, pong, masking, cancellation and concurrency |

This is not a line-for-line port of every Python package feature. Python CLI,
gevent/eventlet adapters, caching, paid Pro services, and Python compatibility
classes are outside the Go binding's scope. Browser TLS/HTTP2, WSS, HTTP/3, and
request-layer tests use loopback peers rather than external httpbin or
fingerprint services. TCP/TLS and HTTP/2 signatures are checked for every public
profile. HTTP/3 native defaults connect successfully for 34 profiles; the four
older Firefox/Tor profiles first demonstrate their native missing-extension-57
limitation and then connect with an explicitly custom QUIC extension order.

Chrome145, Chrome146, Chrome150, and Firefox147 have dedicated native HTTP/3
browser settings. Their tests capture raw HTTP/3 control/request frames,
ClientHello fields, and received QUIC parameters/connection IDs, and compare
SETTINGS, pseudo-header order, default header values, and TLS cipher/group/
signature algorithms against the pinned implementation. Custom Perk tests
verify frames and received parameters through qlog. These are actual local wire
captures with source-derived expectations, not a certification against an
independently captured packet trace from every browser version.

`Curl.Duplicate` calls native `curl_easy_duphandle` and supplies independent
callback state, error buffers, borrowed lists, and direct POSTFIELDS storage.
It preserves current native settings without replaying past option commands.
The native clone creates a separate connection cache and follows native cookie
duplication semantics; attached MIME forms must be detached before duplication.

Library distribution is under the MIT license. Native dependency license files
from the upstream archive are retained in `internal/`; native binaries are
installed separately rather than committed to the Go module.
