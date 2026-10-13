# Testing

The tests use the real native library. Install it before running the suite:

```sh
go run ./cmd/curl-go-install -with-cli
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Go 1.25 or newer, a C compiler, and `CGO_ENABLED=1` are required. All tests run
against local HTTP, TLS, WebSocket, QUIC/HTTP3, and proxy servers. Internet access is needed for the
installer and initial Go module downloads, not for the tests or the library.
Missing native libraries and unsupported profiles fail the tests; they are never
silently skipped. Sandboxes must permit TCP and UDP loopback listeners. When the normal Go
cache is unwritable, set `GOCACHE` to a writable directory.

## Independent native parity

`TestAllProfilesNativeParity` runs every concrete profile through the public Go
`Client` and the checksum-verified upstream `curl-impersonate` executable in a
separate process. Each sends an identical default GET and a binary POST with
duplicate ordered headers, cookies, and an overridden language to the same URL.
The matrix covers plaintext HTTP/1.1, TLS 1.3 with HTTP/1.1 and HTTP/2, TLS 1.2
with HTTP/2, and HTTP/3. `TestProfileAliasesNativeParity` compares all 17 aliases
against their native canonical targets over TLS/HTTP2.

Small loopback peers return the captured request parameters as JSON. They read
the wire before ordinary HTTP parsing discards ordering or extension contents:

| Layer | Captured and compared |
| --- | --- |
| TLS | ClientHello record version and size, legacy version, session ID length, ordered cipher suites, compression methods, every extension ID and payload, supported versions/groups, point formats, signature algorithms, key-share groups and formats, ALPN/ALPS, certificate compression, delegated credentials, record limits, ECH structure, SNI, and negotiated version/cipher/ALPN/resumption. Raw captures also include JA3 and its MD5. |
| HTTP/1 | Request line, every header's exact name/value/order, duplicates, body, trailers, and raw request bytes. |
| HTTP/2 | Preface, SETTINGS values/order, WINDOW_UPDATE, stream IDs, priorities/weights/exclusivity, frame flags/padding, ordered pseudoheaders and ordinary headers, HPACK bytes, DATA and unknown frames through request completion. |
| HTTP/3 | Ordered SETTINGS, pseudoheaders and ordinary headers, QPACK bytes, request and control frames, body, and initial unidirectional streams. |
| QUIC | Initial version, CID lengths, initial packet-number behavior/encoding, token length, and every ordered transport parameter and payload. Initial decryption preserves the complete ClientHello and raw extension 57. |

Cryptographic byte strings cannot match across independent requests. The test
keeps raw JSON evidence and compares normalized parameters exactly. Its narrow
rules are pinned to native source: fresh TLS random/session IDs and public keys;
reserved TLS GREASE IDs while retaining their positions; extension/QUIC-parameter
permutation only for profiles that enable it; GREASE ECH payload sizes
144/176/208/240 after structural validation; and the dependent, validated
BoringSSL padding rule. QUIC normalization covers fresh source CIDs, configured
GREASE and AUTO RTT fields, and Firefox147's configured random destination-CID
length/packet number. Its packet-number encoding length is validated against
the [pinned ngtcp2 encoder](https://github.com/ngtcp2/ngtcp2/blob/v1.20.0/lib/ngtcp2_conn.c#L1852)
before normalization. Unknown extension/frame/parameter bytes remain strict.
TLS GREASE anchors and key-share formats are validated before normalization.
Mutation regression tests ensure changed stable fields cannot be normalized away.

Raw JA3 can vary with native extension permutation and conditional padding, so
the comparator checks its underlying fields under those same rules. It excludes
encrypted packet bytes, retransmission counts/packet segmentation, timing, and
HTTP/2 SETTINGS-ACK arrival timing. This verifies the fresh request's observable
fingerprint parameters; it does not claim byte-identical encrypted traffic or
cover operating-system TCP fingerprints, later requests, or session resumption.
See [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html),
[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), and the pinned BoringSSL
[ECH](https://github.com/google/boringssl/blob/156c7b75ae9b8c3b3f847acf264f17594c3859fb/ssl/encrypted_client_hello.cc)
and [padding](https://github.com/google/boringssl/blob/156c7b75ae9b8c3b3f847acf264f17594c3859fb/ssl/extensions.cc) implementations.

The native CLI resets initial QUIC packet numbers to zero after applying its
profile. The reference invocation explicitly restores the source profile's
packet-number setting; that field stays checked rather than ignored.
Firefox133/135/144 and Tor145 omit QUIC extension 57 in their native defaults.
`TestLegacyProfilesNativeHTTP3FailureParity` verifies both clients fail with
native code 7; their successful HTTP/3 parity cases use the same explicitly
custom extension order on both clients.

Run the parity cases and optionally retain every raw and normalized JSON pair:

```sh
go run ./cmd/curl-go-install -with-cli
CURL_GO_PARITY_DIR=/tmp/curl-go-parity go test -count=1 -run 'NativeParity|NativeHTTP3FailureParity' .
```

`CURL_IMPERSONATE_BIN` selects another executable location. Tests fail if it is
missing or its exact native version identity differs from the loaded library.
`-q` disables `.curlrc`; proxy and curl environment overrides are removed.
No test downloads a reference client. Offline setup can use `-archive` together
with `-with-cli -cli-archive`; both archives must match the pinned SHA-256.

## Existing native coverage

The installer pins curl-impersonate **v2.2.3** and verifies each archive against
the official release asset's SHA-256 digest before writing the dynamic library.
It defaults to `.lib`, where the loader discovers it. To install elsewhere:

```sh
go run ./cmd/curl-go-install -with-cli -dir /absolute/path/to/native
```

Set `CURL_IMPERSONATE_LIB` to the exact path printed by the command. `-archive`
accepts a downloaded official release archive and performs the same digest
verification. `-goos` and `-goarch` select a target for cross installation;
`-libc gnu` or `-libc musl` explicitly selects Linux libc. Native execution
requires the asset to match the host platform.

`TestAllProfilesHTTP` and `TestAllProfilesTLSAndHTTP2Fingerprints` exercise every
one of the 38 public browser profiles. The TLS test captures the actual
ClientHello and compares cipher order, GREASE, supported groups, signature
algorithms, ALPN, and explicit extension ordering. It also reads decrypted
HTTP/2 frames, verifies SETTINGS order and values, connection WINDOW_UPDATE,
pseudo-header order, and every default header's value and order.
`TestAllProfilesWithoutDefaultHeaders` verifies the header toggle for every
profile. `TestProfileAliasesPerformCanonicalFingerprint` performs the same wire
checks through every public alias. The expectations come from the pinned native
source, independently of the Go binding's profile registry.

`TestWebSocketAllBrowserProfiles` performs a real WSS handshake and message
exchange for all 38 profiles. The WebSocket suite also covers text and binary
messages, masking, fragmentation, automatic pong, concurrent send/receive,
timeouts, close frames, TLS verification, and invalid handshakes/messages.

`TestAllProfilesHTTP3` exercises all 38 profiles against a local QUIC server.
Native defaults work for 34 profiles. Firefox133, Firefox135, Firefox144, and
Tor145 have native TCP extension allowlists that omit QUIC transport parameters
(extension 57). Their tests first assert the expected native connection error,
then perform a successful request with an explicitly custom HTTP/3 extension
order. That override is not presented as a captured browser fingerprint.

The pinned native release supplies dedicated browser HTTP/3 fingerprints for
Chrome145, Chrome146, Chrome150, and Firefox147. `TestNativeHTTP3BrowserSettings`
captures their actual control/request streams and verifies SETTINGS order and
values, pseudo-header order, default header values, TLS cipher/group/signature
algorithm order, and received QUIC transport parameters and connection IDs.
`TestNativeCustomizedPerk` verifies custom HTTP/3 SETTINGS, pseudo-header order,
and QUIC transport parameters using decoded frames and server qlog events.
These tests compare local wire behavior against source-derived expectations;
they do not certify equivalence to separately captured browser packet traces.

The remaining suite covers low-level easy handles, typed options and infos,
body and header callbacks, requests and binary uploads, cookies and redirects,
TLS verification, proxies, decompression, streaming and trailers, cancellation,
connection reuse, concurrent handle pooling, multipart uploads, WebSockets, and
custom fingerprint application. See [UPSTREAM.md](UPSTREAM.md) for the upstream
test mapping and scope.

`Curl.Duplicate` uses native `curl_easy_duphandle`, with independent callback
state, error buffers, borrowed header lists, and direct POSTFIELDS storage.
Regression tests cover replacement-body ownership, binary bodies and explicit
body lengths, detached MIME forms, callback cancellation/errors, and temporary
empty reads. Duplication preserves native configuration without replaying a
history of option-setting commands.

The CI workflow installs the same pinned release on Linux amd64 and arm64,
macOS arm64 and amd64, and Windows amd64. A separate Alpine job tests Linux
amd64 musl. A configured CI matrix is not evidence that those jobs have already
run. The full normal suite, race suite, `go vet`, and `go build` have been
verified before the independent parity suite was added on macOS arm64
(Go 1.26.1) and Linux arm64 GNU (Go 1.25.14 in an ephemeral official `golang:1.25`
container). Both used the checksum-verified v2.2.3 native library. The new
native parity matrix is verified locally on macOS arm64. Its Linux rerun could
not start because the local Docker daemon was unavailable; CI installs the
independent executable on all configured platforms. A live default-Chrome request to `https://example.com`
also returned HTTP/2 200 with certificate verification enabled.

To regenerate the profile expectations, obtain `patches/curl.patch` from tag
`v2.2.3` and run:

```sh
python3 tools/generate_profile_signatures.py /path/to/curl.patch
```

The generator checks the pinned source digest, records the release commit and
SHA-256, and refuses an unrelated source snapshot. Native release upgrades must
update the installer digests, headers/constants, profile registry, fixture
generator, and resulting wire expectations together.

The option type table can be regenerated from the vendored release header with
`python3 tools/generate_option_kinds.py`. The Go numeric constants come from
the pinned curl_cffi `const.py` identified in [UPSTREAM.md](UPSTREAM.md), using
`python3 tools/generate_constants.py /path/to/const.py` followed by `gofmt -w constants.go`.
