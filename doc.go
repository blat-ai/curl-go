// Package curlgo binds curl-impersonate's native TLS and HTTP browser profiles
// to Go. Transport implements net/http.RoundTripper; Client adds a cookie jar
// and standard HTTP conveniences. Curl exposes typed low-level options, native
// MIME, custom fingerprints, and WebSocket frame operations.
//
// Install the pinned native library with go run ./cmd/curl-go-install or point
// CURL_IMPERSONATE_LIB at an existing curl-impersonate shared library. A C
// compiler and cgo are required. Close clients and native handles explicitly.
package curlgo
