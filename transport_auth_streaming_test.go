package curlgo

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportTerminalAuthenticationHeadersStreamBeforeBody(t *testing.T) {
	const digestChallenge = `Digest realm="curl-go-stream", nonce="fixed-stream-nonce", algorithm=MD5, qop="auth"`
	for _, test := range []struct {
		name        string
		proxy       bool
		auth        int
		credentials bool
		challenge   string
		requests    int32
		finalAuth   string
	}{
		{name: "origin-basic-rejected", auth: 1, credentials: true, challenge: `Basic realm="curl-go-stream"`, requests: 1, finalAuth: "Basic "},
		{name: "origin-digest-rejected", auth: 2, credentials: true, challenge: digestChallenge, requests: 2, finalAuth: "Digest "},
		{name: "origin-basic-incompatible-digest", auth: 1, credentials: true, challenge: digestChallenge, requests: 1, finalAuth: "Basic "},
		{name: "origin-digest-incompatible-basic", auth: 2, credentials: true, challenge: `Basic realm="curl-go-stream"`, requests: 1},
		{name: "origin-digest-no-credentials", auth: 2, challenge: digestChallenge, requests: 1},
		{name: "proxy-basic-rejected", proxy: true, auth: 1, credentials: true, challenge: `Basic realm="curl-go-stream"`, requests: 1, finalAuth: "Basic "},
		{name: "proxy-digest-rejected", proxy: true, auth: 2, credentials: true, challenge: digestChallenge, requests: 2, finalAuth: "Digest "},
	} {
		t.Run(test.name, func(t *testing.T) {
			const finalBody = "terminal authentication response body"
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
			var attempts atomic.Int32
			status, challengeHeader, authorizationHeader := http.StatusUnauthorized, "WWW-Authenticate", "Authorization"
			if test.proxy {
				status, challengeHeader, authorizationHeader = http.StatusProxyAuthRequired, "Proxy-Authenticate", "Proxy-Authorization"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				attempt := attempts.Add(1)
				if attempt > test.requests {
					t.Errorf("native client retried terminal response: attempt %d, want %d", attempt, test.requests)
					http.Error(w, "unexpected authentication retry", http.StatusBadRequest)
					return
				}
				if test.proxy && (request.RequestURI != "http://example.test/auth-stream" || request.Header.Get("Authorization") != "") {
					t.Errorf("proxy request target=%q origin authorization=%q", request.RequestURI, request.Header.Get("Authorization"))
				}
				w.Header().Set(challengeHeader, test.challenge)
				w.Header().Set("X-Auth-Attempt", fmt.Sprint(attempt))
				if attempt < test.requests {
					if request.Header.Get(authorizationHeader) != "" {
						t.Errorf("initial Digest exchange unexpectedly sent credentials: %q", request.Header.Get(authorizationHeader))
					}
					// The retryable challenge completes immediately. Only the
					// terminal response body waits for the caller to release it.
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(status)
					return
				}
				authorization := request.Header.Get(authorizationHeader)
				if (test.finalAuth == "" && authorization != "") || (test.finalAuth != "" && !strings.HasPrefix(authorization, test.finalAuth)) {
					t.Errorf("terminal authentication header=%q, want prefix %q", authorization, test.finalAuth)
				}
				w.Header().Set("X-Final", "terminal-authentication")
				w.Header().Set("Content-Length", strconv.Itoa(len(finalBody)))
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				select {
				case <-release:
					_, _ = io.WriteString(w, finalBody)
				case <-request.Context().Done():
				}
			}))
			defer server.Close()
			defer releaseBody() // Unblock handlers before Close even on a failed assertion.
			client := transportClient(t)
			client.Timeout = time.Second
			client.CurlTransport.Timeout = 750 * time.Millisecond
			client.CurlTransport.CurlOptions = make(map[Option]any)
			target := server.URL + "/auth-stream"
			if test.proxy {
				target = "http://example.test/auth-stream"
				client.CurlTransport.Proxy = server.URL
				client.CurlTransport.CurlOptions[OptNoProxy] = ""
				client.CurlTransport.CurlOptions[OptProxyAuth] = test.auth
				if test.credentials {
					client.CurlTransport.CurlOptions[OptProxyUserPwd] = "stream-user:wrong"
				}
			} else {
				client.CurlTransport.CurlOptions[OptHTTPAuth] = test.auth
				if test.credentials {
					client.CurlTransport.CurlOptions[OptUsername] = "stream-user"
					client.CurlTransport.CurlOptions[OptPassword] = "wrong"
				}
			}
			response, err := client.Get(target)
			if err != nil {
				t.Fatalf("terminal response headers waited for gated body: %v (native attempts=%d)", err, attempts.Load())
			}
			defer response.Body.Close()
			if response.StatusCode != status || response.Header.Get("X-Final") != "terminal-authentication" || response.Header.Get("X-Auth-Attempt") != fmt.Sprint(test.requests) {
				t.Fatalf("published response status=%d headers=%v; want terminal status=%d attempt=%d", response.StatusCode, response.Header, status, test.requests)
			}
			if attempts.Load() != test.requests {
				t.Fatalf("native requests=%d, want %d", attempts.Load(), test.requests)
			}
			// Get has returned while the server still cannot write a byte of
			// body. Release it now and verify the response remains readable.
			releaseBody()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != finalBody {
				t.Fatalf("terminal body=%q, %v; want %q", body, err, finalBody)
			}
			if attempts.Load() != test.requests {
				t.Fatalf("native requests after body=%d, want %d", attempts.Load(), test.requests)
			}
		})
	}
}
