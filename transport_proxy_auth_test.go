package curlgo

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportProxyDigestAuthenticationFinalResponse(t *testing.T) {
	const target = "http://example.test/proxy-digest?fixed=1"
	for _, test := range []struct {
		name, password, body string
		status               int
	}{
		{"authenticated", "proxy-pass", "final proxy response", http.StatusOK},
		{"rejected", "incorrect", "proxy authentication denied", http.StatusProxyAuthRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			var attempts atomic.Int32
			// This is the actual configured HTTP proxy. It answers the absolute
			// request target itself; no DNS lookup or origin network is involved.
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := attempts.Add(1)
				if r.RequestURI != target || r.Host != "example.test" || r.Header.Get("Authorization") != "" {
					t.Errorf("proxy request target=%q host=%q origin authorization=%q", r.RequestURI, r.Host, r.Header.Get("Authorization"))
					http.Error(w, "unexpected proxy request", http.StatusBadRequest)
					return
				}
				w.Header().Set("X-Proxy-Exchange", fmt.Sprint(attempt))
				if !proxyDigestTestAuthenticated(r) {
					w.Header().Set("Proxy-Authenticate", `Digest realm="curl-go-proxy", nonce="fixed-proxy-nonce", algorithm=MD5, qop="auth"`)
					w.WriteHeader(http.StatusProxyAuthRequired)
					_, _ = io.WriteString(w, "proxy authentication denied")
					return
				}
				w.Header().Set("X-Proxy-Final", "authenticated")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "final proxy response")
			}))
			defer proxy.Close()
			client := transportClient(t)
			client.Timeout = 3 * time.Second
			client.CurlTransport.Proxy = proxy.URL
			client.CurlTransport.CurlOptions = map[Option]any{
				OptProxyAuth: 2, OptProxyUserPwd: "proxy-user:" + test.password, OptNoProxy: "",
			}
			response, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			body := responseBytes(t, response, nil)
			if attempts.Load() != 2 {
				t.Fatalf("proxy attempts=%d; want challenge then authenticated retry", attempts.Load())
			}
			if response.StatusCode != test.status || response.Header.Get("X-Proxy-Exchange") != "2" || string(body) != test.body {
				t.Fatalf("final proxy response status=%d headers=%v body=%q; want status=%d exchange=2 body=%q", response.StatusCode, response.Header, body, test.status, test.body)
			}
			if test.status == http.StatusOK && response.Header.Get("X-Proxy-Final") != "authenticated" {
				t.Fatalf("final proxy response headers missing: %v", response.Header)
			}
			if response.Trailer.Get("X-Proxy-Final") != "" || response.Trailer.Get("X-Proxy-Exchange") != "" {
				t.Fatalf("proxy retry headers misclassified as trailers: %v", response.Trailer)
			}
		})
	}
}

func proxyDigestTestAuthenticated(r *http.Request) bool {
	value := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(value, "Digest ") {
		return false
	}
	fields := make(map[string]string)
	for _, field := range strings.Split(strings.TrimPrefix(value, "Digest "), ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return false
		}
		fields[name] = strings.Trim(value, `"`)
	}
	// libcurl's Digest URI is the path/query even though the forwarding request
	// target is absolute. Both forms are checked independently by this test.
	if fields["username"] != "proxy-user" || fields["realm"] != "curl-go-proxy" || fields["nonce"] != "fixed-proxy-nonce" || fields["uri"] != r.URL.RequestURI() || fields["qop"] != "auth" {
		return false
	}
	response := digestTestMD5(digestTestMD5("proxy-user:curl-go-proxy:proxy-pass") + ":fixed-proxy-nonce:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + digestTestMD5(r.Method+":"+fields["uri"]))
	return fields["response"] == response
}
