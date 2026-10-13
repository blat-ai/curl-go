package curlgo

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func digestTestMD5(value string) string {
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}

func digestTestAuthenticated(r *http.Request) bool {
	value := r.Header.Get("Authorization")
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
	if fields["username"] != "user" || fields["realm"] != "curl-go" || fields["nonce"] != "fixed-test-nonce" || fields["uri"] != r.URL.RequestURI() || fields["qop"] != "auth" {
		return false
	}
	response := digestTestMD5(digestTestMD5("user:curl-go:pass") + ":fixed-test-nonce:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + digestTestMD5(r.Method+":"+fields["uri"]))
	return fields["response"] == response
}

func configureDigestTestClient(t *testing.T, password string) *Client {
	t.Helper()
	client := transportClient(t)
	client.Timeout = 3 * time.Second
	client.CurlTransport.CurlOptions = map[Option]any{
		OptHTTPAuth: 2, OptUsername: "user", OptPassword: password,
	}
	return client
}

func TestTransportDigestAuthenticationFinalResponse(t *testing.T) {
	for _, test := range []struct {
		name, method, password, body string
		status                       int
	}{
		{"success", "GET", "pass", "authenticated body", http.StatusOK},
		{"empty", "GET", "pass", "", http.StatusOK},
		{"no-content", "GET", "pass", "", http.StatusNoContent},
		{"head", "HEAD", "pass", "", http.StatusOK},
		{"rejected", "GET", "incorrect", "denied body", http.StatusUnauthorized},
		{"rejected-head", "HEAD", "incorrect", "", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := requests.Add(1)
				if !digestTestAuthenticated(r) {
					w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
					w.Header().Set("X-Exchange", fmt.Sprint(attempt))
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, "denied body")
					return
				}
				w.Header().Set("X-Exchange", fmt.Sprint(attempt))
				w.Header().Set("X-Final", "authenticated")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := configureDigestTestClient(t, test.password)
			request, _ := http.NewRequest(test.method, server.URL+"/digest", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body := responseBytes(t, response, nil)
			if requests.Load() != 2 {
				t.Fatalf("native requests=%d; want challenge then retry", requests.Load())
			}
			if response.StatusCode != test.status || response.Header.Get("X-Exchange") != "2" || string(body) != test.body {
				t.Fatalf("final response status=%d headers=%v body=%q; want status=%d exchange=2 body=%q", response.StatusCode, response.Header, body, test.status, test.body)
			}
			if test.password == "pass" && response.Header.Get("X-Final") != "authenticated" {
				t.Fatalf("final headers missing: %v", response.Header)
			}
			if response.Trailer.Get("X-Final") != "" {
				t.Fatalf("retry headers misclassified as trailers: %v", response.Trailer)
			}
		})
	}
}

func TestTransportDigestFinalHeadersRemainStreaming(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !digestTestAuthenticated(r) {
			w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Final", "streaming")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "body after response headers")
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	client := configureDigestTestClient(t, "pass")
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Final") != "streaming" {
		t.Fatalf("streaming response=%d %v", response.StatusCode, response.Header)
	}
	// The server cannot send its body until this test releases it, so final
	// headers must be available without waiting for the response body.
}

func TestTransportNativeAuthenticationWithoutChallengeStreams(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusProxyAuthRequired} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Final", "no authentication challenge")
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer server.Close()
			client := configureDigestTestClient(t, "pass")
			client.CurlTransport.Timeout = 200 * time.Millisecond
			client.CurlTransport.CurlOptions[OptProxyAuth] = 2
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("final response headers did not stream: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != status || response.Header.Get("X-Final") != "no authentication challenge" {
				t.Fatalf("final response=%d %v", response.StatusCode, response.Header)
			}
		})
	}
}

func TestTransportDeadlineDuringBufferedUpload(t *testing.T) {
	client := transportClient(t)
	client.CurlTransport.Timeout = 25 * time.Millisecond
	client.CurlTransport.MaxRequestBodyBytes = 1024
	reader, writer := io.Pipe()
	defer writer.Close()
	request, err := http.NewRequest(http.MethodPost, "http://localhost:9/unreached", reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("buffered upload timeout=%v; want context deadline", err)
	}
}

func TestTransportDeadlineDuringResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := transportClient(t)
	client.CurlTransport.Timeout = 25 * time.Millisecond
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if string(body) != "prefix" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body=%q timeout=%v; want prefix and context deadline", body, err)
	}
}

func TestTransportExplicitNativeTimeoutRemainsNative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := transportClient(t)
	client.CurlTransport.Timeout = time.Second
	client.CurlTransport.CurlOptions = map[Option]any{OptTimeoutMS: 10}
	_, err := client.Get(server.URL)
	var native *CurlError
	if !errors.As(err, &native) || !native.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("explicit native timeout=%v; want native timeout before transport deadline", err)
	}
}
