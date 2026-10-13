package curlgo

import (
	"errors"
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

func TestTransportDigestRetryClosesUnfinishedChallenge(t *testing.T) {
	const finalBody = "authenticated final response"
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
	var requests, ignoredMessages atomic.Int32
	var debugCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		if attempt == 1 {
			if r.Header.Get("Authorization") != "" {
				t.Errorf("initial Digest request sent credentials: %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
			w.Header().Set("X-Intermediate", "unfinished-challenge")
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Length", "999")
			w.WriteHeader(http.StatusUnauthorized)
			w.(http.Flusher).Flush()
			// Native curl closes this connection and retries without consuming
			// its advertised body. The test never releases it before Get.
			select {
			case <-release:
				_, _ = io.WriteString(w, "challenge body must remain hidden")
			case <-r.Context().Done():
			}
			return
		}
		if attempt != 2 || !digestTestAuthenticated(r) {
			t.Errorf("retried request=%d authorization=%q", attempt, r.Header.Get("Authorization"))
			http.Error(w, "unexpected Digest retry", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Final", "authenticated")
		_, _ = io.WriteString(w, finalBody)
	}))
	defer server.Close()
	defer releaseBody()
	client := configureDigestTestClient(t, "pass")
	client.Timeout = time.Second
	client.CurlTransport.CurlOptions[OptHTTPVersion] = HTTPVersion1_1
	client.CurlTransport.CurlOptions[OptVerbose] = true
	client.CurlTransport.CurlOptions[OptDebugFunction] = DebugFunc(func(kind DebugType, data []byte) {
		debugCalls.Add(1)
		if kind == DebugText && strings.Contains(string(data), "Ignoring the response-body") {
			ignoredMessages.Add(1)
		}
	})
	response, err := client.Get(server.URL + "/close-challenge")
	if err != nil {
		t.Fatalf("native retry waited for unfinished challenge body: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Final") != "authenticated" || response.Header.Get("X-Intermediate") != "" || string(body) != finalBody {
		t.Fatalf("published status=%d headers=%v body=%q, error=%v", response.StatusCode, response.Header, body, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d, want initial challenge and authenticated retry", requests.Load())
	}
	if debugCalls.Load() == 0 || ignoredMessages.Load() != 0 {
		t.Fatalf("debug calls=%d, body-ignore messages=%d; connection-close retry should not need a body-ignore signal", debugCalls.Load(), ignoredMessages.Load())
	}
}

func TestTransportDigestStaleChallengeRetriesWithFreshNonce(t *testing.T) {
	const finalBody = "final response after stale nonce"
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		switch attempt {
		case 1:
			if r.Header.Get("Authorization") != "" {
				t.Errorf("initial Digest request sent credentials")
			}
			w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
			w.Header().Set("X-Intermediate", "initial-challenge")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "initial challenge body")
		case 2:
			if !digestTestAuthenticated(r) {
				t.Errorf("second request has invalid initial-nonce Digest: %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fresh-test-nonce", algorithm=MD5, qop="auth", stale=true`)
			w.Header().Set("X-Intermediate", "stale-challenge")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "stale challenge body")
		case 3:
			if !digestRetryAuthenticatedWithNonce(r, "fresh-test-nonce") {
				t.Errorf("third request has invalid fresh-nonce Digest: %q", r.Header.Get("Authorization"))
				http.Error(w, "invalid renewed authentication", http.StatusBadRequest)
				return
			}
			w.Header().Set("X-Final", "fresh-nonce")
			w.Header().Set("Content-Length", strconv.Itoa(len(finalBody)))
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-release:
				_, _ = io.WriteString(w, finalBody)
			case <-r.Context().Done():
			}
		default:
			t.Errorf("unexpected authentication attempt %d", attempt)
			http.Error(w, "too many authentication retries", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	defer releaseBody()
	client := configureDigestTestClient(t, "pass")
	client.Timeout = time.Second
	client.CurlTransport.CurlOptions[OptHTTPVersion] = HTTPVersion1_1
	response, err := client.Get(server.URL + "/stale-challenge")
	if err != nil {
		t.Fatalf("final response headers did not stream after stale retry: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Final") != "fresh-nonce" || response.Header.Get("X-Intermediate") != "" || requests.Load() != 3 {
		t.Fatalf("published status=%d headers=%v requests=%d", response.StatusCode, response.Header, requests.Load())
	}
	releaseBody()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != finalBody {
		t.Fatalf("final body=%q, %v; want %q", body, err, finalBody)
	}
}

func digestRetryAuthenticatedWithNonce(r *http.Request, nonce string) bool {
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
	if fields["username"] != "user" || fields["realm"] != "curl-go" || fields["nonce"] != nonce || fields["uri"] != r.URL.RequestURI() || fields["qop"] != "auth" || fields["nc"] != "00000001" {
		return false
	}
	want := digestTestMD5(digestTestMD5("user:curl-go:pass") + ":" + nonce + ":" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + digestTestMD5(r.Method+":"+fields["uri"]))
	return fields["response"] == want
}

func TestTransportUserDebugCallbackHonorsVerbose(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		t.Run(fmt.Sprint(verbose), func(t *testing.T) {
			var calls atomic.Int32
			var sentHeaders, receivedHeaders atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				if !ok || user != "debug-user" || password != "debug-pass" {
					t.Errorf("configured Basic credentials were not sent")
				}
				_, _ = io.WriteString(w, "debug response")
			}))
			defer server.Close()
			client := transportClient(t)
			client.Timeout = time.Second
			client.CurlTransport.CurlOptions = map[Option]any{
				OptHTTPVersion: HTTPVersion1_1,
				OptHTTPAuth:    1, OptUsername: "debug-user", OptPassword: "debug-pass",
				OptVerbose: verbose,
				OptDebugFunction: DebugFunc(func(kind DebugType, data []byte) {
					calls.Add(1)
					if kind == DebugHeaderOut && strings.Contains(string(data), "GET /debug") {
						sentHeaders.Store(true)
					}
					if kind == DebugHeaderIn && strings.Contains(string(data), "HTTP/1.1 200") {
						receivedHeaders.Store(true)
					}
				}),
			}
			response, err := client.Get(server.URL + "/debug")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "debug response" {
				t.Fatalf("response body=%q, %v", body, err)
			}
			if !verbose && calls.Load() != 0 {
				t.Fatalf("Verbose=false invoked user debug callback %d times", calls.Load())
			}
			if verbose && (calls.Load() == 0 || !sentHeaders.Load() || !receivedHeaders.Load()) {
				t.Fatalf("Verbose=true callbacks=%d sent headers=%v received headers=%v", calls.Load(), sentHeaders.Load(), receivedHeaders.Load())
			}
		})
	}
}

func TestTransportAuthenticationFailOnErrorPreservesNativeFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("configured Basic credentials were not sent")
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="curl-go"`)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := transportClient(t)
	client.Timeout = time.Second
	client.CurlTransport.CurlOptions = map[Option]any{
		OptHTTPVersion: HTTPVersion1_1,
		OptHTTPAuth:    1, OptUsername: "user", OptPassword: "wrong",
		OptFailOnError: true,
	}
	response, err := client.Get(server.URL + "/fail-on-auth-error")
	if response != nil {
		response.Body.Close()
		t.Fatalf("FailOnError published rejected-authentication response: %s", response.Status)
	}
	var native *CurlError
	if !errors.As(err, &native) || native.Code != CurlECode_HTTP_RETURNED_ERROR {
		t.Fatalf("FailOnError=%v; want native curl HTTP_RETURNED_ERROR", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d; rejected preemptive Basic authentication must not retry", requests.Load())
	}
}
