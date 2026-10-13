package curlgo

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportDigestPOSTReloadHidesSuccessProbe(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("X-Exchange", fmt.Sprint(attempt))
		if attempt == 1 {
			if len(body) != 0 {
				t.Errorf("authentication probe uploaded %q", body)
			}
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Length", "999")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		if attempt != 2 || string(body) != "upload" {
			t.Errorf("native reload attempt=%d body=%q", attempt, body)
		}
		_, _ = io.WriteString(w, "final POST response")
	}))
	defer server.Close()
	defer releaseBody()
	client := configureDigestTestClient(t, "pass")
	client.Timeout = time.Second
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("upload"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Exchange") != "2" || string(body) != "final POST response" || requests.Load() != 2 {
		t.Fatalf("response=%d %v body=%q error=%v attempts=%d", response.StatusCode, response.Header, body, err, requests.Load())
	}
}

func TestTransportAuthenticationFinalHeadersSurviveBodyDecodingError(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("X-Final", "headers before invalid body")
				if status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Basic realm="curl-go"`)
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "invalid gzip body")
			}))
			defer server.Close()
			client := transportClient(t)
			client.Timeout = time.Second
			client.CurlTransport.CurlOptions = map[Option]any{
				OptHTTPAuth: 1, OptUsername: "user", OptPassword: "wrong",
			}
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("native body failure hid final headers: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != status || response.Header.Get("X-Final") != "headers before invalid body" {
				t.Fatalf("final response=%d %v", response.StatusCode, response.Header)
			}
			_, err = io.ReadAll(response.Body)
			var native *CurlError
			if !errors.As(err, &native) || native.Code != CurlECode_BAD_CONTENT_ENCODING {
				t.Fatalf("body error=%v; want native content-decoding error", err)
			}
		})
	}
}

func TestTransportAuthenticationReloadLimitDoesNotPublishProbe(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
				}
				w.Header().Set("Connection", "close")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "probe")
			}))
			defer server.Close()
			client := configureDigestTestClient(t, "pass")
			client.CurlTransport.CurlOptions[OptMaxRedirs] = 0
			method := http.MethodGet
			var upload io.Reader
			if status == http.StatusOK {
				method, upload = http.MethodPost, strings.NewReader("upload")
			}
			request, err := http.NewRequest(method, server.URL, upload)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if response != nil {
				response.Body.Close()
				t.Fatalf("native reload failure published intermediate status %d", response.StatusCode)
			}
			var native *CurlError
			if !errors.As(err, &native) || native.Code != CurlECode_TOO_MANY_REDIRECTS || requests.Load() != 1 {
				t.Fatalf("reload error=%v requests=%d; want native redirect-limit error and one request", err, requests.Load())
			}
		})
	}
}
