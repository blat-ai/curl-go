package curlgo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportDigestReplaysRequestGetBody(t *testing.T) {
	for _, mode := range []string{"standard", "tracked-bodies"} {
		t.Run(mode, func(t *testing.T) {
			const finalBody = "authenticated after upload replay"
			payload := strings.Repeat("replay this streamed POST\x00", 8192)
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := attempts.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("attempt %d body: %v", attempt, err)
					return
				}
				switch attempt {
				case 1:
					if len(body) != 0 || r.Header.Get("Authorization") != "" {
						t.Errorf("Digest probe body length=%d authorization=%q", len(body), r.Header.Get("Authorization"))
					}
					w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fixed-test-nonce", algorithm=MD5, qop="auth"`)
					w.WriteHeader(http.StatusUnauthorized)
				case 2:
					if string(body) != payload || !digestTestAuthenticated(r) {
						t.Errorf("first authenticated upload length=%d authorization=%q", len(body), r.Header.Get("Authorization"))
					}
					w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="fresh-test-nonce", algorithm=MD5, qop="auth", stale=true`)
					w.WriteHeader(http.StatusUnauthorized)
				case 3:
					if string(body) != payload || !digestRetryAuthenticatedWithNonce(r, "fresh-test-nonce") {
						t.Errorf("replayed upload length=%d authorization=%q", len(body), r.Header.Get("Authorization"))
					}
					_, _ = io.WriteString(w, finalBody)
				default:
					t.Errorf("unexpected upload attempt %d", attempt)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			client := configureDigestTestClient(t, "pass")
			client.Timeout = 2 * time.Second
			client.CurlTransport.CurlOptions[OptHTTPVersion] = HTTPVersion1_1
			request, err := http.NewRequest(http.MethodPost, server.URL+"/upload", strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if _, seekable := request.Body.(io.Seeker); seekable || request.GetBody == nil {
				t.Fatal("regression requires a wrapped non-seekable Body with GetBody")
			}
			var opened, closed atomic.Int32
			if mode == "tracked-bodies" {
				opened.Add(1)
				request.Body = &uploadCloseCounter{ReadCloser: request.Body, closed: &closed}
				getBody := request.GetBody
				request.GetBody = func() (io.ReadCloser, error) {
					body, err := getBody()
					if err != nil {
						return nil, err
					}
					opened.Add(1)
					return &uploadCloseCounter{ReadCloser: body, closed: &closed}, nil
				}
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("unbuffered Digest upload replay: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != finalBody || attempts.Load() != 3 {
				t.Fatalf("status=%d body=%q error=%v attempts=%d", response.StatusCode, body, err, attempts.Load())
			}
			if err := client.CurlTransport.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "tracked-bodies" && (opened.Load() < 2 || closed.Load() != opened.Load()) {
				t.Fatalf("upload streams opened=%d closed=%d; every original/replayed stream must close exactly once", opened.Load(), closed.Load())
			}
		})
	}
}

type uploadCloseCounter struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (b *uploadCloseCounter) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

func TestTransportDigestReplayBodyFailure(t *testing.T) {
	for _, mode := range []string{"factory-error", "factory-error-with-body", "nil-body", "blocked-replay"} {
		t.Run(mode, func(t *testing.T) {
			payload := strings.Repeat("upload", 32768)
			var attempts, opened, closed atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := attempts.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return // Cancellation can interrupt the replayed upload.
				}
				if attempt == 2 && string(body) != payload {
					t.Errorf("first authenticated body length=%d, want %d", len(body), len(payload))
				}
				nonce := "fixed-test-nonce"
				stale := ""
				if attempt >= 2 {
					nonce, stale = "fresh-test-nonce", ", stale=true"
				}
				w.Header().Set("WWW-Authenticate", `Digest realm="curl-go", nonce="`+nonce+`", algorithm=MD5, qop="auth"`+stale)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			client := configureDigestTestClient(t, "pass")
			client.CurlTransport.CurlOptions[OptHTTPVersion] = HTTPVersion1_1
			request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			opened.Add(1)
			request.Body = &uploadCloseCounter{ReadCloser: request.Body, closed: &closed}
			sentinel := errors.New("GetBody could not reopen upload")
			reader, writer := io.Pipe()
			defer writer.Close()
			defer reader.Close()
			replaying := make(chan struct{})
			readingReplay := make(chan struct{})
			request.GetBody = func() (io.ReadCloser, error) {
				close(replaying)
				switch mode {
				case "factory-error":
					return nil, sentinel
				case "factory-error-with-body":
					opened.Add(1)
					return &uploadCloseCounter{ReadCloser: reader, closed: &closed}, sentinel
				case "nil-body":
					return nil, nil
				default:
					opened.Add(1)
					return &uploadCloseCounter{ReadCloser: &uploadReadSignal{ReadCloser: reader, started: readingReplay}, closed: &closed}, nil
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request = request.WithContext(ctx)
			finished := make(chan error, 1)
			go func() {
				response, err := client.Do(request)
				if response != nil {
					response.Body.Close()
				}
				finished <- err
			}()
			select {
			case <-replaying:
			case <-time.After(2 * time.Second):
				t.Fatal("native authentication never requested GetBody")
			}
			if mode == "blocked-replay" {
				select {
				case <-readingReplay:
				case <-time.After(2 * time.Second):
					t.Fatal("native authentication never read the replayed body")
				}
				cancel()
			}
			select {
			case err = <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("upload replay did not stop after failure/cancellation")
			}
			if strings.HasPrefix(mode, "factory-error") && !errors.Is(err, sentinel) {
				t.Fatalf("factory failure=%v; want original GetBody error", err)
			}
			if mode == "nil-body" && (err == nil || !strings.Contains(err.Error(), "nil body")) {
				t.Fatalf("nil GetBody stream=%v; want a clear error", err)
			}
			if mode == "blocked-replay" && !errors.Is(err, context.Canceled) {
				t.Fatalf("blocked replay cancellation=%v", err)
			}
			if err := client.CurlTransport.Close(); err != nil {
				t.Fatal(err)
			}
			if attempts.Load() < 2 || opened.Load() != closed.Load() {
				t.Fatalf("attempts=%d upload streams opened=%d closed=%d", attempts.Load(), opened.Load(), closed.Load())
			}
		})
	}
}

type uploadReadSignal struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (r *uploadReadSignal) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(p)
}
