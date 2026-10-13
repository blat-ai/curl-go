package curlgo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTransportExplicitProxyIgnoresEnvironmentNoProxy(t *testing.T) {
	for _, routing := range []string{"proxy-field", "proxy-function"} {
		for _, bypass := range []struct{ name, value, host string }{
			{"all-hosts", "*", "127.0.0.1"},
			{"matching-host", "localhost", "localhost"},
		} {
			t.Run(routing+"/"+bypass.name, func(t *testing.T) {
				t.Setenv("NO_PROXY", bypass.value)
				t.Setenv("no_proxy", bypass.value)
				var origins, proxies, callbacks atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					origins.Add(1)
					_, _ = io.WriteString(w, "origin")
				}))
				defer origin.Close()
				target := strings.Replace(origin.URL, "127.0.0.1", bypass.host, 1) + "/proxy-check?fixed=1"
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					proxies.Add(1)
					if request.RequestURI != target {
						t.Errorf("proxy request target=%q, want %q", request.RequestURI, target)
					}
					_, _ = io.WriteString(w, "proxy")
				}))
				defer proxy.Close()
				client := transportClient(t)
				if routing == "proxy-field" {
					client.CurlTransport.Proxy = proxy.URL
				} else {
					proxyURL, err := url.Parse(proxy.URL)
					if err != nil {
						t.Fatal(err)
					}
					client.CurlTransport.ProxyFunc = func(request *http.Request) (*url.URL, error) {
						callbacks.Add(1)
						if request.URL.String() != target {
							t.Errorf("ProxyFunc URL=%q, want %q", request.URL, target)
						}
						return proxyURL, nil
					}
				}
				response, err := client.Get(target)
				body := responseBytes(t, response, err)
				if string(body) != "proxy" || proxies.Load() != 1 || origins.Load() != 0 {
					t.Fatalf("explicit routing overridden by NO_PROXY=%q: body=%q proxy=%d origin=%d", bypass.value, body, proxies.Load(), origins.Load())
				}
				if routing == "proxy-function" && callbacks.Load() != 1 {
					t.Fatalf("ProxyFunc calls=%d, want 1", callbacks.Load())
				}
			})
		}
	}
}

func TestTransportProxyFunctionNilSelectsDirectRouting(t *testing.T) {
	var proxies atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxies.Add(1)
		_, _ = io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	client := transportClient(t)
	client.CurlTransport.Proxy = proxy.URL
	client.CurlTransport.ProxyFunc = func(*http.Request) (*url.URL, error) { return nil, nil }
	response, err := client.Get(origin.URL)
	if body := responseBytes(t, response, err); string(body) != "origin" || proxies.Load() != 0 {
		t.Fatalf("nil ProxyFunc did not choose direct routing: body=%q proxy=%d", body, proxies.Load())
	}
}

func TestTransportExplicitNoProxyOptionCanBypassProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	var proxies atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxies.Add(1)
		_, _ = io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	client := transportClient(t)
	client.CurlTransport.Proxy = proxy.URL
	client.CurlTransport.CurlOptions = map[Option]any{OptNoProxy: "*"}
	response, err := client.Get(origin.URL)
	if body := responseBytes(t, response, err); string(body) != "origin" || proxies.Load() != 0 {
		t.Fatalf("explicit OptNoProxy override ignored: body=%q proxy=%d", body, proxies.Load())
	}
}
