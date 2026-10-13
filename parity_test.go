package curlgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The reference is the released executable, in a separate process. These tests
// deliberately exercise Client/Transport rather than another easy-handle wrapper.
type parityRequestSpec struct {
	URL      string
	Method   string
	Body     []byte
	Headers  []Header
	Mode     string
	ExtraCLI []string
	Options  map[Option]any
}

func TestAllProfilesNativeParity(t *testing.T) {
	executable := nativeParityCLI(t)
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			for _, mode := range []string{"http1", "tls-http1", "tls-http2", "tls12-http2", "http3"} {
				t.Run(mode, func(t *testing.T) {
					var url string
					if mode == "http3" {
						server := startParityHTTP3Server(t)
						t.Cleanup(func() { _ = server.Close() })
						url = server.URL
					} else {
						server := startParityTCPServer(t, mode)
						t.Cleanup(func() { _ = server.Close() })
						url = server.URL
					}
					for _, scenario := range []string{"default-get", "ordered-post"} {
						t.Run(scenario, func(t *testing.T) {
							spec := paritySpec(url, mode, scenario)
							if mode == "http3" && legacyParityHTTP3(profile) {
								// These native presets lack QUIC extension 57. Both
								// clients receive the same documented custom override.
								order := "28-51-27-13-34-10-45-16-65281-23-5-0-43-57-65037"
								spec.Options[OptHTTP3TLSExtensionOrder] = order
								spec.ExtraCLI = []string{"--http3-tls-extension-order", order}
								t.Log("comparing explicitly customized HTTP/3; native default lacks QUIC extension 57")
							}
							assertNativeParity(t, executable, profile, spec)
						})
					}
				})
			}
		})
	}
}

func TestProfileAliasesNativeParity(t *testing.T) {
	executable := nativeParityCLI(t)
	aliases := ProfileAliases()
	var names []string
	for alias := range aliases {
		names = append(names, string(alias))
	}
	sort.Strings(names)
	for _, alias := range names {
		t.Run(alias, func(t *testing.T) {
			server := startParityTCPServer(t, "tls-http2")
			t.Cleanup(func() { _ = server.Close() })
			assertNativeParity(t, executable, Profile(alias), paritySpec(server.URL, "tls-http2", "default-get"))
		})
	}
}

func TestLegacyProfilesNativeHTTP3FailureParity(t *testing.T) {
	executable := nativeParityCLI(t)
	for _, profile := range []Profile{Firefox133, Firefox135, Firefox144, Tor145} {
		t.Run(string(profile), func(t *testing.T) {
			server := startParityHTTP3Server(t)
			t.Cleanup(func() { _ = server.Close() })
			spec := paritySpec(server.URL, "http3", "default-get")
			_, goErr := runParityGo(t, profile, spec)
			var curlErr *CurlError
			if !errors.As(goErr, &curlErr) || curlErr.Code != ErrCodeCouldntConnect {
				t.Fatalf("Go native preset error=%v; want CURL_COULDNT_CONNECT", goErr)
			}
			_, nativeErr := runParityCLI(t, executable, profile, spec)
			var exitErr *exec.ExitError
			if !errors.As(nativeErr, &exitErr) || exitErr.ExitCode() != int(ErrCodeCouldntConnect) {
				t.Fatalf("native preset error=%v; want curl exit code %d", nativeErr, ErrCodeCouldntConnect)
			}
		})
	}
}

func legacyParityHTTP3(profile Profile) bool {
	return profile == Firefox133 || profile == Firefox135 || profile == Firefox144 || profile == Tor145
}

func paritySpec(url, mode, scenario string) parityRequestSpec {
	spec := parityRequestSpec{URL: url, Method: http.MethodGet, Mode: mode, Options: make(map[Option]any)}
	switch mode {
	case "http1", "tls-http1":
		spec.Options[OptHTTPVersion] = HTTPVersion1_1
	case "tls-http2", "tls12-http2":
		spec.Options[OptHTTPVersion] = HTTPVersion2
	case "http3":
		spec.Options[OptHTTPVersion] = HTTPVersion3Only
	}
	if mode == "tls12-http2" {
		spec.Options[OptSSLVersion] = SSLVersionTLS1_2 | (SSLVersionTLS1_2 << 16)
	}
	if scenario == "ordered-post" {
		spec.Method = http.MethodPost
		spec.Body = []byte("curl-go parity\x00\xff\r\nfixed binary body")
		spec.Headers = []Header{
			{Name: "Content-Type", Value: "application/octet-stream"},
			{Name: "X-Parity", Value: "first"},
			{Name: "X-Parity", Value: "second"},
			{Name: "Cookie", Value: "first=1; second=two"},
			{Name: "Accept-Language", Value: "en-GB,en;q=0.7"},
		}
	}
	return spec
}

func runParityGo(t *testing.T, profile Profile, spec parityRequestSpec) ([]byte, error) {
	t.Helper()
	client, err := NewClient(profile)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	client.CurlTransport.InsecureSkipVerify = true
	client.CurlTransport.Timeout = 10 * time.Second
	client.CurlTransport.CurlOptions = spec.Options
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var body io.Reader
	if spec.Body != nil {
		body = bytes.NewReader(spec.Body)
	}
	request, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, body)
	if err != nil {
		return nil, err
	}
	if len(spec.Headers) > 0 {
		request = WithOrderedHeaders(request, spec.Headers)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("capture server returned %s (%s)", response.Status, response.Header.Get("Content-Type"))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return data, err
}

func assertNativeParity(t *testing.T, executable string, profile Profile, spec parityRequestSpec) {
	t.Helper()
	goJSON, err := runParityGo(t, profile, spec)
	if err != nil {
		t.Fatalf("Go client request: %v", err)
	}
	nativeJSON, err := runParityCLI(t, executable, profile, spec)
	if err != nil {
		t.Fatalf("native curl request: %v", err)
	}
	var got, want parityCapture
	if err := json.Unmarshal(goJSON, &got); err != nil {
		t.Fatalf("Go capture JSON: %v", err)
	}
	if err := json.Unmarshal(nativeJSON, &want); err != nil {
		t.Fatalf("native capture JSON: %v", err)
	}
	gotCanonical, err := canonicalParityCapture(profile, got)
	if err != nil {
		t.Fatalf("canonicalize Go capture: %v", err)
	}
	wantCanonical, err := canonicalParityCapture(profile, want)
	if err != nil {
		t.Fatalf("canonicalize native capture: %v", err)
	}
	gotJSON, _ := json.MarshalIndent(gotCanonical, "", "  ")
	wantJSON, _ := json.MarshalIndent(wantCanonical, "", "  ")
	if directory := os.Getenv("CURL_GO_PARITY_DIR"); directory != "" {
		name := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(t.Name())
		directory = filepath.Join(directory, name)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"go.raw.json": goJSON, "native.raw.json": nativeJSON, "go.normalized.json": gotJSON, "native.normalized.json": wantJSON} {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("Go/native wire parameters differ:\n%s", parityJSONDiff(gotJSON, wantJSON))
	}
}
