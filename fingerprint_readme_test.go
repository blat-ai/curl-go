package curlgo

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Parse the documented literals rather than maintaining a copy that can drift
// away from the snippet users run. A real verified TLS request exercises native
// cipher selection, which ValidateFingerprint alone cannot check.
func TestReadmeCustomFingerprint(t *testing.T) {
	fingerprint := readmeCustomFingerprint(t)
	server := startParityTCPServer(t, "tls-http2")
	client, err := NewClient(Chrome)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	caPath := filepath.Join(t.TempDir(), "capture-server.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.cert.Certificate[0]})
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	client.CurlTransport.CAFile = caPath
	client.CurlTransport.Fingerprint = fingerprint
	client.Timeout = 10 * time.Second
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("README custom fingerprint failed a verified TLS request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("README request returned %s", response.Status)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var capture parityCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.TLS == nil || capture.TLS.NegotiatedVersion != tls.VersionTLS13 || capture.TLS.NegotiatedProtocol != "h2" || capture.HTTP.HTTP2 == nil {
		t.Fatalf("README fingerprint did not negotiate TLS 1.3 and HTTP/2: %+v", capture.TLS)
	}
	hello := capture.TLS.ClientHello
	fields := strings.Split(fingerprint.JA3, ",")
	if got := fingerprintIDs(withoutProfileGrease(hello.Ciphers)); got != fields[1] {
		t.Errorf("README cipher fingerprint=%s, want %s", got, fields[1])
	}
	if got := fingerprintIDs(withoutProfileGrease(hello.SupportedGroups)); got != fields[3] {
		t.Errorf("README supported groups=%s, want %s", got, fields[3])
	}
	var extensions []uint16
	for _, extension := range hello.Extensions {
		if !parityGrease(extension.ID) && extension.ID != 21 {
			extensions = append(extensions, extension.ID)
		}
	}
	if got := fingerprintIDs(extensions); got != fields[2] {
		t.Errorf("README extension fingerprint=%s, want %s", got, fields[2])
	}
	akamai := strings.Split(fingerprint.Akamai, "|")
	var settings []string
	var window uint32
	for _, frame := range capture.HTTP.HTTP2.Frames {
		if frame.Type == 4 && frame.Flags == 0 {
			for _, setting := range frame.Settings {
				settings = append(settings, fmt.Sprintf("%d:%d", setting.ID, setting.Value))
			}
		}
		if frame.Type == 8 && frame.StreamID == 0 && frame.WindowIncrement != nil {
			window = *frame.WindowIncrement
		}
	}
	if got := strings.Join(settings, ";"); got != akamai[0] {
		t.Errorf("README HTTP/2 SETTINGS=%s, want %s", got, akamai[0])
	}
	if got := strconv.FormatUint(uint64(window), 10); got != akamai[1] {
		t.Errorf("README HTTP/2 window=%s, want %s", got, akamai[1])
	}
	var order []string
	for _, header := range capture.HTTP.Headers {
		if strings.HasPrefix(header.Name, ":") {
			order = append(order, header.Name[1:2])
		}
	}
	if got := strings.Join(order, ","); got != akamai[3] {
		t.Errorf("README HTTP/2 pseudoheader order=%s, want %s", got, akamai[3])
	}
}

func TestReadmeCustomFingerprintLineEndings(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := readmeCustomFingerprint(t)
	lf := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, ending := range []struct{ name, text string }{
		{"LF", lf}, {"CRLF", strings.ReplaceAll(lf, "\n", "\r\n")},
	} {
		t.Run(ending.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile("README.md", []byte(ending.text), 0600); err != nil {
				t.Fatal(err)
			}
			if got := readmeCustomFingerprint(t); got != want {
				t.Fatalf("line endings changed documented fingerprint: got %+v, want %+v", got, want)
			}
		})
	}
}

func readmeCustomFingerprint(t *testing.T) Fingerprint {
	t.Helper()
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	_, section, ok := strings.Cut(text, "## Custom fingerprints\n")
	if !ok {
		t.Fatal("README custom fingerprint section is missing")
	}
	_, block, ok := strings.Cut(section, "```go\n")
	if !ok {
		t.Fatal("README custom fingerprint example is missing")
	}
	block, _, ok = strings.Cut(block, "```")
	if !ok {
		t.Fatal("README custom fingerprint example is unterminated")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "README-example.go", "package example\nfunc example() {\n"+block+"\n}", 0)
	if err != nil {
		t.Fatalf("README fingerprint example is invalid Go: %v", err)
	}
	var fingerprint Fingerprint
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		selector, ok := literal.Type.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Fingerprint" {
			return true
		}
		if found {
			t.Fatal("README example contains multiple fingerprints")
		}
		found = true
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				t.Fatal("README example fingerprint requires named fields")
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok {
				t.Fatal("README example fingerprint field is invalid")
			}
			value, ok := field.Value.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				t.Fatalf("README example %s requires a literal string; extend its runtime test if the example changes", key.Name)
			}
			text, err := strconv.Unquote(value.Value)
			if err != nil {
				t.Fatal(err)
			}
			switch key.Name {
			case "JA3":
				fingerprint.JA3 = text
			case "Akamai":
				fingerprint.Akamai = text
			default:
				t.Fatalf("README example field %s is not exercised; extend its runtime test", key.Name)
			}
		}
		return false
	})
	if !found || fingerprint.JA3 == "" || fingerprint.Akamai == "" {
		t.Fatal("README custom fingerprint example must exercise JA3 and Akamai")
	}
	return fingerprint
}
