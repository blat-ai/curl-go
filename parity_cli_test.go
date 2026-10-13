package curlgo

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// nativeParityCLI deliberately invokes the official, independently built tool;
// reconstructing its options with Curl would test the bindings against themselves.
// Tests never download dependencies or silently skip an absent reference client.
func nativeParityCLI(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("CURL_IMPERSONATE_BIN")
	if executable == "" {
		name := "curl-impersonate"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		executable = filepath.Join(".lib", name)
	}
	absolute, err := filepath.Abs(executable)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(absolute); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("native parity tests require the pinned upstream executable: run go run ./cmd/curl-go-install -with-cli, or set CURL_IMPERSONATE_BIN (%s: %v)", absolute, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, absolute, "-q", "--version")
	cmd.Env = parityCLIEnvironment()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run upstream CLI version: %v\n%s", err, output)
	}
	first, _, _ := strings.Cut(string(output), "\n")
	start := strings.Index(first, "libcurl/")
	if start < 0 || !strings.Contains(first, "curl-impersonate/"+strings.TrimPrefix(NativeVersion, "v")) {
		t.Fatalf("reference CLI is not pinned curl-impersonate %s: %s", NativeVersion, first)
	}
	native, err := Version()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(first[start:]) != strings.TrimSpace(native) {
		t.Fatalf("reference CLI and loaded library identities differ\nCLI: %s\nGo:  %s", first[start:], native)
	}
	t.Logf("reference CLI: %s; loaded native library: %s", absolute, native)
	return absolute
}

func parityCLIEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "CURL_") || key == "HTTP_PROXY" || key == "HTTPS_PROXY" || key == "ALL_PROXY" || key == "NO_PROXY" || key == "SSL_CERT_FILE" || key == "SSL_CERT_DIR" || key == "SSLKEYLOGFILE" {
			continue
		}
		env = append(env, entry)
	}
	return env
}

func runParityCLI(t *testing.T, executable string, profile Profile, spec parityRequestSpec) ([]byte, error) {
	t.Helper()
	canonical, err := NormalizeProfile(profile)
	if err != nil {
		return nil, err
	}
	args := []string{"-q", "--impersonate", string(canonical), "--insecure", "--noproxy", "*", "--proxy", "", "--max-time", "10", "--silent", "--show-error", "--compressed", "--header", "Expect:"}
	switch spec.Mode {
	case "http1", "tls-http1":
		args = append(args, "--http1.1")
	case "http2", "tls-http2":
		args = append(args, "--http2")
	case "tls12-http2":
		args = append(args, "--http2", "--tlsv1.2", "--tls-max", "1.2")
	case "http3":
		args = append(args, "--http3-only")
		// The upstream tool applies its zero-initialized CLI packet-number
		// field after impersonation, overriding the native profile's value.
		// Restore that source-defined preset so both clients use the same
		// configuration; the captured packet number remains compared.
		meta, err := parityProfileMetadata(profile)
		if err != nil {
			return nil, err
		}
		var initialPacketNumber any = meta.QUICInitialPacketNumber
		if override, ok := spec.Options[OptQUICInitialPacketNumber]; ok {
			initialPacketNumber = override
		}
		args = append(args, "--quic-initial-packet-number", fmt.Sprint(initialPacketNumber))
	default:
		return nil, fmt.Errorf("unknown parity request mode %q", spec.Mode)
	}
	for _, header := range spec.Headers {
		args = append(args, "--header", header.Name+": "+header.Value)
	}
	if spec.Body != nil {
		// A regular file gives the tool the same known upload length as Go's
		// bytes.Reader, without introducing a custom Content-Length header.
		bodyPath := filepath.Join(t.TempDir(), "request-body.bin")
		if err := os.WriteFile(bodyPath, spec.Body, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--upload-file", bodyPath)
	}
	args = append(args, "--request", spec.Method)
	args = append(args, spec.ExtraCLI...)
	args = append(args, "--url", spec.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = parityCLIEnvironment()
	cmd.Stdin = bytes.NewReader(spec.Body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("upstream %s %s %s: %w: %s", profile, spec.Mode, spec.Method, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
