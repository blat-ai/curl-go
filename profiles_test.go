package curlgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

type profileSignature struct {
	Headers                 []string `json:"headers"`
	Ciphers                 []uint16 `json:"ciphers"`
	Groups                  []uint16 `json:"groups"`
	SignatureAlgorithms     []uint16 `json:"signature_algorithms"`
	Grease                  bool     `json:"grease"`
	PermuteExtensions       bool     `json:"permute_extensions"`
	ECH                     bool     `json:"ech"`
	ExtensionOrder          []uint16 `json:"extension_order"`
	HTTP3Settings           string   `json:"http3_settings"`
	QUICTransportParameters string   `json:"quic_transport_parameters"`
	QUICCIDLength           string   `json:"quic_cid_length"`
	QUICInitialPacketNumber int      `json:"quic_initial_packet_number"`
	HTTP2Settings           string   `json:"http2_settings"`
	HTTP2WindowUpdate       uint32   `json:"http2_window_update"`
	HTTP2PseudoHeadersOrder string   `json:"http2_pseudo_headers_order"`
}

func profileExpectations(t *testing.T) map[string]profileSignature {
	t.Helper()
	data, err := os.ReadFile("testdata/profile_signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NativeRelease string                      `json:"native_release"`
		Profiles      map[string]profileSignature `json:"profiles"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.NativeRelease != "v2.2.3" {
		t.Fatal("profile fixture is not for the pinned native release")
	}
	return fixture.Profiles
}

// Every public concrete target must perform a real request. No network external
// to localhost is used, and a missing library is an error rather than a skip.
func TestAllProfilesHTTP(t *testing.T) {
	expected := profileExpectations(t)
	if len(expected) != len(Profiles()) {
		t.Fatalf("%d fixtures for %d public profiles", len(expected), len(Profiles()))
	}
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			want, ok := expected[string(profile)]
			if !ok {
				t.Fatal("public profile lacks an upstream fixture")
			}
			wire := performProfileExchange(t, profile, true, false)
			// Curl_add_custom_headers in the pinned native patch suppresses
			// Priority on HTTP/1.x unless the User-Agent identifies Firefox.
			firefox := false
			for _, field := range want.Headers {
				if strings.HasPrefix(strings.ToLower(field), "user-agent:") && strings.Contains(field, "Firefox/") {
					firefox = true
				}
			}
			var expectedHeaders []string
			for _, field := range want.Headers {
				if !firefox && strings.HasPrefix(strings.ToLower(field), "priority:") {
					continue
				}
				expectedHeaders = append(expectedHeaders, field)
			}
			assertProfileHeaders(t, wire.Headers, expectedHeaders)
		})
	}
}

func TestAllProfilesTLSAndHTTP2Fingerprints(t *testing.T) {
	expected := profileExpectations(t)
	certificate := profileTestCertificate(t)
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			wire := performProfileTLSExchange(t, profile, true, certificate)
			assertProfileWireSignature(t, wire, expected[string(profile)])
		})
	}
}

func TestAllProfilesWithoutDefaultHeaders(t *testing.T) {
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			wire := performProfileExchange(t, profile, false, false)
			for _, field := range wire.Headers {
				name, _, _ := strings.Cut(field, ":")
				if strings.EqualFold(name, "user-agent") || strings.EqualFold(name, "sec-ch-ua") || strings.EqualFold(name, "sec-fetch-site") {
					t.Fatalf("default_headers=false still sent browser header %q", field)
				}
			}
		})
	}
}

func TestProfileAliasesPerformCanonicalFingerprint(t *testing.T) {
	expected := profileExpectations(t)
	certificate := profileTestCertificate(t)
	for alias, target := range ProfileAliases() {
		t.Run(string(alias), func(t *testing.T) {
			actual, err := NormalizeProfile(alias)
			if err != nil || actual != target {
				t.Fatalf("NormalizeProfile(%q)=%q, %v; want %q", alias, actual, err, target)
			}
			wire := performProfileTLSExchange(t, alias, true, certificate)
			assertProfileWireSignature(t, wire, expected[string(target)])
		})
	}
}

type profileWire struct {
	Hello         []byte
	Headers       []string
	PseudoHeaders string
	Settings      string
	WindowUpdate  uint32
	ALPN          string
	Err           error
}

func performProfileExchange(t *testing.T, profile Profile, defaultHeaders, secure bool) profileWire {
	t.Helper()
	if secure {
		return performProfileTLSExchange(t, profile, defaultHeaders, profileTestCertificate(t))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan profileWire, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- profileWire{Err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			done <- profileWire{Err: err}
			return
		}
		var wire profileWire
		for name, values := range request.Header {
			for _, value := range values {
				wire.Headers = append(wire.Headers, strings.ToLower(name)+": "+value)
			}
		}
		_, wire.Err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		done <- wire
	}()
	performProfileRequest(t, profile, defaultHeaders, "http://"+listener.Addr().String()+"/profile", false)
	return awaitProfileWire(t, done)
}

func performProfileTLSExchange(t *testing.T, profile Profile, defaultHeaders bool, certificate tls.Certificate) profileWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan profileWire, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- profileWire{Err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		recorded := &profileRecordingConn{Conn: conn}
		tlsConn := tls.Server(recorded, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			done <- profileWire{Err: fmt.Errorf("TLS handshake: %w", err)}
			return
		}
		wire := readProfileHTTP2(tlsConn)
		wire.Hello, err = recorded.clientHello()
		wire.ALPN = tlsConn.ConnectionState().NegotiatedProtocol
		if wire.Err == nil {
			wire.Err = err
		}
		done <- wire
		drainCaptureHTTP2(tlsConn)
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// A DNS hostname ensures the SNI extension is present, as in upstream tests.
	performProfileRequest(t, profile, defaultHeaders, "https://localhost:"+port+"/profile", true)
	return awaitProfileWire(t, done)
}

func awaitProfileWire(t *testing.T, done <-chan profileWire) profileWire {
	t.Helper()
	select {
	case wire := <-done:
		if wire.Err != nil {
			t.Fatal(wire.Err)
		}
		return wire
	case <-time.After(12 * time.Second):
		t.Fatal("local profile capture timed out")
	}
	return profileWire{}
}

func performProfileRequest(t *testing.T, profile Profile, defaultHeaders bool, url string, secure bool) {
	t.Helper()
	c, err := NewCurl()
	if err != nil {
		t.Fatalf("load curl-impersonate: %v; install with go run ./cmd/curl-go-install", err)
	}
	defer c.Close()
	if err := c.Impersonate(string(profile), defaultHeaders); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	for _, option := range []struct {
		key   Option
		value any
	}{
		{OptURL, url}, {OptWriteFunction, &body}, {OptProxy, ""}, {OptNoProxy, "*"},
		{OptTimeoutMS, 10000}, {OptSSLVerifyPeer, false}, {OptSSLVerifyHost, 0},
	} {
		if err := c.SetOpt(option.key, option.value); err != nil {
			t.Fatalf("SetOpt(%v): %v", option.key, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := c.Perform(ctx); err != nil {
		t.Fatal(err)
	}
	if body.String() != "ok" {
		t.Fatalf("response body=%q, want ok", body.String())
	}
	status, err := c.GetInfo(InfoResponseCode)
	if err != nil || status != int64(200) {
		t.Fatalf("HTTP status=%v, %v", status, err)
	}
	if secure {
		version, err := c.GetInfo(InfoHTTPVersion)
		if err != nil || version != int64(HTTPVersionV20) {
			t.Fatalf("HTTP version=%v, %v; expected HTTP/2", version, err)
		}
	}
}

func assertProfileHeaders(t *testing.T, actual, expected []string) {
	t.Helper()
	for _, wanted := range expected {
		name, value, ok := strings.Cut(wanted, ":")
		if !ok {
			t.Fatalf("invalid fixture header %q", wanted)
		}
		want := strings.ToLower(name) + ":" + value
		found := false
		for _, got := range actual {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing browser header %q in %v", want, actual)
		}
	}
}

func assertProfileWireSignature(t *testing.T, wire profileWire, want profileSignature) {
	t.Helper()
	if wire.ALPN != "h2" {
		t.Errorf("negotiated ALPN=%q, want h2", wire.ALPN)
	}
	if wire.Settings != want.HTTP2Settings {
		t.Errorf("HTTP/2 SETTINGS=%q, want %q", wire.Settings, want.HTTP2Settings)
	}
	if wire.WindowUpdate != want.HTTP2WindowUpdate {
		t.Errorf("HTTP/2 WINDOW_UPDATE=%d, want %d", wire.WindowUpdate, want.HTTP2WindowUpdate)
	}
	if wire.PseudoHeaders != want.HTTP2PseudoHeadersOrder {
		t.Errorf("HTTP/2 pseudo headers=%q, want %q", wire.PseudoHeaders, want.HTTP2PseudoHeadersOrder)
	}
	assertProfileHeaders(t, wire.Headers, want.Headers)
	// Header order is part of the HTTP/2 browser signature.
	var expectedHeaders []string
	for _, value := range want.Headers {
		name, value, _ := strings.Cut(value, ":")
		expectedHeaders = append(expectedHeaders, strings.ToLower(name)+":"+value)
	}
	if !reflect.DeepEqual(wire.Headers, expectedHeaders) {
		t.Errorf("HTTP/2 header order or values differ:\n got %v\nwant %v", wire.Headers, expectedHeaders)
	}
	hello, err := parseProfileClientHello(wire.Hello)
	if err != nil {
		t.Fatal(err)
	}
	if hello.LegacyVersion != tls.VersionTLS12 {
		t.Errorf("ClientHello legacy_version=%#x, want TLS 1.2", hello.LegacyVersion)
	}
	if !reflect.DeepEqual(withoutProfileGrease(hello.Ciphers), want.Ciphers) {
		t.Errorf("TLS cipher order=%v, want %v", hello.Ciphers, want.Ciphers)
	}
	grease := len(withoutProfileGrease(hello.Ciphers)) != len(hello.Ciphers)
	if grease != want.Grease {
		t.Errorf("TLS GREASE=%v, want %v", grease, want.Grease)
	}
	if !reflect.DeepEqual(withoutProfileGrease(hello.Groups), want.Groups) {
		t.Errorf("TLS supported groups=%v, want %v", hello.Groups, want.Groups)
	}
	if !reflect.DeepEqual(hello.SignatureAlgorithms, want.SignatureAlgorithms) {
		t.Errorf("TLS signature algorithms=%v, want %v", hello.SignatureAlgorithms, want.SignatureAlgorithms)
	}
	if !reflect.DeepEqual(hello.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("TLS ALPN order=%v, want h2,http/1.1", hello.ALPN)
	}
	if len(want.ExtensionOrder) != 0 && !reflect.DeepEqual(withoutProfileGrease(hello.ExtensionOrder), want.ExtensionOrder) {
		t.Errorf("TLS extension order=%v, want %v", hello.ExtensionOrder, want.ExtensionOrder)
	}
}

func profileTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type profileRecordingConn struct {
	net.Conn
	mu   sync.Mutex
	data bytes.Buffer
}

func (c *profileRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	_, _ = c.data.Write(p[:n])
	c.mu.Unlock()
	return n, err
}
func (c *profileRecordingConn) clientHello() ([]byte, error) {
	c.mu.Lock()
	data := append([]byte(nil), c.data.Bytes()...)
	c.mu.Unlock()
	var hello []byte
	for len(data) >= 5 {
		length := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+length {
			return nil, errors.New("truncated TLS record")
		}
		if data[0] == 22 {
			hello = append(hello, data[5:5+length]...)
		}
		data = data[5+length:]
		if len(hello) >= 4 {
			if hello[0] != 1 {
				return nil, errors.New("first TLS handshake was not ClientHello")
			}
			length := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
			if len(hello) >= length+4 {
				return hello[4 : 4+length], nil
			}
		}
	}
	return nil, errors.New("missing complete TLS ClientHello")
}

type profileClientHello struct {
	LegacyVersion                                        uint16
	Ciphers, Groups, SignatureAlgorithms, ExtensionOrder []uint16
	ALPN                                                 []string
}

type profileCursor struct {
	data []byte
	err  error
}

func (c *profileCursor) take(n int) []byte {
	if c.err != nil || n < 0 || len(c.data) < n {
		c.err = errors.New("truncated ClientHello field")
		return nil
	}
	value := c.data[:n]
	c.data = c.data[n:]
	return value
}
func (c *profileCursor) u8() int {
	b := c.take(1)
	if len(b) == 0 {
		return 0
	}
	return int(b[0])
}
func (c *profileCursor) u16() int {
	b := c.take(2)
	if len(b) == 0 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (c *profileCursor) vec16() []uint16 {
	b := c.take(c.u16())
	var values []uint16
	if len(b)%2 != 0 {
		c.err = errors.New("odd ClientHello uint16 vector length")
		return nil
	}
	for len(b) >= 2 {
		values = append(values, binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	return values
}

func parseProfileClientHello(data []byte) (profileClientHello, error) {
	c := &profileCursor{data: data}
	hello := profileClientHello{LegacyVersion: uint16(c.u16())}
	c.take(32)
	c.take(c.u8())
	hello.Ciphers = c.vec16()
	c.take(c.u8())
	extensions := &profileCursor{data: c.take(c.u16())}
	for len(extensions.data) > 0 && extensions.err == nil {
		typeID := uint16(extensions.u16())
		value := extensions.take(extensions.u16())
		hello.ExtensionOrder = append(hello.ExtensionOrder, typeID)
		field := &profileCursor{data: value}
		switch typeID {
		case 10:
			hello.Groups = field.vec16()
		case 13:
			hello.SignatureAlgorithms = field.vec16()
		case 16:
			list := &profileCursor{data: field.take(field.u16())}
			for len(list.data) > 0 && list.err == nil {
				hello.ALPN = append(hello.ALPN, string(list.take(list.u8())))
			}
			if list.err != nil {
				return hello, list.err
			}
		}
		if field.err != nil {
			return hello, field.err
		}
	}
	if c.err != nil {
		return hello, c.err
	}
	return hello, extensions.err
}

func withoutProfileGrease(values []uint16) []uint16 {
	var filtered []uint16
	for _, value := range values {
		if value&0x0f0f != 0x0a0a || byte(value>>8) != byte(value) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func readProfileHTTP2(conn net.Conn) profileWire {
	var wire profileWire
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		wire.Err = err
		return wire
	}
	if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		wire.Err = fmt.Errorf("invalid HTTP/2 preface %q", preface)
		return wire
	}
	if err := writeProfileHTTP2Frame(conn, 4, 0, 0, nil); err != nil {
		wire.Err = err
		return wire
	}
	var headerBlock []byte
	var streamID uint32
	for frames := 0; frames < 64; frames++ {
		header := make([]byte, 9)
		if _, err := io.ReadFull(conn, header); err != nil {
			wire.Err = err
			return wire
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if length > 1<<20 {
			wire.Err = errors.New("HTTP/2 frame exceeds test limit")
			return wire
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			wire.Err = err
			return wire
		}
		typeID, flags := header[3], header[4]
		id := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		switch typeID {
		case 4:
			if flags&1 != 0 {
				continue
			}
			if len(payload)%6 != 0 {
				wire.Err = errors.New("invalid SETTINGS payload")
				return wire
			}
			var settings []string
			for len(payload) > 0 {
				settings = append(settings, strconv.Itoa(int(binary.BigEndian.Uint16(payload[:2])))+":"+strconv.FormatUint(uint64(binary.BigEndian.Uint32(payload[2:6])), 10))
				payload = payload[6:]
			}
			wire.Settings = strings.Join(settings, ";")
			if err := writeProfileHTTP2Frame(conn, 4, 1, 0, nil); err != nil {
				wire.Err = err
				return wire
			}
		case 8:
			if id == 0 && len(payload) == 4 {
				wire.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		case 1, 9:
			streamID = id
			if typeID == 1 {
				if flags&8 != 0 {
					if len(payload) == 0 || int(payload[0])+1 > len(payload) {
						wire.Err = errors.New("invalid padded HEADERS")
						return wire
					}
					padding := int(payload[0])
					payload = payload[1 : len(payload)-padding]
				}
				if flags&32 != 0 {
					if len(payload) < 5 {
						wire.Err = errors.New("invalid priority HEADERS")
						return wire
					}
					payload = payload[5:]
				}
			}
			headerBlock = append(headerBlock, payload...)
			if flags&4 == 0 {
				continue
			}
			decoder := hpack.NewDecoder(65536, func(field hpack.HeaderField) {
				if strings.HasPrefix(field.Name, ":") {
					switch field.Name {
					case ":method":
						wire.PseudoHeaders += "m"
					case ":authority":
						wire.PseudoHeaders += "a"
					case ":scheme":
						wire.PseudoHeaders += "s"
					case ":path":
						wire.PseudoHeaders += "p"
					}
				} else {
					wire.Headers = append(wire.Headers, field.Name+": "+field.Value)
				}
			})
			if _, err := decoder.Write(headerBlock); err != nil {
				wire.Err = err
				return wire
			}
			if err := decoder.Close(); err != nil {
				wire.Err = err
				return wire
			}
			if err := writeProfileHTTP2Frame(conn, 1, 4, streamID, []byte{0x88}); err != nil {
				wire.Err = err
				return wire
			}
			wire.Err = writeProfileHTTP2Frame(conn, 0, 1, streamID, []byte("ok"))
			return wire
		}
	}
	wire.Err = errors.New("HTTP/2 headers were not received within frame limit")
	return wire
}

func writeProfileHTTP2Frame(conn net.Conn, typeID, flags byte, streamID uint32, payload []byte) error {
	header := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typeID, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[5:], streamID)
	_, err := conn.Write(append(header, payload...))
	return err
}

// Clients can send SETTINGS acknowledgements after the request stream ends.
// Closing a TCP socket with those bytes unread resets it on Windows and can
// discard the response. Publish the capture first, then drain until the client
// closes its handle; the deadline bounds cleanup of a peer that stays open.
func drainCaptureHTTP2(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
}
