package curlgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

// Every profile makes a real HTTP/3 request when explicitly selected. Older
// Firefox and Tor targets have an upstream TCP-only extension allowlist, so
// those four targets additionally need an explicitly custom QUIC allowlist.
// Only Chrome145/146/150 and Firefox147 supply browser-specific native HTTP/3
// fingerprints. Other successful targets use native generic HTTP/3 behavior.
func TestAllProfilesHTTP3(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	requests := make(chan *http.Request, len(Profiles()))
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{profileTestCertificate(t)}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- r
			_, _ = io.WriteString(w, "http3-ok")
		}),
	}
	defer server.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(packetConn) }()
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			c, err := NewCurl()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Impersonate(string(profile), true); err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			for _, option := range []fingerprintOption{
				{OptURL, "https://localhost:" + port + "/http3"}, {OptWriteData, &body},
				{OptHTTPVersion, HTTPVersion3Only}, {OptProxy, ""}, {OptNoProxy, "*"},
				{OptTimeoutMS, 10000}, {OptSSLVerifyPeer, false}, {OptSSLVerifyHost, 0},
			} {
				if err := c.SetOpt(option.option, option.value); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if profile == Firefox133 || profile == Firefox135 || profile == Firefox144 || profile == Tor145 {
				// Their native TLS_EXTENSION_ORDER excludes QUIC transport
				// parameters (57), and they lack HTTP3_TLS_EXTENSION_ORDER.
				// Confirm the limitation before explicitly selecting custom H3.
				err := c.Perform(ctx)
				var curlErr *CurlError
				if !errors.As(err, &curlErr) || curlErr.Code != ErrCodeCouldntConnect {
					t.Fatalf("native legacy HTTP/3 limitation returned %v, want CURL_COULDNT_CONNECT", err)
				}
				order := "28-51-27-13-34-10-45-16-65281-23-5-0-43-57-65037"
				if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{HTTP3TLSExtensionOrder: &order}}); err != nil {
					t.Fatal(err)
				}
				t.Log("verified native HTTP/3 limitation; request uses an explicitly custom QUIC extension order")
			}
			if err := c.Perform(ctx); err != nil {
				t.Fatal(err)
			}
			if body.String() != "http3-ok" {
				t.Fatalf("HTTP/3 body=%q", body.String())
			}
			if version, err := c.GetInfo(InfoHTTPVersion); err != nil || version != int64(HTTPVersion3) {
				t.Fatalf("HTTP version=%v, %v; want HTTP/3", version, err)
			}
			select {
			case r := <-requests:
				if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h3" {
					t.Fatalf("server observed protocol=%s TLS=%#v", r.Proto, r.TLS)
				}
			case err := <-serveErr:
				t.Fatalf("HTTP/3 server exited: %v", err)
			case <-ctx.Done():
				t.Fatal("HTTP/3 request was not observed")
			}
		})
	}
}

func TestNativeHTTP3BrowserSettings(t *testing.T) {
	for _, profile := range []Profile{Chrome145, Chrome146, Chrome150, Firefox147} {
		t.Run(string(profile), func(t *testing.T) {
			wire := performFingerprintHTTP3Exchange(t, profile, Fingerprint{})
			var settings []string
			for _, setting := range wire.Settings {
				// Chrome's GREASE setting is a randomly selected 31*N+33.
				if setting.ID >= 33 && (setting.ID-33)%31 == 0 {
					continue
				}
				settings = append(settings, fmt.Sprintf("%d:%d", setting.ID, setting.Value))
			}
			wantSettings := "1:65536;6:262144;7:100;51:1"
			wantOrder := "masp"
			if profile == Firefox147 {
				wantSettings = "1:65536;7:20;727725890:0;16765559:1;51:1;8:1"
				wantOrder = "msap"
			}
			if got := strings.Join(settings, ";"); got != wantSettings {
				t.Errorf("HTTP/3 SETTINGS=%q, want %q", got, wantSettings)
			}
			if wire.PseudoHeaders != wantOrder {
				t.Errorf("HTTP/3 pseudo-header order=%q, want %q", wire.PseudoHeaders, wantOrder)
			}
			want := profileExpectations(t)[string(profile)]
			assertProfileHeaders(t, wire.Headers, want.Headers)
			var ciphers []uint16
			for _, cipher := range want.Ciphers {
				if cipher >= 0x1301 && cipher <= 0x1303 {
					ciphers = append(ciphers, cipher)
				}
			}
			if !reflect.DeepEqual(wire.Hello.CipherSuites, ciphers) {
				t.Errorf("HTTP/3 TLS cipher order=%v, want %v", wire.Hello.CipherSuites, ciphers)
			}
			var groups []uint16
			for _, group := range wire.Hello.SupportedCurves {
				groups = append(groups, uint16(group))
			}
			if !reflect.DeepEqual(groups, want.Groups) {
				t.Errorf("HTTP/3 TLS group order=%v, want %v", groups, want.Groups)
			}
			wantSigs := append([]uint16(nil), want.SignatureAlgorithms...)
			if profile != Firefox147 {
				// All three Chrome targets explicitly configure this H3 list;
				// Chrome150's TCP list additionally includes ML-DSA.
				wantSigs = []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
			}
			var signatures []uint16
			for _, signature := range wire.Hello.SignatureSchemes {
				signatures = append(signatures, uint16(signature))
			}
			if !reflect.DeepEqual(signatures, wantSigs) {
				t.Errorf("HTTP/3 TLS signature order=%v, want %v", signatures, wantSigs)
			}
			if profile == Firefox147 {
				if wire.Transport.InitialMaxData != 25165824 || wire.Transport.InitialMaxStreamDataBidiLocal != 12582912 || wire.Transport.InitialMaxStreamsUni != 100 || wire.Transport.InitialSourceConnectionID.Len() != 3 {
					t.Errorf("Firefox147 QUIC profile differs: %#v", wire.Transport)
				}
			} else if wire.Transport.InitialMaxData != 15728640 || wire.Transport.InitialMaxStreamDataBidiLocal != 6291456 || wire.Transport.InitialMaxStreamsUni != 103 || wire.Transport.InitialSourceConnectionID.Len() != 0 {
				t.Errorf("%s QUIC profile differs: %#v", profile, wire.Transport)
			}
		})
	}
}

func TestNativeCustomizedPerk(t *testing.T) {
	// A complete numeric transport-parameter set avoids relying on inherited
	// flow-control values. Explicitly retaining the automatically generated
	// connection ID is supported through the extended native grammar.
	parameters := "1:10000;3:1472;4:1048576;5:262144;6:262144;7:262144;8:10;9:10;14:2;15:AUTO"
	wire := performFingerprintHTTP3Exchange(t, Chrome150, Fingerprint{
		Perk: "1:4096;6:123456;7:20|m,s,p,a|" + parameters,
	})
	wantSettings := []http3Setting{{1, 4096}, {6, 123456}, {7, 20}}
	if !reflect.DeepEqual(wire.Settings, wantSettings) {
		t.Errorf("HTTP/3 SETTINGS=%v, want %v", wire.Settings, wantSettings)
	}
	if wire.PseudoHeaders != "mspa" {
		t.Errorf("HTTP/3 pseudo-header order=%q, want mspa", wire.PseudoHeaders)
	}
	if wire.Transport.MaxUDPPayloadSize != 1472 || wire.Transport.InitialMaxData != 1048576 || wire.Transport.InitialMaxStreamsBidi != 10 {
		t.Errorf("custom QUIC transport parameters not applied: %#v", wire.Transport)
	}
}

type http3Setting struct {
	ID    uint64
	Value uint64
}

type fingerprintHTTP3Wire struct {
	Settings      []http3Setting
	PseudoHeaders string
	Headers       []string
	Transport     qlog.ParametersSet
	Hello         tls.ClientHelloInfo
	Err           error
}

// A small standards-compliant QUIC peer captures application frames before
// decoding headers. A regular HTTP server does not expose SETTINGS frame order.
func performFingerprintHTTP3Exchange(t *testing.T, profile Profile, fingerprint Fingerprint) fingerprintHTTP3Wire {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	transport := make(chan qlog.ParametersSet, 1)
	hello := make(chan tls.ClientHelloInfo, 1)
	listener, err := quic.Listen(packetConn, &tls.Config{
		Certificates: []tls.Certificate{profileTestCertificate(t)}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			captured := *info
			captured.CipherSuites = append([]uint16(nil), info.CipherSuites...)
			captured.SupportedCurves = append([]tls.CurveID(nil), info.SupportedCurves...)
			captured.SignatureSchemes = append([]tls.SignatureScheme(nil), info.SignatureSchemes...)
			select {
			case hello <- captured:
			default:
			}
			return nil, nil
		},
	}, &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &fingerprintQUICTrace{parameters: transport}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connections := make(chan *quic.Conn, 1)
	defer func() {
		select {
		case conn := <-connections:
			_ = conn.CloseWithError(0, "test complete")
		default:
		}
	}()
	done := make(chan fingerprintHTTP3Wire, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			done <- fingerprintHTTP3Wire{Err: err}
			return
		}
		connections <- conn
		control, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			done <- fingerprintHTTP3Wire{Err: err}
			return
		}
		// Control stream type 0, SETTINGS type 4, empty payload. Advertising
		// a zero QPACK dynamic capacity makes header decoding deterministic.
		if _, err := control.Write([]byte{0, 4, 0}); err != nil {
			done <- fingerprintHTTP3Wire{Err: err}
			return
		}
		settings := make(chan fingerprintHTTP3Wire, 1)
		go func() {
			for {
				stream, err := conn.AcceptUniStream(ctx)
				if err != nil {
					settings <- fingerprintHTTP3Wire{Err: err}
					return
				}
				reader := bufio.NewReader(stream)
				streamType, err := quicvarint.Read(reader)
				if err != nil {
					settings <- fingerprintHTTP3Wire{Err: err}
					return
				}
				if streamType != 0 {
					go func() { _, _ = io.Copy(io.Discard, reader) }()
					continue
				}
				frameType, payload, err := readFingerprintHTTP3Frame(reader)
				if err != nil || frameType != 4 {
					settings <- fingerprintHTTP3Wire{Err: fmt.Errorf("HTTP/3 control SETTINGS: type=%d, %v", frameType, err)}
					return
				}
				var captured []http3Setting
				entries := bytes.NewReader(payload)
				for entries.Len() != 0 {
					id, err := quicvarint.Read(entries)
					if err != nil {
						settings <- fingerprintHTTP3Wire{Err: err}
						return
					}
					value, err := quicvarint.Read(entries)
					if err != nil {
						settings <- fingerprintHTTP3Wire{Err: err}
						return
					}
					captured = append(captured, http3Setting{id, value})
				}
				settings <- fingerprintHTTP3Wire{Settings: captured}
				return
			}
		}()
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- fingerprintHTTP3Wire{Err: err}
			return
		}
		frameType, payload, err := readFingerprintHTTP3Frame(bufio.NewReader(stream))
		if err != nil || frameType != 1 {
			done <- fingerprintHTTP3Wire{Err: fmt.Errorf("HTTP/3 request HEADERS: type=%d, %v", frameType, err)}
			return
		}
		var wire fingerprintHTTP3Wire
		decode := qpack.NewDecoder().Decode(payload)
		for {
			field, err := decode()
			if err == io.EOF {
				break
			}
			if err != nil {
				done <- fingerprintHTTP3Wire{Err: err}
				return
			}
			if strings.HasPrefix(field.Name, ":") {
				wire.PseudoHeaders += string(field.Name[1])
			} else {
				wire.Headers = append(wire.Headers, field.Name+": "+field.Value)
			}
		}
		select {
		case captured := <-settings:
			wire.Settings, wire.Err = captured.Settings, captured.Err
		case <-ctx.Done():
			wire.Err = ctx.Err()
		}
		select {
		case wire.Transport = <-transport:
		case <-ctx.Done():
			wire.Err = ctx.Err()
		}
		select {
		case wire.Hello = <-hello:
		case <-ctx.Done():
			wire.Err = ctx.Err()
		}
		var encoded bytes.Buffer
		encoder := qpack.NewEncoder(&encoded)
		_ = encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
		_ = encoder.WriteField(qpack.HeaderField{Name: "content-length", Value: "2"})
		response := quicvarint.Append(nil, 1)
		response = quicvarint.Append(response, uint64(encoded.Len()))
		response = append(response, encoded.Bytes()...)
		response = append(response, 0, 2, 'o', 'k') // DATA frame.
		if _, err := stream.Write(response); wire.Err == nil {
			wire.Err = err
		}
		if err := stream.Close(); wire.Err == nil {
			wire.Err = err
		}
		done <- wire
	}()
	c, err := NewCurl()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Impersonate(string(profile), true); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFingerprint(c, fingerprint); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	var body bytes.Buffer
	for _, option := range []fingerprintOption{
		{OptURL, "https://localhost:" + port + "/fingerprint"}, {OptWriteData, &body},
		{OptHTTPVersion, HTTPVersion3Only}, {OptProxy, ""}, {OptNoProxy, "*"},
		{OptTimeoutMS, 10000}, {OptSSLVerifyPeer, false}, {OptSSLVerifyHost, 0},
	} {
		if err := c.SetOpt(option.option, option.value); err != nil {
			t.Fatal(err)
		}
	}
	performed := make(chan error, 1)
	go func() { performed <- c.Perform(ctx) }()
	var wire fingerprintHTTP3Wire
	select {
	case wire = <-done:
		if wire.Err != nil {
			cancel()
			<-performed
			t.Fatal(wire.Err)
		}
		if err := <-performed; err != nil {
			t.Fatal(err)
		}
	case err := <-performed:
		if err != nil {
			t.Fatal(err)
		}
		select {
		case wire = <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if body.String() != "ok" {
		t.Fatalf("response body=%q", body.String())
	}
	if wire.Err != nil {
		t.Fatal(wire.Err)
	}
	return wire
}

func readFingerprintHTTP3Frame(reader *bufio.Reader) (uint64, []byte, error) {
	frameType, err := quicvarint.Read(reader)
	if err != nil {
		return 0, nil, err
	}
	length, err := quicvarint.Read(reader)
	if err != nil || length > 1048576 {
		return 0, nil, fmt.Errorf("invalid HTTP/3 frame length %d: %v", length, err)
	}
	data := make([]byte, int(length))
	_, err = io.ReadFull(reader, data)
	return frameType, data, err
}

type fingerprintQUICTrace struct {
	parameters chan qlog.ParametersSet
}

func (t *fingerprintQUICTrace) AddProducer() qlogwriter.Recorder { return t }
func (*fingerprintQUICTrace) SupportsSchemas(string) bool        { return true }
func (*fingerprintQUICTrace) Close() error                       { return nil }
func (t *fingerprintQUICTrace) RecordEvent(event qlogwriter.Event) {
	parameters, ok := event.(qlog.ParametersSet)
	if !ok || parameters.Initiator != qlog.InitiatorRemote {
		return
	}
	select {
	case t.parameters <- parameters:
	default:
	}
}
