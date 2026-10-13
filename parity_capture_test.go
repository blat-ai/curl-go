package curlgo

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

type parityCapture struct {
	TLS  *parityTLSCapture `json:"tls"`
	HTTP parityHTTPCapture `json:"http"`
	QUIC *parityQUICCapture `json:"quic,omitempty"`
}

type parityHTTPCapture struct {
	Protocol string              `json:"protocol"`
	Method   string              `json:"method"`
	Target   string              `json:"target"`
	Headers  []parityHeader      `json:"headers"`
	Trailers []parityHeader      `json:"trailers"`
	Body     []byte              `json:"body"`
	HTTP1    *parityHTTP1Capture `json:"http1"`
	HTTP2    *parityHTTP2Capture `json:"http2"`
	HTTP3    *parityHTTP3Capture `json:"http3,omitempty"`
}

type parityHeader struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
}

type parityHTTP1Capture struct {
	RawRequest []byte `json:"raw_request"`
}

type parityHTTP2Capture struct {
	Preface     []byte             `json:"preface"`
	Frames      []parityHTTP2Frame `json:"frames"`
	HeaderBlock []byte             `json:"header_block"`
}

type parityHTTP2Frame struct {
	Type            uint8                `json:"type"`
	Flags           uint8                `json:"flags"`
	StreamID        uint32               `json:"stream_id"`
	Length          uint32               `json:"length"`
	Payload         []byte               `json:"payload"`
	Settings        []parityHTTP2Setting `json:"settings"`
	WindowIncrement *uint32              `json:"window_increment"`
	Priority        *parityHTTP2Priority `json:"priority"`
	Padding         []byte               `json:"padding"`
	HeaderFragment  []byte               `json:"header_fragment"`
	Data            []byte               `json:"data"`
}

type parityHTTP2Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

type parityHTTP2Priority struct {
	Exclusive  bool   `json:"exclusive"`
	Dependency uint32 `json:"dependency"`
	Weight     uint16 `json:"weight"`
}

type parityTCPServer struct {
	URL      string
	listener net.Listener
	mode     string
	cert     tls.Certificate
	errors   chan error
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
}

func startParityTCPServer(t *testing.T, mode string) *parityTCPServer {
	t.Helper()
	switch mode {
	case "http1", "tls-http1", "tls-http2", "tls12-http2":
	default:
		t.Fatalf("unknown parity TCP server mode %q", mode)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &parityTCPServer{listener: listener, mode: mode, cert: profileTestCertificate(t), errors: make(chan error, 32), conns: make(map[net.Conn]struct{})}
	scheme := "https"
	if mode == "http1" {
		scheme = "http"
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server.URL = scheme + "://localhost:" + port + "/parity?probe=1"
	server.wg.Add(1)
	go server.accept()
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func (s *parityTCPServer) Errors() <-chan error { return s.errors }

func (s *parityTCPServer) Close() error {
	s.once.Do(func() {
		s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}

func (s *parityTCPServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.report(err)
			}
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			if err := s.handle(conn); err != nil {
				s.report(err)
			}
		}()
	}
}

func (s *parityTCPServer) report(err error) {
	select {
	case s.errors <- err:
	default:
	}
}

func (s *parityTCPServer) handle(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	capture := parityCapture{}
	if s.mode != "http1" {
		recorded := &profileRecordingConn{Conn: conn}
		config := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
		if s.mode == "tls-http1" {
			config.NextProtos = []string{"http/1.1"}
		}
		if s.mode == "tls12-http2" {
			config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}
		secure := tls.Server(recorded, config)
		if err := secure.Handshake(); err != nil {
			return fmt.Errorf("parity TLS handshake: %w", err)
		}
		recorded.mu.Lock()
		data := append([]byte{}, recorded.data.Bytes()...)
		recorded.mu.Unlock()
		var err error
		capture.TLS, err = captureParityClientHello(data)
		if err != nil {
			return err
		}
		state := secure.ConnectionState()
		capture.TLS.NegotiatedVersion = state.Version
		capture.TLS.NegotiatedCipher = state.CipherSuite
		capture.TLS.NegotiatedProtocol = state.NegotiatedProtocol
		capture.TLS.ServerName = state.ServerName
		capture.TLS.Resumed = state.DidResume
		conn = secure
	}
	if s.mode == "tls-http2" || s.mode == "tls12-http2" {
		return serveParityHTTP2(conn, capture)
	}
	return serveParityHTTP1(conn, capture)
}

func serveParityHTTP1(conn net.Conn, capture parityCapture) error {
	var raw bytes.Buffer
	reader := bufio.NewReader(io.TeeReader(conn, &raw))
	var header bytes.Buffer
	for header.Len() <= 1<<20 {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		header.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if header.Len() > 1<<20 {
		return errors.New("HTTP/1 header exceeds parity test limit")
	}
	request, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(header.Bytes()), reader)))
	if err != nil {
		return err
	}
	if strings.EqualFold(request.Header.Get("Expect"), "100-continue") {
		if _, err := io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return err
		}
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
	request.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("HTTP/1 body exceeds parity test limit")
	}
	capture.HTTP = parityHTTPCapture{Protocol: request.Proto, Method: request.Method, Target: request.RequestURI, Body: body, HTTP1: &parityHTTP1Capture{RawRequest: append([]byte{}, raw.Bytes()...)}}
	lines := strings.Split(header.String(), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("invalid raw HTTP/1 header %q", line)
		}
		capture.HTTP.Headers = append(capture.HTTP.Headers, parityHeader{Name: name, Value: strings.TrimSpace(value)})
	}
	for name, values := range request.Trailer {
		for _, value := range values {
			capture.HTTP.Trailers = append(capture.HTTP.Trailers, parityHeader{Name: name, Value: value})
		}
	}
	response, err := json.Marshal(capture)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(response), response)
	return err
}

func serveParityHTTP2(conn net.Conn, capture parityCapture) error {
	wire := &parityHTTP2Capture{Preface: make([]byte, 24)}
	if _, err := io.ReadFull(conn, wire.Preface); err != nil {
		return err
	}
	if string(wire.Preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return fmt.Errorf("invalid HTTP/2 preface %q", wire.Preface)
	}
	// Keep the response peer's SETTINGS fixed for both clients.
	if err := writeProfileHTTP2Frame(conn, 4, 0, 0, nil); err != nil {
		return err
	}
	capture.HTTP = parityHTTPCapture{Protocol: "HTTP/2.0", HTTP2: wire, Body: []byte{}}
	var streamID uint32
	var block []byte
	var headersDone, streamEnded bool
	decoder := hpack.NewDecoder(65536, func(field hpack.HeaderField) {
		entry := parityHeader{Name: field.Name, Value: field.Value, Sensitive: field.Sensitive}
		if headersDone {
			capture.HTTP.Trailers = append(capture.HTTP.Trailers, entry)
			return
		}
		capture.HTTP.Headers = append(capture.HTTP.Headers, entry)
		switch field.Name {
		case ":method":
			capture.HTTP.Method = field.Value
		case ":path":
			capture.HTTP.Target = field.Value
		}
	})
	for count := 0; count < 256; count++ {
		frame, err := readParityHTTP2Frame(conn)
		if err != nil {
			return err
		}
		wire.Frames = append(wire.Frames, frame)
		switch frame.Type {
		case 4:
			if frame.Flags&1 == 0 {
				if err := writeProfileHTTP2Frame(conn, 4, 1, 0, nil); err != nil {
					return err
				}
			}
		case 1, 9:
			if streamID == 0 {
				streamID = frame.StreamID
			}
			if frame.StreamID != streamID {
				return errors.New("multiple request streams in parity exchange")
			}
			block = append(block, frame.HeaderFragment...)
			if frame.Flags&1 != 0 && frame.Type == 1 {
				streamEnded = true
			}
			if frame.Flags&4 != 0 {
				if !headersDone {
					wire.HeaderBlock = append([]byte{}, block...)
				}
				if _, err := decoder.Write(block); err != nil {
					return err
				}
				if err := decoder.Close(); err != nil {
					return err
				}
				block = nil
				headersDone = true
			}
		case 0:
			if frame.StreamID != streamID || !headersDone {
				return errors.New("DATA on unexpected parity request stream")
			}
			capture.HTTP.Body = append(capture.HTTP.Body, frame.Data...)
			if len(capture.HTTP.Body) > 1<<20 {
				return errors.New("HTTP/2 body exceeds parity test limit")
			}
			if frame.Flags&1 != 0 {
				streamEnded = true
			}
		case 3, 7:
			return fmt.Errorf("client sent terminating HTTP/2 frame type %d", frame.Type)
		}
		if headersDone && streamEnded && len(block) == 0 {
			response, err := json.Marshal(capture)
			if err != nil {
				return err
			}
			var encoded bytes.Buffer
			encoder := hpack.NewEncoder(&encoded)
			for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/json"}, {Name: "content-length", Value: strconv.Itoa(len(response))}} {
				if err := encoder.WriteField(field); err != nil {
					return err
				}
			}
			if err := writeProfileHTTP2Frame(conn, 1, 4, streamID, encoded.Bytes()); err != nil {
				return err
			}
			for len(response) > 16384 {
				if err := writeProfileHTTP2Frame(conn, 0, 0, streamID, response[:16384]); err != nil {
					return err
				}
				response = response[16384:]
			}
			return writeProfileHTTP2Frame(conn, 0, 1, streamID, response)
		}
	}
	return errors.New("HTTP/2 request did not finish within parity frame limit")
}

func readParityHTTP2Frame(conn net.Conn) (parityHTTP2Frame, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return parityHTTP2Frame{}, err
	}
	length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	frame := parityHTTP2Frame{Length: length, Type: header[3], Flags: header[4], StreamID: binary.BigEndian.Uint32(header[5:]) & 0x7fffffff, Payload: make([]byte, length)}
	if length > 1<<20 {
		return frame, errors.New("HTTP/2 frame exceeds parity test limit")
	}
	if _, err := io.ReadFull(conn, frame.Payload); err != nil {
		return frame, err
	}
	payload := frame.Payload
	if (frame.Type == 0 || frame.Type == 1) && frame.Flags&8 != 0 {
		if len(payload) == 0 || int(payload[0])+1 > len(payload) {
			return frame, errors.New("invalid HTTP/2 padding")
		}
		padding := int(payload[0])
		frame.Padding = append([]byte{}, payload[len(payload)-padding:]...)
		payload = payload[1 : len(payload)-padding]
	}
	parsePriority := func(data []byte) (*parityHTTP2Priority, error) {
		if len(data) < 5 {
			return nil, errors.New("truncated HTTP/2 priority")
		}
		dependency := binary.BigEndian.Uint32(data[:4])
		return &parityHTTP2Priority{Exclusive: dependency&0x80000000 != 0, Dependency: dependency & 0x7fffffff, Weight: uint16(data[4]) + 1}, nil
	}
	switch frame.Type {
	case 0:
		frame.Data = append([]byte{}, payload...)
	case 1:
		if frame.Flags&32 != 0 {
			priority, err := parsePriority(payload)
			if err != nil {
				return frame, err
			}
			frame.Priority = priority
			payload = payload[5:]
		}
		frame.HeaderFragment = append([]byte{}, payload...)
	case 9:
		frame.HeaderFragment = append([]byte{}, payload...)
	case 2:
		priority, err := parsePriority(payload)
		if err != nil {
			return frame, err
		}
		frame.Priority = priority
	case 4:
		if frame.Flags&1 != 0 && len(payload) != 0 {
			return frame, errors.New("HTTP/2 SETTINGS ACK has payload")
		}
		if len(payload)%6 != 0 {
			return frame, errors.New("invalid HTTP/2 SETTINGS payload")
		}
		for len(payload) > 0 {
			frame.Settings = append(frame.Settings, parityHTTP2Setting{ID: binary.BigEndian.Uint16(payload[:2]), Value: binary.BigEndian.Uint32(payload[2:6])})
			payload = payload[6:]
		}
	case 8:
		if len(payload) != 4 {
			return frame, errors.New("invalid HTTP/2 WINDOW_UPDATE payload")
		}
		value := binary.BigEndian.Uint32(payload) & 0x7fffffff
		frame.WindowIncrement = &value
	}
	return frame, nil
}
