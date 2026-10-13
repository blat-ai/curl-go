package curlgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

// Initial packets are encrypted with public, version-specific keys. Observing
// those packets before quic-go consumes them lets this test preserve the actual
// TLS extension bytes and QUIC transport-parameter order. ClientHelloInfo and a
// qlog transport-parameter event both discard information needed for parity.
type parityQUICPacketConn struct {
	net.PacketConn
	mu    sync.Mutex
	peers map[string]*parityQUICInitialCapture
}

type parityQUICInitialCapture struct {
	Packets     []parityQUICInitialPacket
	Hello       []byte
	Err         error
	crypto      map[uint64]byte
	initialDCID []byte
	largest     uint64
	seen        bool
}

type parityQUICInitialPacket struct {
	Version              uint32 `json:"version"`
	DestinationCIDLength int    `json:"destination_cid_length"`
	SourceCIDLength      int    `json:"source_cid_length"`
	TokenLength          uint64 `json:"token_length"`
	PacketNumber         uint64 `json:"packet_number"`
	PacketNumberLength   int    `json:"packet_number_length"`
	PacketLength         int    `json:"packet_length"`
	// Raw is evidence, not a stable fingerprint: encryption incorporates fresh
	// connection IDs, keys, randoms, and packet numbers for every connection.
	Raw []byte `json:"raw"`
}

func (p *parityQUICPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err == nil {
		p.mu.Lock()
		capture := p.peers[addr.String()]
		if capture == nil {
			capture = &parityQUICInitialCapture{crypto: make(map[uint64]byte)}
			p.peers[addr.String()] = capture
		}
		if capture.Err == nil {
			capture.Err = capture.observe(b[:n])
		}
		p.mu.Unlock()
	}
	return n, addr, err
}

func (p *parityQUICPacketConn) snapshot(addr net.Addr) (parityQUICInitialCapture, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	capture := p.peers[addr.String()]
	if capture == nil {
		return parityQUICInitialCapture{}, errors.New("missing QUIC Initial capture")
	}
	copy := *capture
	copy.Packets = append([]parityQUICInitialPacket(nil), capture.Packets...)
	copy.Hello = append([]byte(nil), capture.Hello...)
	if capture.Err != nil {
		return copy, capture.Err
	}
	if len(copy.Hello) == 0 {
		return copy, errors.New("incomplete QUIC ClientHello")
	}
	return copy, nil
}

func (c *parityQUICInitialCapture) observe(datagram []byte) error {
	for len(datagram) >= 7 && datagram[0]&0x80 != 0 {
		version := binary.BigEndian.Uint32(datagram[1:5])
		initialType := byte(0)
		salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
		label := "quic"
		if version == 0x6b3343cf {
			initialType = 1
			salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
			label = "quicv2"
		} else if version != 1 {
			return fmt.Errorf("unsupported QUIC version %08x", version)
		}
		// Initial is the first packet in a client's coalesced datagram. Other
		// encryption levels contain no ClientHello and remain quic-go's job.
		if (datagram[0]>>4)&3 != initialType {
			return nil
		}
		reader := bytes.NewReader(datagram[5:])
		dcidLength, err := reader.ReadByte()
		if err != nil || dcidLength > 20 {
			return errors.New("invalid QUIC destination connection ID")
		}
		dcid := make([]byte, int(dcidLength))
		if _, err = io.ReadFull(reader, dcid); err != nil {
			return err
		}
		scidLength, err := reader.ReadByte()
		if err != nil || scidLength > 20 {
			return errors.New("invalid QUIC source connection ID")
		}
		if _, err = reader.Seek(int64(scidLength), io.SeekCurrent); err != nil {
			return err
		}
		tokenLength, err := quicvarint.Read(reader)
		if err != nil || tokenLength > uint64(reader.Len()) {
			return errors.New("invalid QUIC Initial token")
		}
		if _, err = reader.Seek(int64(tokenLength), io.SeekCurrent); err != nil {
			return err
		}
		payloadLength, err := quicvarint.Read(reader)
		if err != nil || payloadLength > uint64(reader.Len()) {
			return errors.New("invalid QUIC Initial length")
		}
		pnOffset := len(datagram) - reader.Len()
		packetLength := pnOffset + int(payloadLength)
		if pnOffset+4+aes.BlockSize > packetLength {
			return errors.New("truncated QUIC Initial header-protection sample")
		}
		packet := append([]byte(nil), datagram[:packetLength]...)
		if c.initialDCID == nil {
			c.initialDCID = append([]byte(nil), dcid...)
		}
		// After the server's first response, the destination CID changes but
		// Initial protection still derives from the first client packet's CID.
		initialSecret := hkdf.Extract(sha256.New, c.initialDCID, salt)
		clientSecret := parityQUICExpandLabel(initialSecret, "client in", 32)
		key := parityQUICExpandLabel(clientSecret, label+" key", 16)
		iv := parityQUICExpandLabel(clientSecret, label+" iv", 12)
		hp := parityQUICExpandLabel(clientSecret, label+" hp", 16)
		protection, err := aes.NewCipher(hp)
		if err != nil {
			return err
		}
		mask := make([]byte, aes.BlockSize)
		protection.Encrypt(mask, packet[pnOffset+4:pnOffset+4+aes.BlockSize])
		packet[0] ^= mask[0] & 0x0f
		pnLength := int(packet[0]&3) + 1
		var truncated uint64
		for i := 0; i < pnLength; i++ {
			packet[pnOffset+i] ^= mask[i+1]
			truncated = truncated<<8 | uint64(packet[pnOffset+i])
		}
		packetNumber := truncated
		if c.seen {
			window := uint64(1) << (8 * pnLength)
			expected := c.largest + 1
			packetNumber = (expected & ^(window - 1)) | truncated
			if packetNumber+window/2 <= expected && packetNumber < (1<<62)-window {
				packetNumber += window
			} else if packetNumber > expected+window/2 && packetNumber >= window {
				packetNumber -= window
			}
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := append([]byte(nil), iv...)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
		}
		plain, err := aead.Open(nil, nonce, packet[pnOffset+pnLength:], packet[:pnOffset+pnLength])
		if err != nil {
			return fmt.Errorf("decrypt client QUIC Initial: %w", err)
		}
		c.Packets = append(c.Packets, parityQUICInitialPacket{Version: version, DestinationCIDLength: int(dcidLength), SourceCIDLength: int(scidLength), TokenLength: tokenLength, PacketNumber: packetNumber, PacketNumberLength: pnLength, PacketLength: packetLength, Raw: append([]byte(nil), datagram[:packetLength]...)})
		if !c.seen || packetNumber > c.largest {
			c.largest = packetNumber
		}
		c.seen = true
		if err := c.observeFrames(plain); err != nil {
			return err
		}
		datagram = datagram[packetLength:]
	}
	return nil
}

func parityQUICExpandLabel(secret []byte, label string, length int) []byte {
	label = "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(label))}
	info = append(info, label...)
	info = append(info, 0)
	result := make([]byte, length)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), result)
	return result
}

func (c *parityQUICInitialCapture) observeFrames(data []byte) error {
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		typeID, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		switch typeID {
		case 0, 1: // PADDING, PING
		case 2, 3: // ACK, ACK_ECN
			for i := 0; i < 2; i++ { // largest acknowledged, ACK delay
				if _, err := quicvarint.Read(reader); err != nil {
					return err
				}
			}
			ranges, err := quicvarint.Read(reader)
			if err != nil || ranges > 1<<16 {
				return errors.New("invalid QUIC ACK range count")
			}
			fields := 1 + 2*ranges
			if typeID == 3 {
				fields += 3
			}
			for i := uint64(0); i < fields; i++ {
				if _, err := quicvarint.Read(reader); err != nil {
					return err
				}
			}
		case 6: // CRYPTO
			offset, err := quicvarint.Read(reader)
			if err != nil {
				return err
			}
			length, err := quicvarint.Read(reader)
			if err != nil || length > uint64(reader.Len()) || offset+length > 1<<20 {
				return errors.New("invalid QUIC CRYPTO length")
			}
			for i := uint64(0); i < length; i++ {
				value, _ := reader.ReadByte()
				if old, ok := c.crypto[offset+i]; ok && old != value {
					return errors.New("conflicting retransmitted QUIC CRYPTO bytes")
				}
				c.crypto[offset+i] = value
			}
		case 0x1c, 0x1d: // CONNECTION_CLOSE; after handshake failures only.
			return nil
		default:
			return fmt.Errorf("unhandled frame %d in QUIC Initial", typeID)
		}
	}
	if len(c.Hello) == 0 {
		var assembled []byte
		for i := uint64(0); ; i++ {
			value, ok := c.crypto[i]
			if !ok {
				break
			}
			assembled = append(assembled, value)
		}
		if len(assembled) >= 4 {
			if assembled[0] != 1 {
				return fmt.Errorf("QUIC first handshake type=%d, want ClientHello", assembled[0])
			}
			length := int(assembled[1])<<16 | int(assembled[2])<<8 | int(assembled[3])
			if len(assembled) >= length+4 {
				c.Hello = append([]byte(nil), assembled[4:length+4]...)
			}
		}
	}
	return nil
}

type parityQUICCapture struct {
	InitialPackets      []parityQUICInitialPacket `json:"initial_packets"`
	TransportParameters []parityQUICParameter     `json:"transport_parameters"`
}

type parityQUICParameter struct {
	ID                  uint64 `json:"id"`
	Data                []byte `json:"data"`
	IDEncodedLength     int    `json:"id_encoded_length"`
	LengthEncodedLength int    `json:"length_encoded_length"`
}

type parityHTTP3Setting struct {
	ID                 uint64 `json:"id"`
	Value              uint64 `json:"value"`
	IDEncodedLength    int    `json:"id_encoded_length"`
	ValueEncodedLength int    `json:"value_encoded_length"`
}

type parityHTTP3Frame struct {
	Type                uint64 `json:"type"`
	Payload             []byte `json:"payload"`
	TypeEncodedLength   int    `json:"type_encoded_length"`
	LengthEncodedLength int    `json:"length_encoded_length"`
}

type parityHTTP3UniStream struct {
	ID     uint64             `json:"id"`
	Type   uint64             `json:"type"`
	Frames []parityHTTP3Frame `json:"frames,omitempty"`
	Raw    []byte             `json:"raw,omitempty"`
}

type parityHTTP3Capture struct {
	Settings      []parityHTTP3Setting   `json:"settings"`
	UniStreams    []parityHTTP3UniStream `json:"uni_streams"`
	StreamID      uint64                 `json:"request_stream_id"`
	RequestFrames []parityHTTP3Frame     `json:"request_frames"`
	HeaderBlock   []byte                 `json:"header_block"`
	ControlFrames []parityHTTP3Frame     `json:"control_frames"`
}

type parityHTTP3Server struct {
	URL      string
	listener *quic.Listener
	packets  *parityQUICPacketConn
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	conns    []*quic.Conn
	errors   []error
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
}

func startParityHTTP3Server(t *testing.T) *parityHTTP3Server {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packets := &parityQUICPacketConn{PacketConn: udp, peers: make(map[string]*parityQUICInitialCapture)}
	listener, err := quic.Listen(packets, &tls.Config{
		Certificates: []tls.Certificate{profileTestCertificate(t)},
		NextProtos:   []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	server := &parityHTTP3Server{
		URL:      "https://localhost:" + port + "/parity?fixed=1",
		listener: listener, packets: packets, cancel: cancel, done: make(chan struct{}),
	}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer close(server.done)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			server.mu.Lock()
			server.conns = append(server.conns, conn)
			server.mu.Unlock()
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				if err := server.serveConnection(ctx, conn); err != nil && ctx.Err() == nil {
					server.mu.Lock()
					server.errors = append(server.errors, err)
					server.mu.Unlock()
					_ = conn.CloseWithError(0x102, err.Error())
				}
			}()
		}
	}()
	return server
}

func (s *parityHTTP3Server) Close() error {
	s.once.Do(func() {
		s.cancel()
		_ = s.listener.Close()
		s.mu.Lock()
		for _, conn := range s.conns {
			_ = conn.CloseWithError(0, "parity test complete")
		}
		s.mu.Unlock()
		_ = s.packets.Close()
		// Accept has stopped, so no further handler can call WaitGroup.Add.
		<-s.done
		s.wg.Wait()
		s.mu.Lock()
		s.closeErr = errors.Join(s.errors...)
		s.mu.Unlock()
	})
	return s.closeErr
}

// Opening the control stream with zero QPACK dynamic capacity keeps decoding
// complete: the client cannot hide header values behind an unseen dynamic table.
func (s *parityHTTP3Server) serveConnection(parent context.Context, conn *quic.Conn) error {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	control, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := control.Write([]byte{0, 4, 0}); err != nil {
		return err
	}
	var uniMu sync.Mutex
	var uniReaders []*quic.ReceiveStream
	var uniStreams []parityHTTP3UniStream
	var uniErrors []error
	var uniWG sync.WaitGroup
	uniCtx, stopUni := context.WithCancel(ctx)
	defer stopUni()
	settingsReceived := make(chan []parityHTTP3Setting, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			stream, err := conn.AcceptUniStream(uniCtx)
			if err != nil {
				return
			}
			uniMu.Lock()
			uniReaders = append(uniReaders, stream)
			uniMu.Unlock()
			uniWG.Add(1)
			go func() {
				defer uniWG.Done()
				reader := bufio.NewReader(stream)
				typeID, err := quicvarint.Read(reader)
				captured := parityHTTP3UniStream{ID: uint64(stream.StreamID()), Type: typeID}
				if err == nil && typeID == 0 {
					for {
						frame, frameErr := parityReadHTTP3Frame(reader)
						if frameErr != nil {
							err = frameErr
							break
						}
						captured.Frames = append(captured.Frames, frame)
						if frame.Type == 4 {
							settings, parseErr := parityReadHTTP3Settings(frame.Payload)
							if parseErr != nil {
								err = parseErr
								break
							}
							select {
							case settingsReceived <- settings:
							default:
							}
						}
					}
				} else if err == nil {
					captured.Raw, err = io.ReadAll(io.LimitReader(reader, 1<<20))
				}
				uniMu.Lock()
				uniStreams = append(uniStreams, captured)
				var netErr net.Error
				if err != nil && !errors.Is(err, io.EOF) && !(errors.As(err, &netErr) && netErr.Timeout()) {
					uniErrors = append(uniErrors, err)
				}
				uniMu.Unlock()
			}()
		}
	}()
	defer func() {
		stopUni()
		<-acceptDone
		uniMu.Lock()
		for _, reader := range uniReaders {
			// End observation locally. CancelRead sends STOP_SENDING, which
			// cancels HTTP/3's critical control/QPACK streams while the queued
			// JSON response can still be in flight.
			_ = reader.SetReadDeadline(time.Now())
		}
		uniMu.Unlock()
		uniWG.Wait()
	}()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(stream)
	capture := parityCapture{HTTP: parityHTTPCapture{Protocol: "HTTP/3"}}
	h3 := &parityHTTP3Capture{StreamID: uint64(stream.StreamID())}
	headerCount := 0
	for {
		frame, err := parityReadHTTP3Frame(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		h3.RequestFrames = append(h3.RequestFrames, frame)
		payload := frame.Payload
		switch frame.Type {
		case 1:
			h3.HeaderBlock = append(h3.HeaderBlock, payload...)
			decode := qpack.NewDecoder().Decode(payload)
			for {
				field, err := decode()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return err
				}
				if headerCount == 0 {
					parityAppendHTTP3Header(&capture, field.Name, field.Value)
				} else {
					capture.HTTP.Trailers = append(capture.HTTP.Trailers, parityHeader{Name: field.Name, Value: field.Value})
				}
			}
			headerCount++
		case 0:
			capture.HTTP.Body = append(capture.HTTP.Body, payload...)
		}
	}
	if headerCount == 0 || capture.HTTP.Method == "" || capture.HTTP.Target == "" {
		return errors.New("HTTP/3 request missing HEADERS, :method, or :path")
	}
	select {
	case h3.Settings = <-settingsReceived:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Both curl implementations send their initial control/QPACK streams before
	// the request. After its FIN, drain all already-open uni streams to a bounded
	// quiet period. Stream ordering is captured as IDs, not goroutine order.
	quiet := time.NewTimer(30 * time.Millisecond)
	select {
	case <-quiet.C:
	case <-ctx.Done():
		quiet.Stop()
		return ctx.Err()
	}
	stopUni()
	<-acceptDone
	uniMu.Lock()
	for _, reader := range uniReaders {
		_ = reader.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	}
	uniMu.Unlock()
	uniWG.Wait()
	if err := errors.Join(uniErrors...); err != nil {
		return err
	}
	h3.UniStreams = uniStreams
	for _, stream := range uniStreams {
		if stream.Type == 0 {
			h3.ControlFrames = append(h3.ControlFrames, stream.Frames...)
		}
	}
	initial, err := s.packets.snapshot(conn.RemoteAddr())
	if err != nil {
		return err
	}
	if err := paritySetHTTP3TLS(&capture, initial.Hello, conn.ConnectionState().TLS); err != nil {
		return err
	}
	capture.QUIC = &parityQUICCapture{InitialPackets: initial.Packets}
	for _, extension := range capture.TLS.ClientHello.Extensions {
		if extension.ID == 57 {
			capture.QUIC.TransportParameters, err = parityReadQUICParameters(extension.Data)
			if err != nil {
				return err
			}
		}
	}
	capture.HTTP.HTTP3 = h3
	data, err := json.Marshal(capture)
	if err != nil {
		return err
	}
	var headerBlock bytes.Buffer
	encoder := qpack.NewEncoder(&headerBlock)
	for _, field := range []qpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/json"},
		{Name: "content-length", Value: strconv.Itoa(len(data))},
	} {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	response := quicvarint.Append(nil, 1)
	response = quicvarint.Append(response, uint64(headerBlock.Len()))
	response = append(response, headerBlock.Bytes()...)
	response = quicvarint.Append(response, 0)
	response = quicvarint.Append(response, uint64(len(data)))
	response = append(response, data...)
	if _, err := stream.Write(response); err != nil {
		return err
	}
	return stream.Close()
}

func parityReadHTTP3Settings(payload []byte) ([]parityHTTP3Setting, error) {
	var settings []parityHTTP3Setting
	reader := bytes.NewReader(payload)
	for reader.Len() > 0 {
		id, idLength, err := parityReadVarint(reader)
		if err != nil {
			return nil, err
		}
		value, valueLength, err := parityReadVarint(reader)
		if err != nil {
			return nil, err
		}
		settings = append(settings, parityHTTP3Setting{ID: id, Value: value, IDEncodedLength: idLength, ValueEncodedLength: valueLength})
	}
	return settings, nil
}

// Filled using the common capture schema; these functions are deliberately
// shared with the TCP server's parser instead of reducing TLS to JA3 alone.
func parityAppendHTTP3Header(capture *parityCapture, name, value string) {
	capture.HTTP.Headers = append(capture.HTTP.Headers, parityHeader{Name: name, Value: value})
	switch name {
	case ":method":
		capture.HTTP.Method = value
	case ":path":
		capture.HTTP.Target = value
	}
}

func paritySetHTTP3TLS(capture *parityCapture, hello []byte, state tls.ConnectionState) error {
	parsed, err := parseParityClientHello(hello)
	if err != nil {
		return err
	}
	capture.TLS = &parityTLSCapture{
		RawClientHello: hello, ClientHello: parsed,
		NegotiatedVersion: state.Version, NegotiatedCipher: state.CipherSuite,
		NegotiatedProtocol: state.NegotiatedProtocol, ServerName: state.ServerName, Resumed: state.DidResume,
	}
	return nil
}

func parityReadQUICParameters(data []byte) ([]parityQUICParameter, error) {
	reader := bytes.NewReader(data)
	var parameters []parityQUICParameter
	for reader.Len() > 0 {
		id, idLength, err := parityReadVarint(reader)
		if err != nil {
			return nil, err
		}
		length, lengthLength, err := parityReadVarint(reader)
		if err != nil || length > uint64(reader.Len()) {
			return nil, errors.New("invalid QUIC transport parameter length")
		}
		value := make([]byte, int(length))
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		parameters = append(parameters, parityQUICParameter{ID: id, Data: value, IDEncodedLength: idLength, LengthEncodedLength: lengthLength})
	}
	return parameters, nil
}

// A standards-compliant QUIC varint can use a wider representation than its
// value needs. Preserve that width instead of silently reducing two different
// wire encodings to the same numeric parameter.
func parityReadVarint(reader io.ByteReader) (uint64, int, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	width := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < width; i++ {
		part, err := reader.ReadByte()
		if err != nil {
			return 0, width, io.ErrUnexpectedEOF
		}
		value = value<<8 | uint64(part)
	}
	return value, width, nil
}

func parityReadHTTP3Frame(reader *bufio.Reader) (parityHTTP3Frame, error) {
	typeID, typeWidth, err := parityReadVarint(reader)
	if err != nil {
		return parityHTTP3Frame{}, err
	}
	length, lengthWidth, err := parityReadVarint(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return parityHTTP3Frame{}, err
	}
	if length > 1<<20 {
		return parityHTTP3Frame{}, fmt.Errorf("HTTP/3 frame length %d exceeds capture limit", length)
	}
	frame := parityHTTP3Frame{Type: typeID, TypeEncodedLength: typeWidth, LengthEncodedLength: lengthWidth, Payload: make([]byte, int(length))}
	_, err = io.ReadFull(reader, frame.Payload)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return frame, err
}
