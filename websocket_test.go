package curlgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type websocketWireFrame struct {
	opcode  byte
	final   bool
	masked  bool
	payload []byte
}

func websocketReadWire(reader *bufio.Reader) (websocketWireFrame, error) {
	var head [2]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return websocketWireFrame{}, err
	}
	length := uint64(head[1] & 127)
	if length == 126 {
		var b [2]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return websocketWireFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(b[:]))
	}
	if length == 127 {
		var b [8]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return websocketWireFrame{}, err
		}
		length = binary.BigEndian.Uint64(b[:])
	}
	if length > 8<<20 {
		return websocketWireFrame{}, fmt.Errorf("oversized fixture frame %d", length)
	}
	var mask [4]byte
	masked := head[1]&128 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return websocketWireFrame{}, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return websocketWireFrame{}, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return websocketWireFrame{opcode: head[0] & 15, final: head[0]&128 != 0, masked: masked, payload: payload}, nil
}

func websocketWriteWire(writer io.Writer, opcode byte, final bool, payload []byte) error {
	first := opcode
	if final {
		first |= 128
	}
	header := []byte{first, 0}
	switch {
	case len(payload) < 126:
		header[1] = byte(len(payload))
	case len(payload) <= 65535:
		header[1] = 126
		header = append(header, byte(len(payload)>>8), byte(len(payload)))
	default:
		header[1] = 127
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
		header = append(header, length[:]...)
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func websocketFixture(t *testing.T, secure bool, fn func(net.Conn, *bufio.Reader, *http.Request)) (*httptest.Server, string) {
	t.Helper()
	var mutex sync.Mutex
	connections := make(map[net.Conn]bool)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		mutex.Lock()
		connections[connection] = true
		mutex.Unlock()
		defer func() { _ = connection.Close(); mutex.Lock(); delete(connections, connection); mutex.Unlock() }()
		key := r.Header.Get("Sec-WebSocket-Key")
		hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(hash[:]))
		if err = buffer.Flush(); err != nil {
			return
		}
		fn(connection, buffer.Reader, r)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(func() {
		mutex.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		mutex.Unlock()
		server.Close()
	})
	return server, strings.Replace(strings.Replace(server.URL, "https://", "wss://", 1), "http://", "ws://", 1)
}

func dialTestWebSocket(t *testing.T, address string, options WebSocketOptions) *WebSocket {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w, err := DialWebSocket(ctx, address, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	return w
}

func TestWebSocketTextBinaryEchoAndMasking(t *testing.T) {
	masking := make(chan bool, 10)
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		for {
			frame, err := websocketReadWire(reader)
			if err != nil {
				return
			}
			masking <- frame.masked
			_ = websocketWriteWire(connection, frame.opcode, frame.final, frame.payload)
			if frame.opcode == 8 {
				return
			}
		}
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{Profile: Chrome})
	if w.Response.StatusCode != 101 {
		t.Fatalf("status = %d", w.Response.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, test := range []struct {
		data []byte
		flag WSFlag
	}{{[]byte("hello browser"), WSText}, {[]byte{0, 1, 255, 0}, WSBinary}, {[]byte{}, WSText}, {bytes.Repeat([]byte("x"), 150000), WSBinary}} {
		if err := w.Send(ctx, test.data, test.flag); err != nil {
			t.Fatal(err)
		}
		data, flag, err := w.Recv(ctx)
		if err != nil || flag != test.flag || !bytes.Equal(data, test.data) {
			t.Fatalf("echo flag %d len %d: got flag %d len %d, %v", test.flag, len(test.data), flag, len(data), err)
		}
		if !<-masking {
			t.Fatal("client frame was not masked")
		}
	}
}

func TestWebSocketFragmentationAndAutomaticPong(t *testing.T) {
	pong := make(chan websocketWireFrame, 1)
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		_ = websocketWriteWire(connection, 1, false, []byte("first"))
		_ = websocketWriteWire(connection, 9, true, []byte("ping"))
		_ = websocketWriteWire(connection, 0, true, []byte("second"))
		frame, err := websocketReadWire(reader)
		if err == nil {
			pong <- frame
		}
		_, _ = websocketReadWire(reader)
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, flag, err := w.Recv(ctx)
	if err != nil || flag != WSText || string(data) != "firstsecond" {
		t.Fatalf("fragmented message = %q, %d, %v", data, flag, err)
	}
	select {
	case frame := <-pong:
		if frame.opcode != 10 || string(frame.payload) != "ping" || !frame.masked {
			t.Fatalf("pong = %+v", frame)
		}
	case <-ctx.Done():
		t.Fatal("automatic pong not received")
	}
}

func TestWebSocketReceiveTimeoutPreservesFragments(t *testing.T) {
	finish := make(chan struct{})
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		_ = websocketWriteWire(connection, 2, false, []byte("part1"))
		<-finish
		_ = websocketWriteWire(connection, 0, true, []byte("part2"))
		_, _ = websocketReadWire(reader)
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, _, err := w.Recv(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("receive timeout = %v", err)
	}
	close(finish)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, flag, err := w.Recv(ctx)
	if err != nil || flag != WSBinary || string(data) != "part1part2" {
		t.Fatalf("resumed message = %q, %d, %v", data, flag, err)
	}
}

func TestWebSocketCloseFrameAndCloseInterruptsReceive(t *testing.T) {
	t.Run("remote", func(t *testing.T) {
		_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
			_ = websocketWriteWire(connection, 8, true, []byte{3, 232, 'b', 'y', 'e'})
			_, _ = websocketReadWire(reader)
		})
		w := dialTestWebSocket(t, address, WebSocketOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		data, flag, err := w.Recv(ctx)
		if err != nil || flag != WSClose {
			t.Fatalf("close frame = %v, %d, %v", data, flag, err)
		}
		code, reason, err := ParseWebSocketClose(data)
		if err != nil || code != 1000 || reason != "bye" {
			t.Fatalf("close payload = %d, %q, %v", code, reason, err)
		}
		_, _, err = w.Recv(ctx)
		if !errors.Is(err, ErrWebSocketClosed) {
			t.Fatalf("closed receive = %v", err)
		}
	})
	t.Run("local", func(t *testing.T) {
		_, address := websocketFixture(t, false, func(_ net.Conn, reader *bufio.Reader, _ *http.Request) { _, _ = websocketReadWire(reader) })
		w := dialTestWebSocket(t, address, WebSocketOptions{})
		done := make(chan error, 1)
		go func() { _, _, err := w.Recv(context.Background()); done <- err }()
		time.Sleep(20 * time.Millisecond)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrWebSocketClosed) {
				t.Fatalf("receive after Close = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not interrupt Recv")
		}
	})
}

func TestWebSocketMaximumMessageAndInvalidText(t *testing.T) {
	for _, test := range []struct {
		name    string
		opcode  byte
		payload []byte
		limit   int64
		want    error
	}{{"limit", 2, []byte("0123456789"), 5, ErrWebSocketMessageTooLarge}, {"utf8", 1, []byte{255}, 100, nil}} {
		t.Run(test.name, func(t *testing.T) {
			_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
				_ = websocketWriteWire(connection, test.opcode, true, test.payload)
				_, _ = websocketReadWire(reader)
			})
			w := dialTestWebSocket(t, address, WebSocketOptions{MaxMessageSize: test.limit})
			_, _, err := w.Recv(context.Background())
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("receive error = %v", err)
			}
		})
	}
}

func TestWebSocketTLSAndFailedHandshake(t *testing.T) {
	_, address := websocketFixture(t, true, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		for {
			frame, err := websocketReadWire(reader)
			if err != nil {
				return
			}
			_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
			if frame.opcode == 8 {
				return
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := DialWebSocket(ctx, address, WebSocketOptions{})
	if err == nil {
		t.Fatal("self-signed WebSocket certificate accepted")
	}
	w := dialTestWebSocket(t, address, WebSocketOptions{InsecureSkipVerify: true})
	if err = w.SendText(ctx, "secure"); err != nil {
		t.Fatal(err)
	}
	data, _, err := w.Recv(ctx)
	if err != nil || string(data) != "secure" {
		t.Fatalf("TLS echo = %q, %v", data, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer server.Close()
	_, err = DialWebSocket(ctx, strings.Replace(server.URL, "http://", "ws://", 1), WebSocketOptions{})
	var handshake *WebSocketHandshakeError
	if !errors.As(err, &handshake) || handshake.Response == nil || handshake.Response.StatusCode != 403 {
		t.Fatalf("failed handshake = %v", err)
	}
}

func TestWebSocketConcurrentSendAndReceive(t *testing.T) {
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		for {
			frame, err := websocketReadWire(reader)
			if err != nil {
				return
			}
			_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
			if frame.opcode == 8 {
				return
			}
		}
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const count = 20
	received := make(chan error, 1)
	go func() {
		seen := make(map[string]bool)
		for i := 0; i < count; i++ {
			data, flag, err := w.Recv(ctx)
			if err != nil || flag != WSText {
				received <- fmt.Errorf("receive %d: %d %v", i, flag, err)
				return
			}
			seen[string(data)] = true
		}
		if len(seen) != count {
			received <- fmt.Errorf("unique messages %d", len(seen))
			return
		}
		received <- nil
	}()
	var wait sync.WaitGroup
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			if err := w.SendText(ctx, fmt.Sprint(i)); err != nil {
				failures <- err
			}
		}(i)
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketAllBrowserProfiles(t *testing.T) {
	_, address := websocketFixture(t, true, func(connection net.Conn, reader *bufio.Reader, r *http.Request) {
		_ = websocketWriteWire(connection, 1, true, []byte(r.Header.Get("User-Agent")))
		for {
			frame, err := websocketReadWire(reader)
			if err != nil {
				return
			}
			_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
			if frame.opcode == 8 {
				return
			}
		}
	})
	for _, profile := range Profiles() {
		t.Run(string(profile), func(t *testing.T) {
			w := dialTestWebSocket(t, address, WebSocketOptions{Profile: profile, InsecureSkipVerify: true})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			userAgent, flag, err := w.Recv(ctx)
			if err != nil || flag != WSText {
				t.Fatalf("handshake user agent = %q, %d, %v", userAgent, flag, err)
			}
			browser := "Chrome/"
			switch {
			case strings.HasPrefix(string(profile), "edge"):
				browser = "Edg/"
			case strings.HasPrefix(string(profile), "safari"):
				browser = "Safari/"
			case strings.HasPrefix(string(profile), "firefox"), strings.HasPrefix(string(profile), "tor"):
				browser = "Firefox/"
			}
			if !strings.Contains(string(userAgent), browser) {
				t.Fatalf("profile %s WebSocket user agent = %q, want %s", profile, userAgent, browser)
			}
			payload := []byte("profile " + string(profile) + "\x00")
			if err = w.SendBinary(ctx, payload); err != nil {
				t.Fatal(err)
			}
			data, flag, err := w.Recv(ctx)
			if err != nil || flag != WSBinary || !bytes.Equal(data, payload) {
				t.Fatalf("profile binary echo = %q, %d, %v", data, flag, err)
			}
		})
	}
}
