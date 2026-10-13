package curlgo

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type websocketInterruptedWireResult struct {
	length, received int64
	err              error
}

func websocketBackpressureFixture(t *testing.T) (string, <-chan error, func(), <-chan websocketInterruptedWireResult) {
	t.Helper()
	started := make(chan error, 1)
	drained := make(chan websocketInterruptedWireResult, 1)
	release := make(chan struct{})
	var once sync.Once
	releasePeer := func() { once.Do(func() { close(release) }) }
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		if tcp, ok := connection.(*net.TCPConn); ok {
			if err := tcp.SetReadBuffer(16 << 10); err != nil {
				started <- err
				return
			}
		}
		var header [14]byte
		_, err := io.ReadFull(reader, header[:])
		if err == nil && (header[0] != 0x82 || header[1] != 0xff) {
			err = fmt.Errorf("large frame header=%x; want one final masked binary frame", header)
		}
		started <- err
		if err != nil {
			return
		}
		<-release
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(4 << 20)
		}
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		received, err := io.Copy(io.Discard, reader)
		drained <- websocketInterruptedWireResult{length: int64(binary.BigEndian.Uint64(header[2:10])), received: received, err: err}
	})
	t.Cleanup(releasePeer)
	return address, started, releasePeer, drained
}

func TestWebSocketInterruptedSendClosesPendingFrame(t *testing.T) {
	for _, mode := range []string{"deadline", "cancellation", "concurrent-close"} {
		t.Run(mode, func(t *testing.T) {
			address, started, releasePeer, drained := websocketBackpressureFixture(t)
			w := dialTestWebSocket(t, address, WebSocketOptions{})
			ctx, cancel := context.WithCancel(context.Background())
			wantError := error(context.Canceled)
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
				wantError = context.DeadlineExceeded
			} else if mode == "concurrent-close" {
				wantError = ErrWebSocketClosed
			}
			defer cancel()
			data := make([]byte, 16<<20)
			sent, received := make(chan error, 1), make(chan error, 1)
			go func() { _, _, err := w.Recv(context.Background()); received <- err }()
			go func() { sent <- w.SendBinary(ctx, data) }()
			select {
			case err := <-started:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("native sender never started the frame")
			}
			var closed chan error
			if mode == "cancellation" {
				cancel()
			} else if mode == "concurrent-close" {
				closed = make(chan error, 1)
				go func() {
					closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					closed <- w.CloseWithStatus(closeCtx, 1000, "")
				}()
			}
			select {
			case err := <-sent:
				if !errors.Is(err, wantError) {
					t.Fatalf("interrupted send=%v; want %v", err, wantError)
				}
			case <-time.After(time.Second):
				t.Fatal("backpressured send did not honor interruption")
			}
			if closed != nil {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close and interrupted Send deadlocked")
				}
			}
			select {
			case err := <-received:
				if !errors.Is(err, ErrWebSocketClosed) {
					t.Fatalf("receive during interrupted send=%v; want closed socket", err)
				}
			case <-time.After(time.Second):
				t.Fatal("interrupted send did not wake concurrent Recv")
			}
			if err := w.SendText(context.Background(), "next"); !errors.Is(err, ErrWebSocketClosed) {
				t.Fatalf("send after incomplete frame=%v; want closed socket", err)
			}
			releasePeer()
			select {
			case result := <-drained:
				if result.err != nil || result.length != int64(len(data)) || result.received <= 0 || result.received >= result.length {
					t.Fatalf("wire frame length=%d received=%d error=%v; want truncated frame followed by EOF", result.length, result.received, result.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("interrupted sender left the peer connection open")
			}
		})
	}
}

func TestWebSocketCancelledSendBeforeNativePreservesConnection(t *testing.T) {
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		frame, err := websocketReadWire(reader)
		if err != nil {
			return
		}
		_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
		_, _ = websocketReadWire(reader) // Normal close.
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.SendText(ctx, "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("send before native framing=%v; want cancellation", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.SendText(ctx, "healthy"); err != nil {
		t.Fatal(err)
	}
	data, flag, err := w.Recv(ctx)
	if err != nil || flag != WSText || string(data) != "healthy" {
		t.Fatalf("response after pre-cancelled send=%q flag=%d error=%v", data, flag, err)
	}
}

func TestWebSocketCancellationWaitingNativeMutexPreservesConnection(t *testing.T) {
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		frame, err := websocketReadWire(reader)
		if err != nil {
			return
		}
		_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
		_, _ = websocketReadWire(reader)
	})
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	w.curl.mu.Lock()
	locked := true
	defer func() {
		if locked {
			w.curl.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- w.SendText(ctx, "cancelled before native") }()
	// Wait until this sender owns the operation semaphore. Curl's mutex remains
	// held across the deadline, so it cannot enter native framing in the meantime.
	for len(w.sendSem) != 0 {
		select {
		case <-ctx.Done():
			t.Fatal("sender did not reach the native mutex before its deadline")
		case <-time.After(time.Millisecond):
		}
	}
	<-ctx.Done()
	w.curl.mu.Unlock()
	locked = false
	select {
	case err := <-sent:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("send cancelled while waiting for native mutex=%v; want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled sender did not return after native mutex was released")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.SendText(ctx, "healthy"); err != nil {
		t.Fatal(err)
	}
	data, flag, err := w.Recv(ctx)
	if err != nil || flag != WSText || string(data) != "healthy" {
		t.Fatalf("response after mutex-wait cancellation=%q flag=%d error=%v", data, flag, err)
	}
}

func TestWebSocketCancelledQueuedSendPreservesActiveFrame(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	releasePeer := func() { once.Do(func() { close(release) }) }
	started := make(chan error, 1)
	const messageSize = 16 << 20
	_, address := websocketFixture(t, false, func(connection net.Conn, reader *bufio.Reader, _ *http.Request) {
		var header [14]byte
		_, err := io.ReadFull(reader, header[:])
		started <- err
		if err != nil {
			return
		}
		<-release
		if header[0] != 0x82 || header[1] != 0xff || binary.BigEndian.Uint64(header[2:10]) != messageSize {
			t.Errorf("active frame header=%x", header)
			return
		}
		if _, err = io.CopyN(io.Discard, reader, messageSize); err != nil {
			t.Errorf("queued send cancellation truncated active frame: %v", err)
			return
		}
		frame, err := websocketReadWire(reader)
		if err != nil {
			return
		}
		_ = websocketWriteWire(connection, frame.opcode, true, frame.payload)
		_, _ = websocketReadWire(reader)
	})
	t.Cleanup(releasePeer)
	w := dialTestWebSocket(t, address, WebSocketOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- w.SendBinary(ctx, make([]byte, messageSize)) }()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native sender never started the active frame")
	}
	queued, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	err := w.SendText(queued, "cancelled queue entry")
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued send=%v; want deadline", err)
	}
	releasePeer()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("queued cancellation interrupted active send: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("active send did not finish after peer resumed reading")
	}
	if err := w.SendText(ctx, "healthy"); err != nil {
		t.Fatal(err)
	}
	data, flag, err := w.Recv(ctx)
	if err != nil || flag != WSText || string(data) != "healthy" {
		t.Fatalf("response after queued cancellation=%q flag=%d error=%v", data, flag, err)
	}
}
