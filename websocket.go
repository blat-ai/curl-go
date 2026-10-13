package curlgo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrWebSocketClosed indicates that the WebSocket's native handle was released.
var ErrWebSocketClosed = errors.New("curlgo: WebSocket is closed")

// ErrWebSocketMessageTooLarge indicates a received message exceeding its limit.
var ErrWebSocketMessageTooLarge = errors.New("curlgo: WebSocket message exceeds MaxMessageSize")

// WebSocketOptions configures a browser-impersonated WebSocket handshake.
// Timeout and ConnectTimeout limit the handshake; each subsequent operation
// uses its own context. Zero Profile selects the latest Chrome profile.
type WebSocketOptions struct {
	Profile            Profile
	DefaultHeaders     *bool
	Fingerprint        Fingerprint
	Headers            http.Header
	OrderedHeaders     []Header
	Subprotocols       []string
	Proxy              string
	InsecureSkipVerify bool
	CAFile             string
	CAPath             string
	ClientCertFile     string
	ClientKeyFile      string
	ClientKeyPassword  string
	Interface          string
	Timeout            time.Duration
	ConnectTimeout     time.Duration
	// MaxMessageSize defaults to 16 MiB; a negative value disables the limit.
	MaxMessageSize int64
	CurlOptions    map[Option]any
}

// WebSocketHandshakeError includes any HTTP response received during a failed
// handshake. Response.Body is empty because native upgrading owns the connection.
type WebSocketHandshakeError struct {
	Response *http.Response
	Err      error
}

func (e *WebSocketHandshakeError) Error() string {
	return "curlgo: WebSocket handshake: " + e.Err.Error()
}
func (e *WebSocketHandshakeError) Unwrap() error { return e.Err }

// WebSocket supports concurrent send and receive operations. Messages are
// reassembled across frames, and partial receive state survives context expiry.
// libcurl answers server pings automatically. Close releases the native handle.
type WebSocket struct {
	Response        *http.Response
	curl            *Curl
	lifetime        context.Context
	cancel          context.CancelFunc
	recvSem         chan struct{}
	sendSem         chan struct{}
	maxMessageSize  int64
	recvBuffer      []byte
	recvType        WSFlag
	controlBuffer   []byte
	sendInterrupted bool // Protected by sendSem; an incomplete frame cannot be reused.
	closeOnce       sync.Once
	closeErr        error
}

// DialWebSocket connects to a ws:// or wss:// URL using curl-impersonate.
func DialWebSocket(ctx context.Context, address string, options WebSocketOptions) (*WebSocket, error) {
	if ctx == nil {
		return nil, errors.New("curlgo: nil WebSocket context")
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
		return nil, errors.New("curlgo: WebSocket URL must use ws or wss and contain a host")
	}
	if options.Timeout < 0 || options.ConnectTimeout < 0 {
		return nil, errors.New("curlgo: WebSocket timeouts must not be negative")
	}
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}
	profile := options.Profile
	if profile == "" {
		profile = Chrome
	}
	profile, err = NormalizeProfile(profile)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	r.Header = options.Headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	if len(options.Subprotocols) > 0 {
		for _, protocol := range options.Subprotocols {
			if !validHeaderName(protocol) {
				return nil, fmt.Errorf("curlgo: invalid WebSocket subprotocol %q", protocol)
			}
		}
		r.Header.Set("Sec-WebSocket-Protocol", strings.Join(options.Subprotocols, ", "))
	}
	if len(options.OrderedHeaders) > 0 {
		r = WithOrderedHeaders(r, options.OrderedHeaders)
	}
	if err = validateRequest(r); err != nil {
		return nil, err
	}
	c, err := NewCurl()
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = c.Close()
		}
	}()
	if err = c.Impersonate(string(profile), options.DefaultHeaders == nil || *options.DefaultHeaders); err != nil {
		return nil, err
	}
	if err = ApplyFingerprint(c, options.Fingerprint); err != nil {
		return nil, err
	}
	parser := newResponseHeaders(r, 1<<20)
	hostVerify := 2
	if options.InsecureSkipVerify {
		hostVerify = 0
	}
	config := []struct {
		o Option
		v any
	}{
		{OptURL, address}, {OptConnectOnly, 2}, {OptProxy, options.Proxy}, {OptSSLVerifyPeer, !options.InsecureSkipVerify}, {OptSSLVerifyHost, hostVerify},
		{OptHeaderFunction, parser}, {OptWriteFunction, io.Discard}, {OptHTTPHeader, requestHeaders(r)}, {OptSuppressConnectHeaders, true},
	}
	if options.ConnectTimeout > 0 {
		config = append(config, struct {
			o Option
			v any
		}{OptConnectTimeoutMS, milliseconds(options.ConnectTimeout)})
	}
	for _, field := range []struct {
		o Option
		v string
	}{{OptCAInfo, options.CAFile}, {OptCAPath, options.CAPath}, {OptSSLCert, options.ClientCertFile}, {OptSSLKey, options.ClientKeyFile}, {OptKeyPasswd, options.ClientKeyPassword}, {OptInterface, options.Interface}} {
		if field.v != "" {
			config = append(config, struct {
				o Option
				v any
			}{field.o, field.v})
		}
	}
	for _, option := range config {
		if err = c.SetOpt(option.o, option.v); err != nil {
			return nil, err
		}
	}
	keys := make([]int, 0, len(options.CurlOptions))
	for option := range options.CurlOptions {
		keys = append(keys, int(option))
	}
	sort.Ints(keys)
	for _, key := range keys {
		option := Option(key)
		switch option {
		case OptURL, OptConnectOnly, OptHeaderFunction, OptHeaderData, OptWriteFunction, OptWriteData, OptHTTPHeader, OptFollowLocation, OptWSOptions:
			return nil, fmt.Errorf("curlgo: WebSocket option %d is managed by DialWebSocket", option)
		}
		if err = c.SetOpt(option, options.CurlOptions[option]); err != nil {
			return nil, err
		}
	}
	err = c.Perform(ctx)
	if err != nil {
		return nil, &WebSocketHandshakeError{Response: parser.response, Err: err}
	}
	if parser.response == nil || parser.response.StatusCode != http.StatusSwitchingProtocols {
		return nil, &WebSocketHandshakeError{Response: parser.response, Err: errors.New("server did not switch WebSocket protocols")}
	}
	response := parser.response
	response.Body = io.NopCloser(bytes.NewReader(nil))
	response.ContentLength = 0
	if selected := response.Header.Get("Sec-WebSocket-Protocol"); selected != "" {
		found := false
		for _, protocol := range options.Subprotocols {
			if protocol == selected {
				found = true
				break
			}
		}
		if !found {
			return nil, &WebSocketHandshakeError{Response: response, Err: fmt.Errorf("server selected unrequested subprotocol %q", selected)}
		}
	}
	limit := options.MaxMessageSize
	if limit == 0 {
		limit = 16 << 20
	}
	lifetime, cancel := context.WithCancel(context.Background())
	w := &WebSocket{Response: response, curl: c, lifetime: lifetime, cancel: cancel, recvSem: make(chan struct{}, 1), sendSem: make(chan struct{}, 1), maxMessageSize: limit}
	w.recvSem <- struct{}{}
	w.sendSem <- struct{}{}
	success = true
	return w, nil
}

func (w *WebSocket) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("curlgo: nil WebSocket context")
	}
	if w == nil || w.curl == nil || w.lifetime == nil || w.lifetime.Err() != nil {
		return nil, nil, ErrWebSocketClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(w.lifetime, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

func (w *WebSocket) operationError(ctx context.Context, err error) error {
	if ctx.Err() == nil && w.lifetime.Err() != nil {
		return ErrWebSocketClosed
	}
	return err
}

func websocketSemaphore(ctx context.Context, semaphore chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-semaphore:
		return nil
	}
}

// Send sends one complete text, binary, ping or pong frame. Text payloads must
// contain valid UTF-8, and control payloads must be at most 125 bytes.
// If a send is interrupted after native framing starts, the connection closes
// because its unfinished frame cannot be replaced by a subsequent message.
func (w *WebSocket) Send(ctx context.Context, data []byte, flag WSFlag) error {
	if flag != WSText && flag != WSBinary && flag != WSPing && flag != WSPong {
		return errors.New("curlgo: Send requires one text, binary, ping or pong flag")
	}
	if flag == WSText && !utf8.Valid(data) {
		return errors.New("curlgo: WebSocket text must be valid UTF-8")
	}
	if (flag == WSPing || flag == WSPong) && len(data) > 125 {
		return errors.New("curlgo: WebSocket control payload exceeds 125 bytes")
	}
	op, cancel, err := w.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = websocketSemaphore(op, w.sendSem); err != nil {
		return w.operationError(ctx, err)
	}
	interrupted := false
	defer func() {
		w.sendSem <- struct{}{}
		if interrupted {
			// Release the send semaphore before waiting on Close: a concurrent
			// graceful Close may already own closeOnce and need that semaphore.
			w.closeOnce.Do(func() { w.closeErr = w.curl.Close() })
		}
	}()
	err, interrupted = w.sendMessage(op, data, flag)
	reported := w.operationError(ctx, err)
	if interrupted {
		w.sendInterrupted = true
		w.cancel()
	}
	return reported
}

func (w *WebSocket) sendMessage(ctx context.Context, data []byte, flag WSFlag) (error, bool) {
	started := false
	for {
		n, attempted, err := w.curl.wsSendFrame(ctx, data, 0, flag)
		started = started || attempted
		var curlError *CurlError
		if err != nil && !(errors.As(err, &curlError) && curlError.Code == CurlECode_AGAIN) {
			return err, started
		}
		if n < 0 || n > len(data) {
			return errors.New("curlgo: invalid native WebSocket send count"), started
		}
		data = data[n:]
		if len(data) == 0 && err == nil {
			return nil, false
		}
		if n == 0 {
			if err = webSocketWait(ctx); err != nil {
				return err, started
			}
		}
	}
}

func (w *WebSocket) SendText(ctx context.Context, text string) error {
	return w.Send(ctx, []byte(text), WSText)
}
func (w *WebSocket) SendBinary(ctx context.Context, data []byte) error {
	return w.Send(ctx, data, WSBinary)
}
func (w *WebSocket) Ping(ctx context.Context, data []byte) error { return w.Send(ctx, data, WSPing) }
func (w *WebSocket) Pong(ctx context.Context, data []byte) error { return w.Send(ctx, data, WSPong) }

// Recv waits for one complete data message or a close frame. Ping and pong frames
// are handled internally. A close frame is returned with WSClose and no error;
// later operations return ErrWebSocketClosed. Context expiry preserves fragments
// so the next Recv can continue the same message.
func (w *WebSocket) Recv(ctx context.Context) ([]byte, WSFlag, error) {
	op, cancel, err := w.operationContext(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer cancel()
	if err = websocketSemaphore(op, w.recvSem); err != nil {
		return nil, 0, w.operationError(ctx, err)
	}
	defer func() { w.recvSem <- struct{}{} }()
	buffer := make([]byte, 16<<10)
	for {
		n, frame, err := w.curl.WSRecv(op, buffer)
		if err != nil {
			return nil, 0, w.operationError(ctx, err)
		}
		typeFlag := frame.Flags & (WSText | WSBinary | WSClose | WSPing | WSPong)
		if typeFlag == WSText || typeFlag == WSBinary {
			if w.recvType != 0 && w.recvType != typeFlag {
				_ = w.CloseWithStatus(context.Background(), 1002, "inconsistent message type")
				return nil, 0, errors.New("curlgo: inconsistent WebSocket fragmented message type")
			}
			w.recvType = typeFlag
			if w.maxMessageSize > 0 && (int64(len(w.recvBuffer))+int64(n) > w.maxMessageSize || frame.BytesLeft > w.maxMessageSize-int64(len(w.recvBuffer))-int64(n)) {
				_ = w.CloseWithStatus(context.Background(), 1009, "message too large")
				return nil, 0, ErrWebSocketMessageTooLarge
			}
			w.recvBuffer = append(w.recvBuffer, buffer[:n]...)
			if frame.BytesLeft == 0 && frame.Flags&WSCont == 0 {
				message := w.recvBuffer
				w.recvBuffer = nil
				w.recvType = 0
				if typeFlag == WSText && !utf8.Valid(message) {
					_ = w.CloseWithStatus(context.Background(), 1007, "invalid UTF-8")
					return nil, 0, errors.New("curlgo: received invalid WebSocket text UTF-8")
				}
				return message, typeFlag, nil
			}
		} else if typeFlag == WSClose || typeFlag == WSPing || typeFlag == WSPong {
			w.controlBuffer = append(w.controlBuffer, buffer[:n]...)
			if len(w.controlBuffer) > 125 || frame.BytesLeft > 125-int64(len(w.controlBuffer)) {
				_ = w.CloseWithStatus(context.Background(), 1002, "invalid control frame")
				return nil, 0, errors.New("curlgo: WebSocket control frame exceeds 125 bytes")
			}
			if frame.BytesLeft != 0 {
				continue
			}
			control := w.controlBuffer
			w.controlBuffer = nil
			if typeFlag == WSClose {
				if _, _, err = ParseWebSocketClose(control); err != nil {
					_ = w.CloseWithStatus(context.Background(), 1002, "invalid close frame")
					return nil, 0, err
				}
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				_ = w.shutdown(closeCtx, control)
				closeCancel()
				return control, WSClose, nil
			}
		}
	}
}

func validWebSocketCloseCode(code int) bool {
	return (code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006) || code >= 3000 && code <= 4999
}

// ParseWebSocketClose extracts a close status and reason. An empty payload uses
// status 1005 (no status received), which cannot be sent as a wire close code.
func ParseWebSocketClose(payload []byte) (int, string, error) {
	if len(payload) == 0 {
		return 1005, "", nil
	}
	if len(payload) < 2 || len(payload) > 125 {
		return 0, "", errors.New("curlgo: invalid WebSocket close payload length")
	}
	code := int(binary.BigEndian.Uint16(payload))
	reason := payload[2:]
	if !validWebSocketCloseCode(code) || !utf8.Valid(reason) {
		return 0, "", errors.New("curlgo: invalid WebSocket close status or UTF-8 reason")
	}
	return code, string(reason), nil
}

// CloseWithStatus sends a close frame and releases the connection. The reason
// must be valid UTF-8 and fit within the protocol's 123-byte limit.
func (w *WebSocket) CloseWithStatus(ctx context.Context, code int, reason string) error {
	if ctx == nil {
		return errors.New("curlgo: nil WebSocket context")
	}
	if !validWebSocketCloseCode(code) || !utf8.ValidString(reason) || len(reason) > 123 {
		return errors.New("curlgo: invalid WebSocket close status or reason")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
		defer cancel()
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, uint16(code))
	copy(payload[2:], reason)
	return w.shutdown(ctx, payload)
}

func (w *WebSocket) shutdown(ctx context.Context, payload []byte) error {
	if w == nil || w.curl == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		w.cancel()
		if err := websocketSemaphore(ctx, w.sendSem); err == nil {
			// Sending a close frame is best effort; the native handle is always
			// released even if the peer already disconnected.
			if !w.sendInterrupted {
				_, _ = w.sendMessage(ctx, payload, WSClose)
			}
			w.sendSem <- struct{}{}
		}
		w.closeErr = w.curl.Close()
	})
	return w.closeErr
}

// Close sends normal status 1000 with a brief deadline, then releases resources.
func (w *WebSocket) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	return w.CloseWithStatus(ctx, 1000, "")
}
