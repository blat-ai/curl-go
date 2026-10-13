package curlgo

/*
#include "native.h"
*/
import "C"

import (
	"context"
	"errors"
	"time"
	"unsafe"
)

// WSFrame describes the portion of a native WebSocket frame returned by WSRecv.
type WSFrame struct {
	Flags     WSFlag
	Offset    int64
	BytesLeft int64
	Len       int
}

// WSRecv reads a portion of a WebSocket frame after a CONNECT_ONLY=2 transfer.
// It waits on CURLE_AGAIN without preventing a concurrent sender or Close.
func (c *Curl) WSRecv(ctx context.Context, buffer []byte) (int, WSFrame, error) {
	if ctx == nil {
		return 0, WSFrame{}, errors.New("curlgo: nil context")
	}
	if len(buffer) == 0 {
		return 0, WSFrame{}, errors.New("curlgo: empty WebSocket receive buffer")
	}
	for {
		if e := ctx.Err(); e != nil {
			return 0, WSFrame{}, e
		}
		c.mu.Lock()
		if c.easy == nil {
			c.mu.Unlock()
			return 0, WSFrame{}, ErrClosed
		}
		c.clearError()
		var n C.size_t
		var meta C.struct_curl_ws_frame
		code := C.cg_ws_recv(c.easy, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)), &n, &meta)
		frame := WSFrame{Flags: WSFlag(meta.flags), Offset: int64(meta.offset), BytesLeft: int64(meta.bytesleft), Len: int(meta.len)}
		e := c.check(code, "ws_recv")
		c.mu.Unlock()
		if code != C.int(CurlECode_AGAIN) {
			return int(n), frame, e
		}
		if e := webSocketWait(ctx); e != nil {
			return 0, WSFrame{}, e
		}
	}
}

// WSSend sends bytes through an established WebSocket connection. The returned
// count may be smaller than len(data); the caller must handle partial sends.
func (c *Curl) WSSend(ctx context.Context, data []byte, flags WSFlag) (int, error) {
	return c.WSSendFrame(ctx, data, 0, flags)
}

// WSSendFrame additionally supplies a full payload length for WSOffset sends.
func (c *Curl) WSSendFrame(ctx context.Context, data []byte, frameSize int64, flags WSFlag) (int, error) {
	n, _, err := c.wsSendFrame(ctx, data, frameSize, flags)
	return n, err
}

// wsSendFrame reports whether native framing was entered. Even CURLE_AGAIN
// with no reported payload bytes may leave an encoded frame pending in curl.
func (c *Curl) wsSendFrame(ctx context.Context, data []byte, frameSize int64, flags WSFlag) (int, bool, error) {
	if ctx == nil {
		return 0, false, errors.New("curlgo: nil context")
	}
	if frameSize < 0 {
		return 0, false, errors.New("curlgo: negative WebSocket frame size")
	}
	attempted := false
	for {
		if e := ctx.Err(); e != nil {
			return 0, attempted, e
		}
		c.mu.Lock()
		if e := ctx.Err(); e != nil {
			c.mu.Unlock()
			return 0, attempted, e
		}
		if c.easy == nil {
			c.mu.Unlock()
			return 0, attempted, ErrClosed
		}
		c.clearError()
		var p unsafe.Pointer
		if len(data) > 0 {
			p = unsafe.Pointer(&data[0])
		}
		var n C.size_t
		attempted = true
		code := C.cg_ws_send(c.easy, p, C.size_t(len(data)), &n, C.curl_off_t(frameSize), C.uint(flags))
		e := c.check(code, "ws_send")
		c.mu.Unlock()
		if code != C.int(CurlECode_AGAIN) || n > 0 {
			return int(n), attempted, e
		}
		if e := webSocketWait(ctx); e != nil {
			return 0, attempted, e
		}
	}
}
func webSocketWait(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
