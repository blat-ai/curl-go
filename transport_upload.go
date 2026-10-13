package curlgo

import (
	"errors"
	"io"
	"sync"
)

// replayableRequestBody supplies the native rewind callback with fresh streams
// from Request.GetBody. Read and Seek run serially in native callbacks; Close
// can run concurrently to interrupt a blocked Read after cancellation.
type replayableRequestBody struct {
	mu      sync.Mutex
	body    io.ReadCloser
	getBody func() (io.ReadCloser, error)
	closed  bool
}

func (b *replayableRequestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	body := b.body
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	return body.Read(p)
}

func (b *replayableRequestBody) Seek(offset int64, whence int) (int64, error) {
	// Native authentication rewinds to the beginning of the upload.
	if offset != 0 || whence != io.SeekStart {
		return 0, errors.New("curlgo: replayable request body only supports rewinding to its beginning")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	body, err := b.getBody()
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return 0, err
	}
	if body == nil {
		return 0, errors.New("curlgo: Request.GetBody returned a nil body")
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = body.Close()
		return 0, io.ErrClosedPipe
	}
	oldBody := b.body
	b.body = body
	b.mu.Unlock()
	_ = oldBody.Close()
	return 0, nil
}

func (b *replayableRequestBody) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	body := b.body
	b.mu.Unlock()
	return body.Close()
}
