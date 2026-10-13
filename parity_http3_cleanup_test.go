package curlgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// HTTP/3 control and QPACK streams are critical streams. The capture observer
// must stop local reads without telling the client to stop sending on them.
// This raw QUIC client exposes remote cancellation directly, before an HTTP/3
// implementation turns it into a connection-level error during JSON delivery.
func TestParityHTTP3CaptureCleanupPreservesCriticalStreams(t *testing.T) {
	server := startParityHTTP3Server(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	}()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, endpoint.Host, &tls.Config{
		ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test complete")
	var critical []*quic.SendStream
	for _, streamType := range []uint64{0, 2, 3} {
		stream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		data := quicvarint.Append(nil, streamType)
		if streamType == 0 {
			data = append(data, 4, 0) // An empty SETTINGS frame.
		}
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
		critical = append(critical, stream)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// This produces a JSON response large enough to need multiple QUIC packets.
	body := bytes.Repeat([]byte{0, 0xff, '\r', '\n'}, 16<<10)
	var headers bytes.Buffer
	encoder := qpack.NewEncoder(&headers)
	for _, field := range []qpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: endpoint.Host},
		{Name: ":path", Value: endpoint.RequestURI()},
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	request := quicvarint.Append(nil, 1)
	request = quicvarint.Append(request, uint64(headers.Len()))
	request = append(request, headers.Bytes()...)
	request = quicvarint.Append(request, 0)
	request = quicvarint.Append(request, uint64(len(body)))
	request = append(request, body...)
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stream)
	var response []byte
	for {
		frame, err := parityReadHTTP3Frame(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == 0 {
			response = append(response, frame.Payload...)
		}
	}
	var capture parityCapture
	if err := json.Unmarshal(response, &capture); err != nil {
		t.Fatalf("incomplete JSON response (%d bytes): %v", len(response), err)
	}
	if !bytes.Equal(capture.HTTP.Body, body) {
		t.Fatal("JSON response did not contain the complete binary request body")
	}
	// Allow the server's post-response cleanup frames to reach the client. A
	// remote STOP_SENDING immediately cancels the corresponding SendStream.
	quiet := time.NewTimer(150 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case <-critical[0].Context().Done():
			t.Fatal(fmt.Errorf("capture cleanup canceled HTTP/3 control stream: %w", context.Cause(critical[0].Context())))
		case <-critical[1].Context().Done():
			t.Fatal(fmt.Errorf("capture cleanup canceled QPACK encoder stream: %w", context.Cause(critical[1].Context())))
		case <-critical[2].Context().Done():
			t.Fatal(fmt.Errorf("capture cleanup canceled QPACK decoder stream: %w", context.Cause(critical[2].Context())))
		case <-quiet.C:
			return
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
