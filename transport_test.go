package curlgo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func transportClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Chrome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func responseBytes(t *testing.T, response *http.Response, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTransportHTTPMethodsAndBinaryBodies(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Method", r.Method)
		_, _ = io.Copy(w, r.Body)
	}))
	defer s.Close()
	c := transportClient(t)
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PURGE", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			payload := []byte{'a', 0, 'b', 255, 'c'}
			var body io.Reader = bytes.NewReader(payload)
			if method == "HEAD" {
				body = nil
			}
			r, err := http.NewRequest(method, s.URL, body)
			if err != nil {
				t.Fatal(err)
			}
			response, err := c.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			if response.Header.Get("X-Method") != method {
				t.Fatalf("method = %q", response.Header.Get("X-Method"))
			}
			data := responseBytes(t, response, nil)
			if method != "HEAD" && !bytes.Equal(data, payload) {
				t.Fatalf("body = %v, want %v", data, payload)
			}
		})
	}
}

func TestTransportPostNoBodyAndUnknownLength(t *testing.T) {
	lengths := make(chan int64, 2)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lengths <- r.ContentLength
		_, _ = io.Copy(w, r.Body)
	}))
	defer s.Close()
	c := transportClient(t)
	data := postBytes(t, c, s.URL, "application/octet-stream", nil)
	if len(data) != 0 {
		t.Fatal(data)
	}
	body := io.NopCloser(strings.NewReader("unknown length"))
	r, err := http.NewRequest("POST", s.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	data = doBytes(t, c, r)
	if string(data) != "unknown length" {
		t.Fatalf("body = %q", data)
	}
	first, second := <-lengths, <-lengths
	if first != 0 || second != -1 {
		t.Fatalf("lengths = %d, %d", first, second)
	}
}

func TestTransportFormsJSONAndMultipart(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			file, _, err := r.FormFile("upload")
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			defer file.Close()
			data, _ := io.ReadAll(file)
			_, _ = fmt.Fprintf(w, "%s|%s", r.FormValue("name"), data)
			return
		}
		w.Header().Set("X-Content-Type", r.Header.Get("Content-Type"))
		_, _ = io.Copy(w, r.Body)
	}))
	defer s.Close()
	c := transportClient(t)
	data := postFormBytes(t, c, s.URL, url.Values{"foo": {"a", "b"}, "bar": {"x y"}})
	if string(data) != "bar=x+y&foo=a&foo=b" {
		t.Fatalf("form = %q", data)
	}
	data = postBytes(t, c, s.URL, "application/json", strings.NewReader(`{"foo":"bar"}`))
	if string(data) != `{"foo":"bar"}` {
		t.Fatalf("JSON = %q", data)
	}
	var buffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&buffer)
	_ = multipartWriter.WriteField("name", "test")
	file, err := multipartWriter.CreateFormFile("upload", "data.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("binary\x00payload"))
	_ = multipartWriter.Close()
	data = postBytes(t, c, s.URL, multipartWriter.FormDataContentType(), &buffer)
	if string(data) != "test|binary\x00payload" {
		t.Fatalf("multipart = %q", data)
	}
}

func TestTransportCookiesRedirectsAndAuth(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "foo", Value: "bar", Path: "/"})
			http.Redirect(w, r, "/echo", http.StatusFound)
		case "/auth":
			user, password, ok := r.BasicAuth()
			if !ok || user != "user" || password != "pass" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, "authenticated")
		case "/307":
			http.Redirect(w, r, "/body", http.StatusTemporaryRedirect)
		case "/303":
			http.Redirect(w, r, "/body", http.StatusSeeOther)
		case "/body":
			_, _ = fmt.Fprintf(w, "%s|", r.Method)
			_, _ = io.Copy(w, r.Body)
		default:
			_, _ = io.WriteString(w, r.Header.Get("Cookie"))
		}
	}))
	defer s.Close()
	c := transportClient(t)
	data := getBytes(t, c, s.URL+"/set")
	if string(data) != "foo=bar" {
		t.Fatalf("redirect cookie = %q", data)
	}
	data = getBytes(t, c, s.URL+"/echo")
	if string(data) != "foo=bar" {
		t.Fatalf("session cookie = %q", data)
	}
	data = getBytes(t, c, strings.Replace(s.URL, "http://", "http://user:pass@", 1)+"/auth")
	if string(data) != "authenticated" {
		t.Fatalf("auth = %q", data)
	}
	for _, test := range []struct{ path, want string }{{"/307", "POST|retained"}, {"/303", "GET|"}} {
		data = postBytes(t, c, s.URL+test.path, "text/plain", strings.NewReader("retained"))
		if string(data) != test.want {
			t.Fatalf("redirect %s = %q", test.path, data)
		}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := c.Get(s.URL + "/set")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestTransportRedirectLoopAndCrossHostAuth(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Header.Get("Authorization")) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loop" {
			http.Redirect(w, r, "/loop", 302)
			return
		}
		http.Redirect(w, r, strings.Replace(target.URL, "127.0.0.1", "localhost", 1), 302)
	}))
	defer s.Close()
	c := transportClient(t)
	_, err := c.Get(s.URL + "/loop")
	if err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Fatalf("redirect loop error = %v", err)
	}
	r, _ := http.NewRequest("GET", s.URL, nil)
	r.SetBasicAuth("user", "pass")
	data := doBytes(t, c, r)
	if len(data) != 0 {
		t.Fatalf("cross-host auth leaked: %q", data)
	}
}

func TestTransportAutomaticDecompression(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "" {
			_, _ = io.WriteString(w, "plain")
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		_, _ = io.WriteString(writer, "compressed payload")
		_ = writer.Close()
		w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
		_, _ = w.Write(compressed.Bytes())
	}))
	defer s.Close()
	c := transportClient(t)
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Uncompressed || response.Header.Get("Content-Encoding") != "" || response.ContentLength != -1 {
		t.Fatalf("decompression response: %+v", response)
	}
	data := responseBytes(t, response, nil)
	if string(data) != "compressed payload" {
		t.Fatalf("body = %q", data)
	}
}

func TestTransportCompressionOverridesPreserveResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "" {
			_, _ = io.WriteString(w, "plain")
			return
		}
		var buffer bytes.Buffer
		compressor := gzip.NewWriter(&buffer)
		_, _ = io.WriteString(compressor, "compressed payload")
		_ = compressor.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(buffer.Len()))
		_, _ = w.Write(buffer.Bytes())
	}))
	defer s.Close()
	for _, test := range []struct {
		name           string
		options        map[Option]any
		manualEncoding bool
		disabled       bool
		wantPlain      bool
	}{
		{"decode_disabled", map[Option]any{OptHTTPContentDecoding: false}, false, false, false},
		{"accept_encoding_nil", map[Option]any{OptAcceptEncoding: nil}, false, false, false},
		{"manual_accept_encoding", nil, true, false, false},
		{"compression_disabled", nil, false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := transportClient(t)
			c.CurlTransport.CurlOptions = test.options
			c.CurlTransport.DisableCompression = test.disabled
			r, _ := http.NewRequest("GET", s.URL, nil)
			if test.manualEncoding {
				r.Header.Set("Accept-Encoding", "gzip")
			}
			response, err := c.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data := responseBytes(t, response, nil)
			if test.wantPlain {
				if string(data) != "plain" || response.Uncompressed {
					t.Fatalf("plain response = %q, uncompressed %v", data, response.Uncompressed)
				}
				return
			}
			if response.Uncompressed || response.Header.Get("Content-Encoding") != "gzip" || response.ContentLength != int64(len(data)) {
				t.Fatalf("encoded response metadata = encoding %q, length %d, uncompressed %v", response.Header.Get("Content-Encoding"), response.ContentLength, response.Uncompressed)
			}
			reader, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("raw body is not gzip: %v", err)
			}
			decoded, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil || string(decoded) != "compressed payload" {
				t.Fatalf("decoded = %q, %v", decoded, err)
			}
		})
	}
}

func TestTransportStreamingAndTrailers(t *testing.T) {
	continueBody := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Trailer")
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-continueBody:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "second\n")
		w.Header().Set("X-Trailer", "finished")
	}))
	defer s.Close()
	c := transportClient(t)
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("first chunk = %q, %v", line, err)
	}
	close(continueBody)
	rest, err := io.ReadAll(reader)
	if err != nil || string(rest) != "second\n" {
		t.Fatalf("second chunk = %q, %v", rest, err)
	}
	if response.Trailer.Get("X-Trailer") != "finished" {
		t.Fatalf("trailer = %v", response.Trailer)
	}
}

func TestTransportTimeoutCancellationAndBodyClose(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			_, _ = io.WriteString(w, "initial")
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			_, _ = io.WriteString(w, "late")
		}
	}))
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.Timeout = 70 * time.Millisecond
	start := time.Now()
	_, err := c.Get(s.URL)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("timeout = %v after %v", err, time.Since(start))
	}
	c.CurlTransport.Timeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	go func() { time.Sleep(40 * time.Millisecond); cancel() }()
	_, err = c.Do(r)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	response, err := c.Get(s.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 7)
	if _, err = io.ReadFull(response.Body, data); err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if err = c.Close(); err != nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("close = %v after %v", err, time.Since(start))
	}
}

func TestTransportCloseWithUnreadStreamingResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		data := bytes.Repeat([]byte("x"), 256<<10)
		for {
			if _, err := w.Write(data); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			default:
			}
		}
	}))
	defer s.Close()
	c := transportClient(t)
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on unread response")
	}
	_, err = c.Get(s.URL)
	if !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("closed request = %v", err)
	}
}

func TestTransportConcurrentPoolAndConnectionReuse(t *testing.T) {
	var connections atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.Start()
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.MaxHandles = 3
	for i := 0; i < 5; i++ {
		if string(getBytes(t, c, s.URL)) != "ok" {
			t.Fatal("body")
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("sequential connections = %d, want 1", got)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := c.Get(s.URL)
			if err != nil {
				failures <- err
				return
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil {
				failures <- err
			} else if string(data) != "ok" {
				failures <- fmt.Errorf("body %q", data)
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if got := connections.Load(); got > 3 {
		t.Fatalf("connections = %d, limit 3", got)
	}
	c.CloseIdleConnections()
	_ = getBytes(t, c, s.URL)
	if got := connections.Load(); got < 2 {
		t.Fatalf("connections after closing idle = %d", got)
	}
}

func TestTransportPoolWaitCancellation(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.MaxHandles = 1
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	_, err = c.Do(r)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait = %v", err)
	}
	close(release)
}

func TestTransportTLSVerificationAndCA(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secure") }))
	defer s.Close()
	c := transportClient(t)
	_, err := c.Get(s.URL)
	if err == nil {
		t.Fatal("self-signed certificate accepted by default")
	}
	c.CurlTransport.InsecureSkipVerify = true
	if data := getBytes(t, c, s.URL); string(data) != "secure" {
		t.Fatalf("body = %q", data)
	}
	c.CloseIdleConnections()
	c.CurlTransport.InsecureSkipVerify = false
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c.CurlTransport.CAFile = ca
	if data := getBytes(t, c, s.URL); string(data) != "secure" {
		t.Fatalf("CA body = %q", data)
	}
}

func TestTransportHTTP2(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintf(w, "%d", r.ProtoMajor) }))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.InsecureSkipVerify = true
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("protocol = %s", response.Proto)
	}
	if string(responseBytes(t, response, nil)) != "2" {
		t.Fatal("server did not receive HTTP/2")
	}
}

func TestTransportTLSClientCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "curlgo test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "native-client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "client.pem")
	keyFile := filepath.Join(directory, "key.pem")
	if err = os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	s.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.InsecureSkipVerify = true
	_, err = c.Get(s.URL)
	if err == nil {
		t.Fatal("server requiring client certificate accepted anonymous client")
	}
	c.CloseIdleConnections()
	c.CurlTransport.ClientCertFile = certificateFile
	c.CurlTransport.ClientKeyFile = keyFile
	if data := getBytes(t, c, s.URL); string(data) != "native-client" {
		t.Fatalf("client certificate subject = %q", data)
	}
}

func TestTransportHTTPSProxyCONNECT(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "tunneled") }))
	defer target.Close()
	connects := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 405)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer upstream.Close()
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		connects <- r.Host
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	defer proxy.Close()
	c := transportClient(t)
	c.CurlTransport.InsecureSkipVerify = true
	c.CurlTransport.Proxy = proxy.URL
	c.CurlTransport.CurlOptions = map[Option]any{OptNoProxy: ""}
	response, err := c.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Content-Length") != "8" {
		t.Fatalf("proxy CONNECT headers surfaced as response: %v", response.Header)
	}
	if data := responseBytes(t, response, nil); string(data) != "tunneled" {
		t.Fatalf("CONNECT body = %q", data)
	}
	select {
	case host := <-connects:
		if host != strings.TrimPrefix(target.URL, "https://") {
			t.Fatalf("CONNECT host = %q", host)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy CONNECT not observed")
	}
}

func TestTransportProxyAndHostOverride(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]string{r.RequestURI, r.Host, r.Header.Get("Proxy-Authorization")})
	}))
	defer proxy.Close()
	c := transportClient(t)
	c.CurlTransport.Proxy = strings.Replace(proxy.URL, "http://", "http://user:pass@", 1)
	c.CurlTransport.CurlOptions = map[Option]any{OptNoProxy: ""}
	r, _ := http.NewRequest("GET", "http://example.test/resource?q=1", nil)
	r.Host = "override.example"
	data := doBytes(t, c, r)
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	// Go's HTTP server uses the absolute proxy request-target's authority as
	// Request.Host. Check the actual Host override on a direct request below.
	if len(values) != 3 || values[0] != "http://example.test/resource?q=1" || values[1] != "example.test" || values[2] != "Basic dXNlcjpwYXNz" {
		t.Fatalf("proxy request = %v", values)
	}
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host) }))
	defer direct.Close()
	c.CurlTransport.Proxy = ""
	r, _ = http.NewRequest("GET", direct.URL, nil)
	r.Host = "override.example"
	if data := doBytes(t, c, r); string(data) != "override.example" {
		t.Fatalf("direct Host override = %q", data)
	}
}

func TestTransportOrderedHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lines := make(chan []string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		var got []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
			got = append(got, strings.TrimSpace(line))
		}
		lines <- got
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	c := transportClient(t)
	disabled := false
	c.CurlTransport.DefaultHeaders = &disabled
	r, _ := http.NewRequest("GET", "http://"+listener.Addr().String(), nil)
	r.Header.Set("X-Z", "old")
	r.Header.Set("X-A", "sorted")
	r = WithOrderedHeaders(r, []Header{{"X-Z", "first"}, {"X-B", "second"}, {"X-Z", "third"}, {"X-Empty", ""}})
	_ = doBytes(t, c, r)
	got := <-lines
	first, second, third, last := -1, -1, -1, -1
	for i, line := range got {
		switch line {
		case "X-Z: first":
			first = i
		case "X-B: second":
			second = i
		case "X-Z: third":
			third = i
		case "X-A: sorted":
			last = i
		}
	}
	if !(first >= 0 && first < second && second < third && third < last) {
		t.Fatalf("header order = %v", got)
	}
	emptySeen := false
	for _, line := range got {
		if line == "X-Empty:" {
			emptySeen = true
		}
	}
	if !emptySeen {
		t.Fatalf("ordered empty header missing: %v", got)
	}
}

func TestTransportLimitsAndInvalidRequestHeaders(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 4096))
		_, _ = io.Copy(w, r.Body)
	}))
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.MaxRequestBodyBytes = 4
	_, err := c.Post(s.URL, "text/plain", strings.NewReader("too long"))
	if err == nil || !strings.Contains(err.Error(), "MaxRequestBodyBytes") {
		t.Fatalf("upload limit = %v", err)
	}
	c.CurlTransport.MaxRequestBodyBytes = 0
	c.CurlTransport.MaxResponseHeaderBytes = 100
	_, err = c.Get(s.URL)
	if err == nil {
		t.Fatal("oversize response headers accepted")
	}
	c.CurlTransport.MaxResponseHeaderBytes = 0
	r, _ := http.NewRequest("GET", s.URL, nil)
	r.Header.Set("X-Test", "value\r\nInjected: yes")
	_, err = c.Do(r)
	if err == nil || !strings.Contains(err.Error(), "invalid request header") {
		t.Fatalf("invalid header = %v", err)
	}
}

func TestTransportUploadCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer s.Close()
	c := transportClient(t)
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", s.URL, reader)
	start := time.Now()
	_, err := c.Do(r)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("upload cancellation = %v after %v", err, time.Since(start))
	}
}

func TestTransportBodyReaderErrors(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer s.Close()
	c := transportClient(t)
	sentinel := errors.New("reader failed")
	r, _ := http.NewRequest("POST", s.URL, transportErrorReader{sentinel})
	_, err := c.Do(r)
	if err == nil {
		t.Fatal("upload reader error was discarded")
	}
}

type transportErrorReader struct{ err error }

func (r transportErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestTransportPerRequestProfile(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Header.Get("User-Agent")) }))
	defer s.Close()
	c := transportClient(t)
	r, _ := http.NewRequest("GET", s.URL, nil)
	r = WithProfile(r, Firefox)
	if data := doBytes(t, c, r); !strings.Contains(string(data), "Firefox/") {
		t.Fatalf("Firefox UA = %q", data)
	}
	if data := getBytes(t, c, s.URL); !strings.Contains(string(data), "Chrome/") {
		t.Fatalf("Chrome UA = %q", data)
	}
}

func TestTransportProfileConnectionCachesArePartitioned(t *testing.T) {
	type connectionKey struct{}
	var connections atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%d|%s", r.Context().Value(connectionKey{}), r.Header.Get("User-Agent"))
	}))
	s.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connectionKey{}, connections.Add(1))
	}
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	c := transportClient(t)
	c.CurlTransport.InsecureSkipVerify = true
	c.CurlTransport.MaxHandles = 2
	var ids []string
	for _, profile := range []Profile{Chrome, Firefox, Chrome, Firefox} {
		r, _ := http.NewRequest("GET", s.URL, nil)
		data := doBytes(t, c, WithProfile(r, profile))
		id, agent, _ := strings.Cut(string(data), "|")
		ids = append(ids, id)
		if profile == Chrome && !strings.Contains(agent, "Chrome/") || profile == Firefox && !strings.Contains(agent, "Firefox/") {
			t.Fatalf("profile %s UA = %q", profile, agent)
		}
	}
	if ids[0] == ids[1] || ids[0] != ids[2] || ids[1] != ids[3] {
		t.Fatalf("Chrome/Firefox connection IDs = %v", ids)
	}
}

func getBytes(t *testing.T, c *Client, url string) []byte {
	t.Helper()
	response, err := c.Get(url)
	return responseBytes(t, response, err)
}
func postBytes(t *testing.T, c *Client, url, contentType string, body io.Reader) []byte {
	t.Helper()
	response, err := c.Post(url, contentType, body)
	return responseBytes(t, response, err)
}
func doBytes(t *testing.T, c *Client, request *http.Request) []byte {
	t.Helper()
	response, err := c.Do(request)
	return responseBytes(t, response, err)
}
func postFormBytes(t *testing.T, c *Client, url string, form url.Values) []byte {
	t.Helper()
	response, err := c.PostForm(url, form)
	return responseBytes(t, response, err)
}
