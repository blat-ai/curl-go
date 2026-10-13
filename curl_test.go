package curlgo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func lowCurl(t *testing.T) *Curl {
	t.Helper()
	c, e := NewCurl()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func lowSet(t *testing.T, c *Curl, o Option, v any) {
	t.Helper()
	if e := c.SetOpt(o, v); e != nil {
		t.Fatal(e)
	}
}
func lowInfo(t *testing.T, c *Curl, i Info) any {
	t.Helper()
	v, e := c.GetInfo(i)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestCurlVersionAndNativeIdentity(t *testing.T) {
	v, e := Version()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(v, "IMPERSONATE") || !strings.Contains(v, "BoringSSL") || !strings.Contains(v, "nghttp2") || !strings.Contains(v, "ngtcp2") {
		t.Fatalf("unexpected native build: %s", v)
	}
}
func TestCurlBinaryPostAndTypedInfo(t *testing.T) {
	payload := []byte{'a', 0, 'b', 255}
	want := append([]byte{}, payload...)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || !bytes.Equal(b, want) || r.Header.Get("X-Test") != "yes" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(201)
		w.Write(b)
	}))
	defer server.Close()
	c := lowCurl(t)
	var body, headers bytes.Buffer
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptPostFields, payload)
	lowSet(t, c, OptHTTPHeader, []string{"X-Test: yes"})
	lowSet(t, c, OptWriteData, &body)
	lowSet(t, c, OptHeaderData, &headers)
	payload[0] = 'z' // Native bytes must survive caller mutation.
	if e := c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(body.Bytes(), want) || !strings.Contains(headers.String(), "X-Reply: yes") {
		t.Fatalf("body %x headers %s", body.Bytes(), headers.String())
	}
	if lowInfo(t, c, InfoResponseCode) != int64(201) || lowInfo(t, c, InfoEffectiveURL) != server.URL+"/" || lowInfo(t, c, InfoHTTPVersion) != int64(HTTPVersion1_1) || lowInfo(t, c, InfoSizeDownloadT) != int64(len(payload)) {
		t.Fatal("unexpected getinfo values")
	}
	if lowInfo(t, c, InfoTotalTime).(float64) <= 0 || lowInfo(t, c, InfoTotalTimeT).(int64) <= 0 {
		t.Fatal("missing timings")
	}
	if lowInfo(t, c, InfoPrimaryIP) != "127.0.0.1" {
		t.Fatal("missing primary IP")
	}
}
func TestCurlRepeatedHeaderReplacementAfterError(t *testing.T) {
	count := make(chan int, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(100 * time.Millisecond)
			return
		}
		count <- len(r.Header.Values("Foo"))
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	c := lowCurl(t)
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptURL, server.URL+"/slow")
	lowSet(t, c, OptTimeoutMS, 20)
	lowSet(t, c, OptHTTPHeader, []string{"Foo: old"})
	var ce *CurlError
	if e := c.Perform(context.Background()); !errors.As(e, &ce) || ce.Code != CurlECode_OPERATION_TIMEDOUT || !ce.Timeout() {
		t.Fatalf("timeout error: %v", e)
	}
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptTimeoutMS, 1000)
	lowSet(t, c, OptHTTPHeader, []string{"Foo: new"})
	if e := c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if n := <-count; n != 1 {
		t.Fatalf("duplicate headers %d", n)
	}
}
func TestCurlRedirectCookiesAndDuplicate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.SetCookie(w, &http.Cookie{Name: "foo", Value: "bar", Path: "/"})
			http.Redirect(w, r, "/done", 302)
			return
		}
		fmt.Fprint(w, r.Header.Get("Cookie"))
	}))
	defer server.Close()
	c := lowCurl(t)
	var b bytes.Buffer
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptURL, server.URL+"/redirect")
	lowSet(t, c, OptCookieFile, "")
	lowSet(t, c, OptFollowLocation, true)
	lowSet(t, c, OptWriteFunction, &b)
	if e := c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if b.String() != "foo=bar" || lowInfo(t, c, InfoRedirectCount) != int64(1) || lowInfo(t, c, InfoEffectiveURL) != server.URL+"/done" {
		t.Fatal("redirect/cookie behavior incorrect")
	}
	cookies := lowInfo(t, c, InfoCookieList).([]string)
	if len(cookies) != 1 || !strings.HasSuffix(cookies[0], "foo\tbar") {
		t.Fatal(cookies)
	}
	history := lowInfo(t, c, InfoRedirectHistory).([]string)
	if !reflect.DeepEqual(history, []string{"302\t" + server.URL + "/redirect"}) {
		t.Fatal(history)
	}
	duplicate, e := c.Duplicate()
	if e != nil {
		t.Fatal(e)
	}
	defer duplicate.Close()
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	b.Reset()
	if e := duplicate.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if b.String() != "foo=bar" {
		t.Fatal("duplicate independent options failed")
	}
}
func TestCurlResetAndConnectionReuse(t *testing.T) {
	var conns atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Foo") != "" {
			http.Error(w, "stale request config", 400)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	c := lowCurl(t)
	for i := 0; i < 3; i++ {
		if e := c.Reset(); e != nil {
			t.Fatal(e)
		}
		lowSet(t, c, OptProxy, "")
		lowSet(t, c, OptURL, server.URL)
		if e := c.Perform(context.Background()); e != nil {
			t.Fatal(e)
		}
		if lowInfo(t, c, InfoResponseCode) != int64(200) {
			t.Fatal("stale reset state")
		}
	}
	if conns.Load() != 1 {
		t.Fatalf("expected connection reuse; got %d connections", conns.Load())
	}
}
func TestCurlUploadAndCallbackErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, e := io.ReadAll(r.Body)
		if e == nil {
			w.Write(data)
		}
	}))
	defer server.Close()
	c := lowCurl(t)
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptUpload, true)
	payload := []byte("streamed\x00bytes")
	lowSet(t, c, OptInFileSizeLarge, len(payload))
	lowSet(t, c, OptReadFunction, bytes.NewReader(payload))
	var b bytes.Buffer
	lowSet(t, c, OptWriteFunction, &b)
	if e := c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b.Bytes(), payload) {
		t.Fatal(b.Bytes())
	}
	sentinel := errors.New("reader failed")
	lowSet(t, c, OptReadFunction, ReadFunc(func([]byte) (int, error) { return 0, sentinel }))
	lowSet(t, c, OptInFileSizeLarge, -1)
	if e := c.Perform(context.Background()); !errors.Is(e, sentinel) {
		t.Fatalf("lost reader error: %v", e)
	}
	c.Reset()
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptWriteFunction, WriteFunc(func([]byte) (int, error) { return 0, sentinel }))
	lowSet(t, c, OptPostFields, "hello")
	if e := c.Perform(context.Background()); !errors.Is(e, sentinel) {
		t.Fatalf("lost writer error: %v", e)
	}
	lowSet(t, c, OptWriteFunction, WriteFunc(func(p []byte) (int, error) { return 0, nil }))
	if e := c.Perform(context.Background()); !errors.Is(e, io.ErrShortWrite) {
		t.Fatalf("short write: %v", e)
	}
	lowSet(t, c, OptWriteFunction, WriteFunc(func(p []byte) (int, error) { panic("intentional") }))
	if e := c.Perform(context.Background()); e == nil || !strings.Contains(e.Error(), "callback panicked: intentional") {
		t.Fatalf("panic propagation: %v", e)
	}
}
func TestCurlContextCancellationAndRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	c := lowCurl(t)
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptURL, server.URL+"/slow")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e := c.Perform(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancellation not prompt")
	}
	lowSet(t, c, OptURL, server.URL)
	if e := c.Perform(context.Background()); e != nil {
		t.Fatalf("handle did not recover: %v", e)
	}
}

func TestCurlUploadZeroLengthReadIsNotEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }))
	defer server.Close()
	c := lowCurl(t)
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptUpload, true)
	lowSet(t, c, OptInFileSizeLarge, -1)
	calls := 0
	payload := strings.NewReader("payload")
	lowSet(t, c, OptReadFunction, ReadFunc(func(p []byte) (int, error) {
		calls++
		if calls%2 == 1 {
			return 0, nil
		}
		return payload.Read(p)
	}))
	var b bytes.Buffer
	lowSet(t, c, OptWriteFunction, &b)
	if e := c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if b.String() != "payload" {
		t.Fatalf("empty read truncated upload: %q", b.String())
	}
	lowSet(t, c, OptReadFunction, ReadFunc(func([]byte) (int, error) { return 0, nil }))
	if e := c.Perform(context.Background()); !errors.Is(e, io.ErrNoProgress) {
		t.Fatalf("nonprogressing reader error: %v", e)
	}
}
func TestCurlValidationAndClosedHandle(t *testing.T) {
	c := lowCurl(t)
	for _, v := range []struct {
		o Option
		v any
	}{{OptURL, "http://x\x00evil"}, {OptHTTPHeader, []string{"X: x\r\nEvil: y"}}, {OptTimeoutMS, "1"}, {CurlOpt_PRIVATE, "unsafe"}, {CurlOpt_SSL_CTX_FUNCTION, 123}, {OptTimeoutMS, uint64(1 << 63)}, {OptPostFields, 10}} {
		if e := c.SetOpt(v.o, v.v); e == nil {
			t.Fatalf("accepted invalid %#v", v)
		}
	}
	if e := c.SetOpt(Option(999999), 1); e == nil {
		t.Fatal("accepted unknown option")
	}
	if e := c.Impersonate("unknown", true); e == nil {
		t.Fatal("accepted unknown profile")
	}
	if n := lowInfo(t, c, InfoActiveSocket); n != int64(-1) {
		t.Fatal(n)
	}
	c.Close()
	c.Close()
	if e := c.SetOpt(OptURL, "x"); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if e := c.Perform(context.Background()); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if _, e := c.GetInfo(InfoResponseCode); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if e := c.Reset(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}

func TestCurlReplacingLargeBodiesRetainsCurrentConfiguration(t *testing.T) {
	c := lowCurl(t)
	for i := 0; i < 100; i++ {
		lowSet(t, c, OptPostFields, bytes.Repeat([]byte{byte(i)}, 64<<10))
	}
	if len(c.allocations) != 1 {
		t.Fatalf("retained %d superseded request bodies", len(c.allocations))
	}
	expected := bytes.Repeat([]byte{99}, 64<<10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !bytes.Equal(b, expected) {
			http.Error(w, "old body", 400)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	lowSet(t, c, OptProxy, "")
	lowSet(t, c, OptURL, server.URL)
	d, e := c.Duplicate()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	c.Close()
	if e = d.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if lowInfo(t, d, InfoResponseCode) != int64(200) {
		t.Fatal("duplicated stale configuration")
	}
}

func TestCurlDuplicateAfterMimeDetached(t *testing.T) {
	c := lowCurl(t)
	m, e := c.NewMime()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.AddPart(MimePart{Name: "foo", Data: []byte("bar")}); e != nil {
		t.Fatal(e)
	}
	lowSet(t, c, OptMIMEPost, m)
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	duplicate, e := c.Duplicate()
	if e != nil {
		t.Fatalf("detached MIME blocked duplication: %v", e)
	}
	duplicate.Close()
}

func TestCurlDuplicatePreservesNativeBodyStateAndSizes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }))
	defer server.Close()
	for _, test := range []struct {
		name string
		copy bool
		size int64
		want []byte
	}{{"binary", false, 4, []byte{'a', 0, 'b', 'c'}}, {"short", false, 3, []byte{'a', 0, 'b'}}, {"strlen", false, -1, []byte{'a'}}, {"copied", true, 4, []byte{'z', 0, 'y', 'x'}}} {
		t.Run(test.name, func(t *testing.T) {
			c := lowCurl(t)
			lowSet(t, c, OptURL, server.URL)
			lowSet(t, c, OptProxy, "")
			lowSet(t, c, OptPostFields, []byte{'a', 0, 'b', 'c'})
			if test.copy {
				lowSet(t, c, OptCopyPostFields, []byte{'z', 0, 'y', 'x'})
			}
			if e := c.SetOpt(OptPostFieldSize, 1000); e == nil {
				t.Fatal("accepted buffer overread")
			}
			if e := c.SetOpt(OptPostFieldSizeLarge, 1000); e == nil {
				t.Fatal("accepted large buffer overread")
			}
			lowSet(t, c, OptPostFieldSizeLarge, test.size)
			var body bytes.Buffer
			lowSet(t, c, OptWriteFunction, &body)
			d, e := c.Duplicate()
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			c.Close()
			if e = d.Perform(context.Background()); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(body.Bytes(), test.want) {
				t.Fatalf("copied body=%x want=%x", body.Bytes(), test.want)
			}
		})
	}
}

func TestCurlDuplicatePreservesMethodAfterBodyRebinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%s", r.Method, body)
	}))
	defer server.Close()
	for _, test := range []struct {
		name    string
		options []struct {
			o Option
			v any
		}
		want string
	}{
		{"get", []struct {
			o Option
			v any
		}{{OptHTTPGet, true}}, "GET|"},
		{"post-disabled", []struct {
			o Option
			v any
		}{{OptPost, false}}, "GET|"},
		{"head-disabled", []struct {
			o Option
			v any
		}{{OptNoBody, true}, {OptNoBody, false}}, "GET|"},
		{"upload", []struct {
			o Option
			v any
		}{{OptUpload, true}, {OptReadFunction, strings.NewReader("stream")}, {OptInFileSizeLarge, 6}}, "PUT|stream"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := lowCurl(t)
			lowSet(t, c, OptURL, server.URL)
			lowSet(t, c, OptProxy, "")
			lowSet(t, c, OptPostFields, "old body")
			for _, o := range test.options {
				lowSet(t, c, o.o, o.v)
			}
			var out bytes.Buffer
			lowSet(t, c, OptWriteFunction, &out)
			d, e := c.Duplicate()
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			c.Close()
			if e = d.Perform(context.Background()); e != nil {
				t.Fatal(e)
			}
			if out.String() != test.want {
				t.Fatalf("duplicate request=%q want=%q", out.String(), test.want)
			}
		})
	}
}

func TestCurlDuplicatePreservesLatestBrowserBaseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Old") != "" || !strings.Contains(r.Header.Get("User-Agent"), "Chrome/150") {
			http.Error(w, "stale base headers", 400)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	c := lowCurl(t)
	lowSet(t, c, OptHTTPBaseHeader, []string{"Old: x"})
	if e := c.Impersonate("chrome", true); e != nil {
		t.Fatal(e)
	}
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptProxy, "")
	d, e := c.Duplicate()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	c.Close()
	if e = d.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if lowInfo(t, d, InfoResponseCode) != int64(200) {
		t.Fatal("duplicate replaced current browser headers")
	}
}
func TestNativeMimeBrowserBoundaryAndFile(t *testing.T) {
	payload := []byte{'x', 0, 255}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Content-Type"), "WebKitFormBoundary") {
			http.Error(w, "wrong profile boundary", 400)
			return
		}
		if e := r.ParseMultipartForm(1 << 20); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		defer r.MultipartForm.RemoveAll()
		if r.FormValue("foo") != "bar" {
			http.Error(w, "missing field", 400)
			return
		}
		f, h, e := r.FormFile("file")
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		defer f.Close()
		b, _ := io.ReadAll(f)
		if h.Filename != "test.bin" || !bytes.Equal(b, payload) {
			http.Error(w, "bad file", 400)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	c := lowCurl(t)
	if e := c.Impersonate("chrome", true); e != nil {
		t.Fatal(e)
	}
	m, e := c.NewMime()
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if e = m.AddPart(MimePart{Name: "foo", Data: []byte("bar")}); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "data.bin")
	if e = os.WriteFile(file, payload, 0600); e != nil {
		t.Fatal(e)
	}
	if e = m.AddPart(MimePart{Name: "file", Filename: "test.bin", ContentType: "application/octet-stream", LocalPath: file}); e != nil {
		t.Fatal(e)
	}
	lowSet(t, c, OptMIMEPost, m)
	lowSet(t, c, OptURL, server.URL)
	lowSet(t, c, OptProxy, "")
	var b bytes.Buffer
	lowSet(t, c, OptWriteFunction, &b)
	if e = c.Perform(context.Background()); e != nil {
		t.Fatal(e)
	}
	if lowInfo(t, c, InfoResponseCode) != int64(200) || b.String() != "ok" {
		t.Fatalf("MIME response: %s", b.String())
	}
	if e = m.AddPart(MimePart{Name: "x", LocalPath: file, Data: []byte("x")}); e == nil {
		t.Fatal("ambiguous MIME source")
	}
	if _, e = c.Duplicate(); e == nil {
		t.Fatal("duplicated form ownership")
	}
	c.Close()
	m.Close()
	if e = m.AddPart(MimePart{Name: "x"}); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}
