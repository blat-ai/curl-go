package curlgo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrTransportClosed is returned when a request uses a closed Transport.
var ErrTransportClosed = errors.New("curlgo: transport is closed")

// Header is a single HTTP header. Repeated names retain their relative order.
type Header struct {
	Name  string
	Value string
}

type orderedHeadersKey struct{}
type requestProfileKey struct{}

// WithOrderedHeaders copies request and its Header map, replaces the listed
// headers' values, and records their wire order. Unlisted headers follow in
// sorted order. Later Header changes, redirect filtering, and cookie-jar updates
// remain authoritative; the context retains order, never credential values.
// An empty string sends an explicitly empty field. Setting a Header value slice
// to nil instead suppresses the corresponding native browser default.
func WithOrderedHeaders(request *http.Request, headers []Header) *http.Request {
	order := make([]string, 0, len(headers))
	copy := request.WithContext(request.Context())
	copy.Header = request.Header.Clone()
	if copy.Header == nil {
		copy.Header = make(http.Header)
	}
	replaced := make(map[string]bool)
	for _, header := range headers {
		lower := strings.ToLower(header.Name)
		if !replaced[lower] {
			for name := range copy.Header {
				if strings.EqualFold(name, header.Name) {
					delete(copy.Header, name)
				}
			}
			replaced[lower] = true
		}
		copy.Header.Add(header.Name, header.Value)
		order = append(order, header.Name)
	}
	return copy.WithContext(context.WithValue(request.Context(), orderedHeadersKey{}, order))
}

// WithProfile returns a shallow copy of request using a different browser profile.
func WithProfile(request *http.Request, profile Profile) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), requestProfileKey{}, profile))
}

// Transport implements http.RoundTripper using curl-impersonate. Its zero value
// uses the default Chrome profile. Configure fields before its first use; a
// Transport can then be shared by concurrent goroutines. Each native easy handle
// owns a reusable connection cache. Responses and uploads are streamed.
type Transport struct {
	Profile Profile
	// DefaultHeaders defaults to true; false disables browser default headers.
	DefaultHeaders *bool
	Fingerprint    Fingerprint
	// Proxy is a libcurl proxy URL, including http(s), socks4 or socks5 schemes.
	// The empty value disables proxy environment variables.
	Proxy string
	// ProxyFunc, when provided, selects a proxy for each request. A nil URL uses
	// a direct connection. It takes precedence over Proxy.
	ProxyFunc          func(*http.Request) (*url.URL, error)
	InsecureSkipVerify bool
	CAFile             string
	CAPath             string
	ClientCertFile     string
	ClientKeyFile      string
	ClientKeyPassword  string
	Interface          string
	// Timeout limits the complete transfer, including reading its response body.
	Timeout        time.Duration
	ConnectTimeout time.Duration
	// MaxHandles bounds concurrent transfers and pooled connections; default 10.
	MaxHandles         int
	DisableKeepAlives  bool
	DisableCompression bool
	// MaxResponseHeaderBytes defaults to 1 MiB. A negative value disables the limit.
	MaxResponseHeaderBytes int64
	// MaxRequestBodyBytes, when positive, buffers and bounds uploads.
	MaxRequestBodyBytes int64
	// CurlOptions override native options after browser impersonation. Options
	// that replace transport callbacks or enable native redirects are rejected.
	CurlOptions map[Option]any

	mu             sync.Mutex
	idle           []*Curl
	active         map[*Curl]context.CancelFunc
	handleProfiles map[*Curl]Profile
	changed        chan struct{}
	closed         bool
	workers        sync.WaitGroup
}

var _ http.RoundTripper = (*Transport)(nil)

func (t *Transport) initLocked() {
	if t.changed == nil {
		t.changed = make(chan struct{})
		t.active = make(map[*Curl]context.CancelFunc)
		if t.handleProfiles == nil {
			t.handleProfiles = make(map[*Curl]Profile)
		}
	}
}

func (t *Transport) signalLocked() { close(t.changed); t.changed = make(chan struct{}) }

func (t *Transport) acquire(ctx context.Context, cancel context.CancelFunc, profile Profile) (*Curl, error) {
	for {
		t.mu.Lock()
		t.initLocked()
		if t.closed {
			t.mu.Unlock()
			return nil, ErrTransportClosed
		}
		if err := ctx.Err(); err != nil {
			t.mu.Unlock()
			return nil, err
		}
		limit := t.MaxHandles
		if limit == 0 {
			limit = 10
		}
		if limit < 0 {
			t.mu.Unlock()
			return nil, errors.New("curlgo: MaxHandles must not be negative")
		}
		var c *Curl
		for i := len(t.idle) - 1; i >= 0; i-- {
			if t.handleProfiles[t.idle[i]] == profile {
				c = t.idle[i]
				t.idle = append(t.idle[:i], t.idle[i+1:]...)
				break
			}
		}
		if c == nil && len(t.active) < limit {
			// Browser changes need a new TLS/HTTP2 connection cache. Evict an
			// idle handle of another profile rather than repurposing its cache.
			if len(t.idle)+len(t.active) >= limit && len(t.idle) > 0 {
				old := t.idle[0]
				t.idle = t.idle[1:]
				delete(t.handleProfiles, old)
				_ = old.Close()
			}
			var err error
			c, err = NewCurl()
			if err != nil {
				t.mu.Unlock()
				return nil, err
			}
			t.handleProfiles[c] = profile
		}
		if c != nil {
			t.active[c] = cancel
			t.workers.Add(1)
			t.mu.Unlock()
			return c, nil
		}
		changed := t.changed
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (t *Transport) release(c *Curl) {
	// Reset drops request-owned pointers but retains libcurl's connection cache.
	err := c.Reset()
	t.mu.Lock()
	delete(t.active, c)
	closeHandle := t.closed || t.DisableKeepAlives || err != nil
	if !closeHandle {
		t.idle = append(t.idle, c)
	} else {
		delete(t.handleProfiles, c)
	}
	t.signalLocked()
	t.mu.Unlock()
	if closeHandle {
		_ = c.Close()
	}
	t.workers.Done()
}

// CloseIdleConnections releases all currently idle native handles. In-flight
// requests continue and the transport remains usable.
func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	t.initLocked()
	idle := t.idle
	t.idle = nil
	for _, c := range idle {
		delete(t.handleProfiles, c)
	}
	t.mu.Unlock()
	for _, c := range idle {
		_ = c.Close()
	}
}

// Close cancels active requests, releases the native pool and waits for callbacks
// to finish. It is safe to call more than once. Close response bodies promptly.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.initLocked()
	t.closed = true
	idle := t.idle
	t.idle = nil
	for _, c := range idle {
		delete(t.handleProfiles, c)
	}
	for _, cancel := range t.active {
		cancel()
	}
	t.signalLocked()
	t.mu.Unlock()
	var result error
	for _, c := range idle {
		result = errors.Join(result, c.Close())
	}
	t.workers.Wait()
	return result
}

// RoundTrip executes a single HTTP request. Redirects, cookies and authentication
// from URL credentials are handled by the containing http.Client.
func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, errors.New("curlgo: nil request")
	}
	uploadBody := request.Body
	requestBodyOwned := true
	defer func() {
		if requestBodyOwned && uploadBody != nil {
			_ = uploadBody.Close()
		}
	}()
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return nil, errors.New("curlgo: only http and https request URLs are supported")
	}
	if request.URL.Host == "" {
		return nil, errors.New("curlgo: request URL has no host")
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if t.Timeout < 0 || t.ConnectTimeout < 0 || t.MaxRequestBodyBytes < 0 {
		return nil, errors.New("curlgo: timeouts and request body limits must not be negative")
	}
	ctx, cancel := context.WithCancel(request.Context())
	if t.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, t.Timeout)
		outerCancel := cancel
		cancel = func() { timeoutCancel(); outerCancel() }
	}
	profile, err := t.requestProfile(request)
	if err != nil {
		cancel()
		return nil, err
	}
	c, err := t.acquire(ctx, cancel, profile)
	if err != nil {
		cancel()
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			cancel()
			t.release(c)
		}
	}()

	// Native authentication retries rewind through GetBody without buffering.
	// Keep ownership of reopened bodies here so cancellation unblocks their reads.
	_, uploadSeekable := uploadBody.(io.Seeker)
	if uploadBody != nil && uploadBody != http.NoBody && !uploadSeekable && request.GetBody != nil && t.MaxRequestBodyBytes == 0 {
		uploadBody = &replayableRequestBody{body: uploadBody, getBody: request.GetBody}
	}
	// Closing the current upload body unblocks readers if a deadline expires.
	uploadDone := make(chan struct{})
	if uploadBody != nil && uploadBody != http.NoBody {
		go func() {
			select {
			case <-ctx.Done():
				_ = uploadBody.Close()
			case <-uploadDone:
			}
		}()
	}
	uploadOwned := true
	defer func() {
		if uploadOwned {
			close(uploadDone)
		}
	}()

	reader, writer := io.Pipe()
	parser := newResponseHeaders(request, t.MaxResponseHeaderBytes)
	var observer *transferObserver
	originAuth, _ := integerValue(t.CurlOptions[OptHTTPAuth])
	proxyAuth, _ := integerValue(t.CurlOptions[OptProxyAuth])
	if originAuth != 0 || proxyAuth != 0 {
		parser.nativeRedirectCount = func() (int64, error) { return c.getInfoLongLocked(InfoRedirectCount) }
		verbose, _ := integerValue(t.CurlOptions[OptVerbose])
		observer = &transferObserver{debug: parser.observeNative, afterStep: parser.afterNativeStep, verbose: verbose != 0}
	}
	decompress, err := t.configure(c, request, parser, responseBodyWriter{headers: parser, writer: writer}, uploadBody)
	if err != nil {
		reader.Close()
		writer.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	owned = false
	uploadOwned = false
	requestBodyOwned = false
	transferDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = writer.CloseWithError(ctx.Err())
		case <-transferDone:
		}
	}()
	go func() {
		err := c.perform(ctx, observer)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		parser.finish(err)
		close(uploadDone)
		if uploadBody != nil {
			_ = uploadBody.Close()
		}
		t.release(c)
		_ = writer.CloseWithError(err)
		close(transferDone)
		cancel()
	}()
	var result responseResult
	select {
	case result = <-parser.ready:
	case <-ctx.Done():
		// A completed transfer also cancels our internal context. A ready
		// response takes priority over that internal cleanup cancellation.
		select {
		case result = <-parser.ready:
		default:
			_ = reader.CloseWithError(ctx.Err())
			return nil, ctx.Err()
		}
	}
	if result.err != nil {
		cancel()
		_ = reader.CloseWithError(result.err)
		return nil, result.err
	}
	response := result.response
	response.Body = &responseBody{reader: reader, cancel: cancel}
	if decompress && response.Header.Get("Content-Encoding") != "" {
		response.Header.Del("Content-Encoding")
		response.Header.Del("Content-Length")
		response.ContentLength = -1
		response.Uncompressed = true
	}
	return response, nil
}

type responseBody struct {
	reader *io.PipeReader
	cancel context.CancelFunc
	once   sync.Once
}

func (b *responseBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *responseBody) Close() error {
	var err error
	b.once.Do(func() { b.cancel(); err = b.reader.Close() })
	return err
}

func milliseconds(d time.Duration) int64 {
	value := int64(d / time.Millisecond)
	if d%time.Millisecond != 0 {
		value++
	}
	return value
}

func (t *Transport) configure(c *Curl, r *http.Request, headers io.Writer, body io.Writer, uploadBody io.Reader) (bool, error) {
	normalized, err := t.requestProfile(r)
	if err != nil {
		return false, err
	}
	defaults := t.DefaultHeaders == nil || *t.DefaultHeaders
	if err = c.Impersonate(string(normalized), defaults); err != nil {
		return false, err
	}
	if err = ApplyFingerprint(c, t.Fingerprint); err != nil {
		return false, err
	}
	set := func(o Option, v any) error {
		if err := c.SetOpt(o, v); err != nil {
			return fmt.Errorf("curlgo: configure option %d: %w", o, err)
		}
		return nil
	}
	proxyValue := t.Proxy
	if t.ProxyFunc != nil {
		proxy, err := t.ProxyFunc(r)
		if err != nil {
			return false, err
		}
		proxyValue = ""
		if proxy != nil {
			proxyValue = proxy.String()
		}
	}
	verifyHost := int64(2)
	if t.InsecureSkipVerify {
		verifyHost = 0
	}
	options := []struct {
		o Option
		v any
	}{
		{OptURL, r.URL.String()}, {OptFollowLocation, false}, {OptProxy, proxyValue},
		// Proxy/ProxyFunc already determine routing; environment NO_PROXY
		// must not silently bypass their explicit selection.
		{OptNoProxy, ""}, {OptPathAsIs, true},
		{OptSSLVerifyPeer, !t.InsecureSkipVerify}, {OptSSLVerifyHost, verifyHost},
		{OptHeaderFunction, headers}, {OptWriteFunction, body},
		{OptSuppressConnectHeaders, true},
	}
	if t.ConnectTimeout > 0 {
		options = append(options, struct {
			o Option
			v any
		}{OptConnectTimeoutMS, milliseconds(t.ConnectTimeout)})
	}
	for _, field := range []struct {
		o Option
		v string
	}{{OptCAInfo, t.CAFile}, {OptCAPath, t.CAPath}, {OptSSLCert, t.ClientCertFile}, {OptSSLKey, t.ClientKeyFile}, {OptKeyPasswd, t.ClientKeyPassword}, {OptInterface, t.Interface}} {
		if field.v != "" {
			options = append(options, struct {
				o Option
				v any
			}{field.o, field.v})
		}
	}
	if t.DisableKeepAlives {
		options = append(options, struct {
			o Option
			v any
		}{OptFreshConnect, true}, struct {
			o Option
			v any
		}{OptForbidReuse, true})
	}
	_, encodingProvided := requestHeaderValue(r, "Accept-Encoding")
	decompress := !t.DisableCompression && !encodingProvided
	if decompress {
		options = append(options, struct {
			o Option
			v any
		}{OptAcceptEncoding, ""})
	} else {
		options = append(options, struct {
			o Option
			v any
		}{OptAcceptEncoding, nil})
	}
	for _, option := range options {
		if err = set(option.o, option.v); err != nil {
			return false, err
		}
	}
	requestHeaderList := requestHeaders(r)
	if t.DisableCompression && !encodingProvided {
		requestHeaderList = append(requestHeaderList, "Accept-Encoding:")
	}
	if err = set(OptHTTPHeader, requestHeaderList); err != nil {
		return false, err
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	if r.Body != nil && r.Body != http.NoBody {
		var upload io.Reader = uploadBody
		length := r.ContentLength
		if length == 0 {
			length = -1
		}
		if t.MaxRequestBodyBytes > 0 {
			data, err := io.ReadAll(io.LimitReader(uploadBody, t.MaxRequestBodyBytes+1))
			if err != nil {
				return false, err
			}
			if int64(len(data)) > t.MaxRequestBodyBytes {
				return false, errors.New("curlgo: request body exceeds MaxRequestBodyBytes")
			}
			if r.ContentLength > 0 && r.ContentLength != int64(len(data)) {
				return false, fmt.Errorf("curlgo: ContentLength=%d but body has %d bytes", r.ContentLength, len(data))
			}
			upload = bytes.NewReader(data)
			length = int64(len(data))
		}
		if err = set(OptUpload, true); err != nil {
			return false, err
		}
		if err = set(OptInFileSizeLarge, length); err != nil {
			return false, err
		}
		if err = set(OptReadFunction, upload); err != nil {
			return false, err
		}
	} else if method == http.MethodPost {
		if err = set(OptPostFields, []byte{}); err != nil {
			return false, err
		}
	}
	if method == http.MethodHead {
		if err = set(OptNoBody, true); err != nil {
			return false, err
		}
	}
	if err = set(OptCustomRequest, method); err != nil {
		return false, err
	}
	keys := make([]int, 0, len(t.CurlOptions))
	for option := range t.CurlOptions {
		keys = append(keys, int(option))
	}
	sort.Ints(keys)
	for _, key := range keys {
		option := Option(key)
		switch option {
		case OptWriteFunction, OptWriteData, OptHeaderFunction, OptHeaderData, OptReadFunction, OptReadData, OptFollowLocation,
			OptURL, OptCustomRequest, OptNoBody, OptUpload, OptPost, OptPostFields, OptHTTPHeader, OptHTTPTransferDecoding:
			return false, fmt.Errorf("curlgo: option %d is managed by Transport", option)
		}
		if err = set(option, t.CurlOptions[option]); err != nil {
			return false, err
		}
		if option == OptAcceptEncoding {
			decompress = t.CurlOptions[option] != nil
		}
	}
	if setting, ok := t.CurlOptions[OptHTTPContentDecoding]; ok {
		numeric, _ := integerValue(setting)
		if numeric == 0 {
			decompress = false
		}
	}
	return decompress, nil
}

func requestHeaderValue(r *http.Request, name string) (string, bool) {
	for key, values := range r.Header {
		if strings.EqualFold(key, name) {
			if len(values) == 0 {
				return "", true
			}
			return values[0], true
		}
	}
	return "", false
}

func (t *Transport) requestProfile(r *http.Request) (Profile, error) {
	profile := t.Profile
	if override, ok := r.Context().Value(requestProfileKey{}).(Profile); ok {
		profile = override
	}
	if profile == "" {
		profile = Chrome
	}
	return NormalizeProfile(profile)
}

func requestHeaders(r *http.Request) []string {
	var result []string
	seen := make(map[string]bool)
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	type headerValues struct {
		name   string
		values []string
		next   int
	}
	groups := make(map[string]*headerValues, len(names))
	for _, name := range names {
		lower := strings.ToLower(name)
		if groups[lower] == nil {
			groups[lower] = &headerValues{name: name}
		}
		groups[lower].values = append(groups[lower].values, r.Header[name]...)
	}
	appendValue := func(name, value string) {
		if value == "" {
			result = append(result, name+";")
		} else {
			result = append(result, name+": "+value)
		}
	}
	if order, ok := r.Context().Value(orderedHeadersKey{}).([]string); ok {
		for _, name := range order {
			lower := strings.ToLower(name)
			group := groups[lower]
			if group == nil {
				continue // net/http or the caller removed this field.
			}
			if len(group.values) == 0 && !seen[lower] {
				result = append(result, name+":")
			} else if group.next < len(group.values) {
				appendValue(name, group.values[group.next])
				group.next++
			}
			seen[lower] = true
		}
	}
	visited := make(map[string]bool)
	for _, name := range names {
		lower := strings.ToLower(name)
		if visited[lower] {
			continue
		}
		visited[lower] = true
		group := groups[lower]
		if len(group.values) == 0 && !seen[lower] {
			result = append(result, group.name+":")
		}
		seen[lower] = true
		for group.next < len(group.values) {
			appendValue(group.name, group.values[group.next])
			group.next++
		}
	}
	if r.Host != "" && r.Host != r.URL.Host && !seen["host"] {
		result = append(result, "Host: "+r.Host)
	}
	if !seen["expect"] {
		result = append(result, "Expect:")
	}
	if !seen["content-type"] {
		result = append(result, "Content-Type:")
	}
	if r.Close && !seen["connection"] {
		result = append(result, "Connection: close")
	}
	return result
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func validateRequest(r *http.Request) error {
	if r.Method != "" && !validHeaderName(r.Method) {
		return errors.New("curlgo: invalid request method")
	}
	if r.ContentLength < -1 {
		return errors.New("curlgo: invalid request ContentLength")
	}
	if len(r.Trailer) != 0 {
		return errors.New("curlgo: request trailers are not supported")
	}
	if strings.ContainsAny(r.Host, "\r\n\x00") {
		return errors.New("curlgo: invalid request Host")
	}
	check := func(name, value string) error {
		if !validHeaderName(name) {
			return fmt.Errorf("curlgo: invalid request header name %q", name)
		}
		for _, c := range value {
			if c == '\r' || c == '\n' || c == 0 || (c < 32 && c != '\t') || c == 127 {
				return fmt.Errorf("curlgo: invalid request header value for %q", name)
			}
		}
		return nil
	}
	for name, values := range r.Header {
		for _, value := range values {
			if err := check(name, value); err != nil {
				return err
			}
		}
		if !validHeaderName(name) {
			return fmt.Errorf("curlgo: invalid request header name %q", name)
		}
	}
	return nil
}

type responseResult struct {
	response *http.Response
	err      error
}
type responseHeaders struct {
	request             *http.Request
	ready               chan responseResult
	response            *http.Response
	buffer              []byte
	limit               int64
	size                int64
	sent                bool
	headersComplete     bool
	lastHeader          string
	nativeRedirectCount func() (int64, error)
	responseRedirects   int64
	nativeIgnoresBody   bool
}

// Native authentication may replace a challenge response before delivering any
// body. A body callback also establishes that the pending response is final.
type responseBodyWriter struct {
	headers *responseHeaders
	writer  io.Writer
}

func (w responseBodyWriter) Write(p []byte) (int, error) {
	if !w.headers.sent {
		if !w.headers.headersComplete || w.headers.response == nil {
			return 0, errors.New("curlgo: received body without complete HTTP response headers")
		}
		w.headers.publish()
	}
	return w.writer.Write(p)
}

func newResponseHeaders(r *http.Request, limit int64) *responseHeaders {
	if limit == 0 {
		limit = 1 << 20
	}
	return &responseHeaders{request: r, ready: make(chan responseResult, 1), limit: limit}
}

func (h *responseHeaders) Write(p []byte) (int, error) {
	h.size += int64(len(p))
	if h.limit > 0 && h.size > h.limit {
		return 0, errors.New("curlgo: response headers exceed MaxResponseHeaderBytes")
	}
	h.buffer = append(h.buffer, p...)
	for {
		i := bytes.IndexByte(h.buffer, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(h.buffer[:i+1]), "\r\n")
		h.buffer = h.buffer[i+1:]
		if err := h.line(line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (h *responseHeaders) line(line string) error {
	if strings.HasPrefix(line, "HTTP/") {
		if h.sent {
			return errors.New("curlgo: received another HTTP response after publishing response headers")
		}
		if h.nativeRedirectCount != nil {
			count, err := h.nativeRedirectCount()
			if err != nil {
				return err
			}
			h.responseRedirects = count
		}
		h.nativeIgnoresBody = false
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return errors.New("curlgo: malformed HTTP status line")
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 999 {
			return errors.New("curlgo: malformed HTTP status code")
		}
		proto := parts[0]
		if proto == "HTTP/2" {
			proto = "HTTP/2.0"
		}
		if proto == "HTTP/3" {
			proto = "HTTP/3.0"
		}
		major, minor, ok := http.ParseHTTPVersion(proto)
		if !ok {
			return fmt.Errorf("curlgo: malformed HTTP protocol %q", parts[0])
		}
		status := parts[1]
		if len(parts) == 3 && parts[2] != "" {
			status += " " + parts[2]
		} else if text := http.StatusText(code); text != "" {
			status += " " + text
		}
		h.response = &http.Response{Status: status, StatusCode: code, Proto: proto, ProtoMajor: major, ProtoMinor: minor, Header: make(http.Header), Trailer: make(http.Header), ContentLength: -1, Request: h.request}
		h.headersComplete = false
		h.lastHeader = ""
		return nil
	}
	if h.response == nil {
		return errors.New("curlgo: received header without status line")
	}
	if line == "" {
		if h.response.StatusCode >= 100 && h.response.StatusCode < 200 && h.response.StatusCode != 101 {
			h.response = nil
			return nil
		}
		if !h.headersComplete {
			if value := h.response.Header.Get("Content-Length"); value != "" {
				length, err := strconv.ParseInt(value, 10, 64)
				if err != nil || length < 0 {
					return errors.New("curlgo: invalid response Content-Length")
				}
				h.response.ContentLength = length
			}
			if strings.EqualFold(h.response.Header.Get("Transfer-Encoding"), "chunked") {
				h.response.TransferEncoding = []string{"chunked"}
				h.response.Header.Del("Transfer-Encoding")
				h.response.ContentLength = -1
			}
			h.response.Close = strings.EqualFold(h.response.Header.Get("Connection"), "close")
			h.headersComplete = true
			h.lastHeader = ""
			if h.nativeRedirectCount == nil {
				h.publish()
			}
		}
		return nil
	}
	if (line[0] == ' ' || line[0] == '\t') && h.lastHeader != "" {
		fields := h.response.Header
		if h.headersComplete {
			fields = h.response.Trailer
		}
		values := fields[h.lastHeader]
		values[len(values)-1] += " " + strings.TrimSpace(line)
		return nil
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return errors.New("curlgo: malformed response header")
	}
	name = http.CanonicalHeaderKey(name)
	value = strings.TrimSpace(value)
	if h.headersComplete {
		h.response.Trailer.Add(name, value)
	} else {
		h.response.Header.Add(name, value)
	}
	h.lastHeader = name
	return nil
}

func (h *responseHeaders) observeNative(kind DebugType, data []byte) {
	// In the pinned native release, http_firstwrite emits this after choosing
	// another exchange and before the last header callback. Observe only that
	// decision; caller diagnostics remain separately controlled by OptVerbose.
	if kind == DebugText && strings.TrimRight(string(data), "\r\n") == "Ignoring the response-body" {
		h.nativeIgnoresBody = true
	}
}

func (h *responseHeaders) afterNativeStep(transferError error) error {
	if h.sent || !h.headersComplete || h.response == nil || h.nativeIgnoresBody {
		return nil
	}
	var native *CurlError
	if errors.As(transferError, &native) {
		// These errors can abort a chosen reload before its epoch advances.
		// Keep the probe hidden and return the original native failure.
		switch native.Code {
		case CurlECode_TOO_MANY_REDIRECTS, CurlECode_SEND_FAIL_REWIND, CurlECode_OUT_OF_MEMORY:
			return nil
		}
		// FailOnError explicitly rejects authentication failures. Body errors,
		// such as malformed compression, keep the final response available.
		authStatus := h.response.StatusCode == http.StatusUnauthorized || h.response.StatusCode == http.StatusProxyAuthRequired
		if authStatus && native.Code == CurlECode_HTTP_RETURNED_ERROR {
			return nil
		}
	}
	count, err := h.nativeRedirectCount()
	if err != nil {
		return err
	}
	// Native curl increments this counter for authentication reloads as well as
	// redirects. With Connection: close it skips the ignore-body diagnostic but
	// completes the reload decision before returning from curl_multi_perform.
	if count == h.responseRedirects {
		h.publish()
	}
	return nil
}

func (h *responseHeaders) publish() {
	if !h.sent {
		h.sent = true
		h.ready <- responseResult{response: h.response}
	}
}

func (h *responseHeaders) finish(err error) {
	if h.sent {
		return
	}
	if err == nil {
		// HEAD, 204 and an empty final authentication failure have no body callback.
		if h.headersComplete && h.response != nil {
			h.publish()
			return
		}
		err = errors.New("curlgo: transfer completed without HTTP response headers")
	}
	h.sent = true
	h.ready <- responseResult{err: err}
}
