package curlgo

/*
#include "native.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"runtime/cgo"
	"strings"
	"sync"
	"unsafe"
)

var ErrClosed = errors.New("curlgo: handle is closed")

// CurlError retains curl's error code and diagnostic text. Callback errors and
// context cancellation are returned directly so errors.Is preserves their cause.
type CurlError struct {
	Code    ErrorCode
	Op      string
	Message string
}

func (e *CurlError) Error() string {
	return fmt.Sprintf("curlgo: %s: curl (%d): %s", e.Op, e.Code, e.Message)
}
func (e *CurlError) Timeout() bool   { return e.Code == CurlECode_OPERATION_TIMEDOUT }
func (e *CurlError) Temporary() bool { return e.Timeout() || e.Code == CurlECode_AGAIN }

// WriteFunc adapts a callback to io.Writer. Callback slices are independent copies.
type WriteFunc func([]byte) (int, error)

func (f WriteFunc) Write(p []byte) (int, error) { return f(p) }

type ReadFunc func([]byte) (int, error)

func (f ReadFunc) Read(p []byte) (int, error) { return f(p) }

type DebugType int

const (
	DebugText DebugType = iota
	DebugHeaderIn
	DebugHeaderOut
	DebugDataIn
	DebugDataOut
	DebugTLSDataIn
	DebugTLSDataOut
)

type DebugFunc func(DebugType, []byte)

type callbackState struct {
	body, header io.Writer
	reader       io.Reader
	seeker       io.Seeker
	debug        DebugFunc
	err          error
	ctx          context.Context
}
type nativeAllocation struct {
	ptr  unsafe.Pointer
	list bool
	size int
}

// Curl owns a native easy handle. Operations are serialized. Perform callbacks
// must not call methods on the same Curl. Call Close to release native resources.
type Curl struct {
	mu                sync.Mutex
	easy              unsafe.Pointer
	multi             unsafe.Pointer
	multiAttached     bool
	connectOnly       int64
	callbacks         *callbackState
	callbackHandle    cgo.Handle
	allocations       map[Option]nativeAllocation
	postFieldsMode    Option
	postFieldsLength  int64
	postFieldsHasData bool
	requestMethod     Option
	sslVersion        SSLVersion
	sslVersionSet     bool
	errorBuffer       unsafe.Pointer
	mimes             map[*Mime]bool
	attachedMime      *Mime
}

func NewCurl() (*Curl, error) {
	if err := ensureLibrary(); err != nil {
		return nil, err
	}
	easy := C.cg_easy_init()
	if easy == nil {
		return nil, errors.New("curlgo: curl_easy_init failed")
	}
	c := &Curl{easy: easy, callbacks: &callbackState{body: io.Discard, header: io.Discard}, allocations: make(map[Option]nativeAllocation), mimes: make(map[*Mime]bool)}
	c.resetSSLVersionTracking()
	c.callbackHandle = cgo.NewHandle(c.callbacks)
	c.multi = C.cg_multi_init()
	if c.multi == nil {
		c.Close()
		return nil, errors.New("curlgo: curl_multi_init failed")
	}
	c.errorBuffer = C.calloc(256, 1)
	if c.errorBuffer == nil {
		c.Close()
		return nil, errors.New("curlgo: allocation failed")
	}
	if err := c.initialize(); err != nil {
		c.Close()
		return nil, err
	}
	runtime.SetFinalizer(c, func(c *Curl) { _ = c.Close() })
	return c, nil
}
func (c *Curl) initialize() error {
	if e := c.check(C.cg_callbacks(c.easy, C.uintptr_t(c.callbackHandle)), "callbacks"); e != nil {
		return e
	}
	if e := c.check(C.cg_setopt_ptr(c.easy, C.int(CurlOpt_ERRORBUFFER), c.errorBuffer), "error buffer"); e != nil {
		return e
	}
	if e := c.check(C.cg_setopt_long(c.easy, C.int(OptNoSignal), 1), "nosignal"); e != nil {
		return e
	}
	// Honor certificate bundle environment variables just as curl_cffi does.
	for _, key := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"} {
		if p := os.Getenv(key); p != "" {
			if st, e := os.Stat(p); e == nil && !st.IsDir() {
				return c.setOptLocked(OptCAInfo, p, false)
			}
		}
	}
	return nil
}
func (c *Curl) check(code C.int, op string) error {
	if code == 0 {
		return nil
	}
	text := ""
	if c.errorBuffer != nil {
		text = C.GoString((*C.char)(c.errorBuffer))
	}
	if text == "" {
		text = C.GoString(C.cg_strerror(code))
	}
	return &CurlError{Code: ErrorCode(code), Op: op, Message: text}
}
func (c *Curl) clearError() {
	if c.errorBuffer != nil {
		*(*byte)(c.errorBuffer) = 0
	}
}
func (c *Curl) freeAllocation(opt Option) {
	if a, ok := c.allocations[opt]; ok {
		if a.list {
			C.cg_slist_free((*C.struct_curl_slist)(a.ptr))
		} else {
			C.free(a.ptr)
		}
		delete(c.allocations, opt)
	}
}
func (c *Curl) releaseAllocations() {
	for o := range c.allocations {
		c.freeAllocation(o)
	}
}

// SetOpt accepts integers/bools for numeric options, strings or []byte for
// string/blob options, []string for slists, io.Writer/io.Reader for callbacks,
// and *Mime for OptMIMEPost. Unsafe pointer and arbitrary C callback options are
// rejected rather than exposing Go pointers to native code.
func (c *Curl) SetOpt(opt Option, value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	return c.setOptLocked(opt, value, true)
}
func (c *Curl) setOptLocked(opt Option, value any, _ bool) error {
	c.clearError()
	var code C.int
	switch opt {
	case OptWriteData, OptWriteFunction, OptHeaderData, OptHeaderFunction:
		var w io.Writer
		switch v := value.(type) {
		case nil:
			w = io.Discard
		case io.Writer:
			w = v
		case func([]byte) (int, error):
			w = WriteFunc(v)
		default:
			return fmt.Errorf("curlgo: option %d requires io.Writer", opt)
		}
		if opt == OptHeaderData || opt == OptHeaderFunction {
			c.callbacks.header = w
		} else {
			c.callbacks.body = w
		}
	case OptReadData, OptReadFunction:
		var r io.Reader
		switch v := value.(type) {
		case nil:
			r = nil
		case io.Reader:
			r = v
		case func([]byte) (int, error):
			r = ReadFunc(v)
		default:
			return fmt.Errorf("curlgo: option %d requires io.Reader", opt)
		}
		c.callbacks.reader = r
		c.callbacks.seeker, _ = r.(io.Seeker)
	case OptSeekFunction, OptSeekData:
		if value == nil {
			c.callbacks.seeker = nil
		} else if s, ok := value.(io.Seeker); ok {
			c.callbacks.seeker = s
		} else {
			return fmt.Errorf("curlgo: option %d requires io.Seeker", opt)
		}
	case OptDebugFunction, OptDebugData:
		switch d := value.(type) {
		case nil:
			c.callbacks.debug = nil
		case DebugFunc:
			c.callbacks.debug = d
		case func(DebugType, []byte):
			c.callbacks.debug = d
		default:
			return errors.New("curlgo: debug callback requires DebugFunc")
		}
	case OptMIMEPost:
		var p unsafe.Pointer
		if value != nil {
			m, ok := value.(*Mime)
			if !ok || m == nil || m.curl != c || m.ptr == nil {
				return errors.New("curlgo: MIME form must be live and belong to this Curl")
			}
			p = unsafe.Pointer(m.ptr)
			c.attachedMime = m
		} else {
			c.attachedMime = nil
		}
		code = C.cg_setopt_ptr(c.easy, C.int(opt), p)
	default:
		kind, known := optionKinds[opt]
		if !known {
			return &CurlError{Code: CurlECode_UNKNOWN_OPTION, Op: "setopt", Message: fmt.Sprintf("unknown option %d", opt)}
		}
		switch {
		case opt < 10000 || (opt >= 30000 && opt < 40000):
			n, e := integerValue(value)
			if e != nil {
				return fmt.Errorf("curlgo: option %d: %w", opt, e)
			}
			if (opt == OptPostFieldSize || opt == OptPostFieldSizeLarge) && c.postFieldsHasData && n > c.postFieldsLength {
				return errors.New("curlgo: post field size exceeds owned body buffer")
			}
			if opt < 10000 {
				if C.sizeof_long == 4 && (n > 2147483647 || n < -2147483648) {
					return errors.New("curlgo: value overflows native long")
				}
				code = C.cg_setopt_long(c.easy, C.int(opt), C.int64_t(n))
			} else {
				code = C.cg_setopt_off(c.easy, C.int(opt), C.int64_t(n))
			}
		case kind == "list":
			var items []string
			switch v := value.(type) {
			case nil:
			case []string:
				items = v
			case [][]byte:
				for _, b := range v {
					items = append(items, string(b))
				}
			default:
				return fmt.Errorf("curlgo: option %d requires []string", opt)
			}
			for _, s := range items {
				if strings.ContainsRune(s, 0) {
					return errors.New("curlgo: list item contains NUL")
				}
				if (opt == OptHTTPHeader || opt == OptHTTPBaseHeader || opt == CurlOpt_PROXYHEADER) && strings.ContainsAny(s, "\r\n") {
					return errors.New("curlgo: header contains CR or LF")
				}
			}
			var list *C.struct_curl_slist
			for _, s := range items {
				p := C.CString(s)
				next := C.cg_slist_append(list, p)
				C.free(unsafe.Pointer(p))
				if next == nil {
					C.cg_slist_free(list)
					return errors.New("curlgo: list allocation failed")
				}
				list = next
			}
			code = C.cg_setopt_ptr(c.easy, C.int(opt), unsafe.Pointer(list))
			if code != 0 {
				C.cg_slist_free(list)
			} else {
				c.freeAllocation(opt)
				if opt == OptHTTPBaseHeader {
					C.cg_slist_free(list)
				} else {
					c.allocations[opt] = nativeAllocation{ptr: unsafe.Pointer(list), list: true}
				}
			}
		case opt == OptPostFields || opt == OptCopyPostFields || kind == "string" || kind == "blob":
			var b []byte
			switch v := value.(type) {
			case nil:
			case string:
				b = []byte(v)
			case []byte:
				b = v
			default:
				return fmt.Errorf("curlgo: option %d requires string or []byte", opt)
			}
			if kind == "string" && opt != OptPostFields && opt != OptCopyPostFields && strings.ContainsRune(string(b), 0) {
				return errors.New("curlgo: string option contains NUL")
			}
			if kind == "blob" {
				if value == nil {
					code = C.cg_setopt_ptr(c.easy, C.int(opt), nil)
				} else {
					p := C.CBytes(append(append([]byte{}, b...), 0))
					code = C.cg_setopt_blob(c.easy, C.int(opt), p, C.size_t(len(b)))
					C.free(p)
				}
			} else {
				var p unsafe.Pointer
				if value != nil {
					p = C.CBytes(append(append([]byte{}, b...), 0))
				}
				if (opt == OptPostFields || opt == OptCopyPostFields) && value != nil {
					code = C.cg_setopt_off(c.easy, C.int(OptPostFieldSizeLarge), C.int64_t(len(b)))
				}
				if code == 0 {
					code = C.cg_setopt_ptr(c.easy, C.int(opt), p)
				}
				if code != 0 {
					C.free(p)
				} else {
					if opt == OptPostFields {
						c.freeAllocation(opt)
						c.allocations[opt] = nativeAllocation{ptr: p, size: len(b)}
					} else {
						C.free(p)
					}
					if opt == OptPostFields || opt == OptCopyPostFields {
						c.postFieldsLength = int64(len(b))
						c.postFieldsHasData = value != nil
						if opt == OptCopyPostFields {
							c.freeAllocation(OptPostFields)
						}
					}
				}
			}
		default:
			return fmt.Errorf("curlgo: option %d requires an unsupported native object or callback", opt)
		}
	}
	if e := c.check(code, "setopt"); e != nil {
		return e
	}
	if opt == CurlOpt_CONNECT_ONLY {
		c.connectOnly, _ = integerValue(value)
	}
	if opt == OptPostFields || opt == OptCopyPostFields {
		c.postFieldsMode = opt
	}
	if opt == OptSSLVersion {
		n, _ := integerValue(value)
		c.sslVersion, c.sslVersionSet = effectiveSSLVersion(SSLVersion(n)), true
	}
	if opt == OptImpersonate {
		switch target := value.(type) {
		case string:
			c.trackImpersonatedSSLVersion(target)
		case []byte:
			c.trackImpersonatedSSLVersion(string(target))
		}
	}
	c.updateRequestMethod(opt, value)
	return nil
}

// POSTFIELDS reattachment changes libcurl's internal method. Remember the
// current method so Duplicate can restore it after rebinding borrowed bytes.
func (c *Curl) updateRequestMethod(opt Option, value any) {
	switch opt {
	case OptPostFields, OptCopyPostFields:
		c.requestMethod = OptPost
	case OptMIMEPost:
		c.requestMethod = OptMIMEPost
	case OptHTTPGet:
		if n, _ := integerValue(value); n != 0 {
			c.requestMethod = OptHTTPGet
		}
	case OptPost:
		if n, _ := integerValue(value); n != 0 {
			c.requestMethod = OptPost
		} else {
			c.requestMethod = OptHTTPGet
		}
	case OptUpload, CurlOpt_PUT:
		if n, _ := integerValue(value); n != 0 {
			c.requestMethod = OptUpload
		} else {
			c.requestMethod = OptHTTPGet
		}
	case OptNoBody:
		if n, _ := integerValue(value); n != 0 {
			c.requestMethod = OptNoBody
		} else if c.requestMethod == OptNoBody {
			c.requestMethod = OptHTTPGet
		}
	}
}
func integerValue(v any) (int64, error) {
	if b, ok := v.(bool); ok {
		if b {
			return 1, nil
		}
		return 0, nil
	}
	if v == nil {
		return 0, errors.New("requires an integer or bool")
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return r.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if r.Uint() > uint64(1<<63-1) {
			return 0, errors.New("integer overflow")
		}
		return int64(r.Uint()), nil
	}
	return 0, errors.New("requires an integer or bool")
}

func (c *Curl) Impersonate(target string, defaultHeaders bool) error {
	p, e := NormalizeProfile(Profile(target))
	if e != nil {
		return e
	}
	if p == "" {
		return errors.New("curlgo: impersonation target is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	c.clearError()
	t := C.CString(string(p))
	defer C.free(unsafe.Pointer(t))
	h := C.int(0)
	if defaultHeaders {
		h = 1
	}
	if e := c.check(C.cg_impersonate(c.easy, t, h), "impersonate "+string(p)); e != nil {
		return e
	}
	c.trackImpersonatedSSLVersion(string(p))
	return nil
}

// Native curl applies a profile's SSL version only before the first explicit
// SSLVERSION setting (including a profile-applied setting). Keep that effective
// value so later partial ExtraFingerprints updates can preserve its other bound.
func (c *Curl) trackImpersonatedSSLVersion(target string) {
	if c.sslVersionSet {
		return
	}
	target, _, _ = strings.Cut(target, ":") // CURLOPT_IMPERSONATE supports :yes/:no.
	target = strings.ToLower(target)        // Native aliases are case-insensitive.
	profile, err := NormalizeProfile(Profile(target))
	if target == "okhttp4" || target == "okhttp4_android" {
		profile = "okhttp4_android" // Additional native-only preset in the pinned release.
		err = nil
	}
	if err != nil || profile == "" {
		return
	}
	minimum := SSLVersionTLS1_2
	switch profile {
	case Safari153, Safari155, Safari170, Safari172IOS, Safari180, Safari180IOS, Safari184, Safari184IOS, "okhttp4_android":
		minimum = SSLVersionTLS1_0
	}
	c.sslVersion, c.sslVersionSet = minimum|SSLVersionMaxDefault, true
}

func (c *Curl) resetSSLVersionTracking() {
	// Curl_init_userdefined passes DEFAULT with MAX_NONE to the native setter;
	// curl 8.22 resolves DEFAULT to TLS 1.2 while retaining maximum flags.
	c.sslVersion, c.sslVersionSet = SSLVersionTLS1_2, false
	// curl_easy_init and curl_easy_reset both apply this native environment
	// profile. Recording it also preserves old Safari's TLS 1.0 minimum.
	if target := os.Getenv("CURL_IMPERSONATE"); target != "" {
		c.trackImpersonatedSSLVersion(target)
	}
}

func effectiveSSLVersion(version SSLVersion) SSLVersion {
	if version&0xffff == SSLVersionDefault {
		return version | SSLVersionTLS1_2
	}
	return version
}

// Perform transfers using curl's multi API so context cancellation interrupts
// network waits promptly. User-provided Reader/Writer callbacks must themselves
// unblock when canceled if they perform blocking I/O.
func (c *Curl) Perform(ctx context.Context) error {
	return c.perform(ctx, nil)
}

// transferObserver is internal to Transport. Native diagnostics distinguish a
// discarded authentication response from a terminal response; afterStep runs
// once native curl has finished deciding whether to start another exchange.
type transferObserver struct {
	debug     DebugFunc
	afterStep func(error) error
	verbose   bool
}

func (c *Curl) perform(ctx context.Context, observer *transferObserver) error {
	if ctx == nil {
		return errors.New("curlgo: nil context")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.clearError()
	c.callbacks.err = nil
	c.callbacks.ctx = ctx
	defer func() { c.callbacks.ctx = nil }()
	if observer != nil {
		if err := c.check(C.cg_setopt_long(c.easy, C.int(OptVerbose), 1), "observe authentication"); err != nil {
			return err
		}
		debug := c.callbacks.debug
		c.callbacks.debug = func(kind DebugType, data []byte) {
			observer.debug(kind, data)
			if observer.verbose && debug != nil {
				debug(kind, data)
			}
		}
		defer func() {
			c.callbacks.debug = debug
			verbose := C.int64_t(0)
			if observer.verbose {
				verbose = 1
			}
			C.cg_setopt_long(c.easy, C.int(OptVerbose), verbose)
		}()
	}
	if e := c.check(C.cg_setopt_long(c.easy, C.int(OptNoProgress), 0), "progress"); e != nil {
		return e
	}
	multi := c.multi
	if c.multiAttached {
		C.cg_multi_remove(multi, c.easy)
		c.multiAttached = false
	}
	C.cg_multi_result(multi, c.easy) // Drain any completion left by cancellation.
	if code := C.cg_multi_add(multi, c.easy); code != 0 {
		return fmt.Errorf("curlgo: multi add: %s", C.GoString(C.cg_multi_strerror(code)))
	}
	c.multiAttached = true
	keepConnection := false
	defer func() {
		if !keepConnection {
			C.cg_multi_remove(multi, c.easy)
			c.multiAttached = false
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var running C.int
		if code := C.cg_multi_perform(multi, &running); code != 0 {
			return fmt.Errorf("curlgo: multi perform: %s", C.GoString(C.cg_multi_strerror(code)))
		}
		if c.callbacks.err != nil {
			if observer != nil {
				_ = observer.afterStep(c.callbacks.err)
			}
			return c.callbacks.err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if running == 0 {
			err := c.check(C.cg_multi_result(multi, c.easy), "perform")
			if err != nil && observer != nil {
				_ = observer.afterStep(err)
			}
			keepConnection = err == nil && c.connectOnly > 0
			return err
		}
		if observer != nil {
			if err := observer.afterStep(nil); err != nil {
				return err
			}
		}
		if code := C.cg_multi_poll(multi, 25); code != 0 {
			return fmt.Errorf("curlgo: multi poll: %s", C.GoString(C.cg_multi_strerror(code)))
		}
	}
}

// getInfoLongLocked is used by native response callbacks during perform, while
// Curl.mu is already held. It must not lock again or clear the native error buffer.
func (c *Curl) getInfoLongLocked(info Info) (int64, error) {
	var value C.int64_t
	code := C.cg_getinfo_long(c.easy, C.int(info), &value)
	return int64(value), c.check(code, "getinfo")
}

// GetInfo returns string, int64, float64, []string, or [][]string (CERTINFO).
func (c *Curl) GetInfo(info Info) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return nil, ErrClosed
	}
	c.clearError()
	var code C.int
	switch int(info) & 0xf00000 {
	case 0x100000:
		if info == CurlInfo_PRIVATE {
			return nil, errors.New("curlgo: native private pointers are not exposed")
		}
		var p *C.char
		code = C.cg_getinfo_string(c.easy, C.int(info), &p)
		if e := c.check(code, "getinfo"); e != nil {
			return nil, e
		}
		if p == nil {
			return "", nil
		}
		return C.GoString(p), nil
	case 0x200000, 0x600000, 0x500000:
		var v C.int64_t
		switch int(info) & 0xf00000 {
		case 0x200000:
			code = C.cg_getinfo_long(c.easy, C.int(info), &v)
		case 0x600000:
			code = C.cg_getinfo_off(c.easy, C.int(info), &v)
		case 0x500000:
			code = C.cg_getinfo_socket(c.easy, C.int(info), &v)
		}
		return int64(v), c.check(code, "getinfo")
	case 0x300000:
		var v C.double
		code = C.cg_getinfo_double(c.easy, C.int(info), &v)
		return float64(v), c.check(code, "getinfo")
	case 0x400000:
		if info != CurlInfo_COOKIELIST && info != CurlInfo_SSL_ENGINES && info != CurlInfo_REDIRECT_HISTORY && info != CurlInfo_COOKIECHANGES && info != CurlInfo_CERTINFO {
			return nil, errors.New("curlgo: native object info is not exposed")
		}
		var p unsafe.Pointer
		code = C.cg_getinfo_ptr(c.easy, C.int(info), &p)
		if e := c.check(code, "getinfo"); e != nil {
			return nil, e
		}
		if info == CurlInfo_CERTINFO {
			if p == nil {
				return [][]string{}, nil
			}
			certs := (*C.struct_curl_certinfo)(p)
			lists := unsafe.Slice(certs.certinfo, int(certs.num_of_certs))
			out := make([][]string, len(lists))
			for i, l := range lists {
				out[i] = slistStrings(l)
			}
			return out, nil
		}
		l := (*C.struct_curl_slist)(p)
		defer C.cg_slist_free(l)
		return slistStrings(l), nil
	default:
		return nil, fmt.Errorf("curlgo: unsupported info %d", info)
	}
}
func slistStrings(l *C.struct_curl_slist) []string {
	out := []string{}
	for ; l != nil; l = l.next {
		out = append(out, C.GoString(l.data))
	}
	return out
}

// Reset clears request configuration while retaining the native connection and
// DNS caches. As in libcurl, native cookie state survives Reset.
func (c *Curl) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	if c.multiAttached {
		C.cg_multi_remove(c.multi, c.easy)
		c.multiAttached = false
	}
	C.cg_easy_reset(c.easy)
	c.resetSSLVersionTracking()
	c.connectOnly = 0
	c.attachedMime = nil
	c.releaseAllocations()
	c.postFieldsMode = 0
	c.postFieldsLength = 0
	c.postFieldsHasData = false
	c.requestMethod = OptHTTPGet
	*c.callbacks = callbackState{body: io.Discard, header: io.Discard}
	return c.initialize()
}

// Duplicate copies request options into an independent handle. Connections and
// connections are not copied; callbacks use the same Go Reader/Writer. Native
// cookie behavior follows curl_easy_duphandle. Borrowed buffers are deep-copied.
func (c *Curl) Duplicate() (*Curl, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return nil, ErrClosed
	}
	if c.attachedMime != nil {
		return nil, errors.New("curlgo: cannot duplicate an attached MIME form")
	}
	copy := C.cg_easy_duplicate(c.easy)
	if copy == nil {
		return nil, errors.New("curlgo: curl_easy_duphandle failed")
	}
	d, e := NewCurl()
	if e != nil {
		C.cg_easy_cleanup(copy)
		return nil, e
	}
	C.cg_easy_cleanup(d.easy)
	d.easy = copy
	*d.callbacks = *c.callbacks
	d.callbacks.ctx = nil
	d.callbacks.err = nil
	d.connectOnly = c.connectOnly
	d.postFieldsMode = c.postFieldsMode
	d.postFieldsLength = c.postFieldsLength
	d.postFieldsHasData = c.postFieldsHasData
	d.requestMethod = c.requestMethod
	d.sslVersion, d.sslVersionSet = c.sslVersion, c.sslVersionSet
	if e = d.check(C.cg_callbacks(d.easy, C.uintptr_t(d.callbackHandle)), "duplicate callbacks"); e == nil {
		e = d.check(C.cg_setopt_ptr(d.easy, C.int(CurlOpt_ERRORBUFFER), d.errorBuffer), "duplicate error buffer")
	}
	if e != nil {
		d.Close()
		return nil, e
	}
	// libcurl duplicates string and blob options itself, but borrows slists and
	// POSTFIELDS. Rebind those pointers before the original can be closed.
	for opt, allocation := range c.allocations {
		if opt == OptHTTPBaseHeader {
			continue
		}
		if allocation.list {
			if e = d.setOptLocked(opt, slistStrings((*C.struct_curl_slist)(allocation.ptr)), false); e != nil {
				d.Close()
				return nil, e
			}
		}
	}
	if c.postFieldsMode == OptPostFields {
		a := c.allocations[OptPostFields]
		var p unsafe.Pointer
		if a.ptr != nil {
			p = C.CBytes(append(append([]byte{}, unsafe.Slice((*byte)(a.ptr), a.size)...), 0))
		}
		if e = d.check(C.cg_setopt_ptr(d.easy, C.int(OptPostFields), p), "duplicate body"); e != nil {
			C.free(p)
			d.Close()
			return nil, e
		}
		d.allocations[OptPostFields] = nativeAllocation{ptr: p, size: a.size}
		var code C.int
		switch c.requestMethod {
		case OptPost: // Rebinding already restored POST and preserved NOBODY.
		case OptNoBody:
			code = C.cg_setopt_long(d.easy, C.int(OptNoBody), 1)
		case OptUpload:
			code = C.cg_setopt_long(d.easy, C.int(OptUpload), 1)
		case OptMIMEPost:
			code = C.cg_setopt_ptr(d.easy, C.int(OptMIMEPost), nil)
		default:
			code = C.cg_setopt_long(d.easy, C.int(OptPost), 0) // Preserves NOBODY.
		}
		if e = d.check(code, "duplicate request method"); e != nil {
			d.Close()
			return nil, e
		}
	}
	return d, nil
}
func (c *Curl) Upkeep() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	c.clearError()
	return c.check(C.cg_upkeep(c.easy), "upkeep")
}
func (c *Curl) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return nil
	}
	runtime.SetFinalizer(c, nil)
	if c.multiAttached {
		C.cg_multi_remove(c.multi, c.easy)
		c.multiAttached = false
	}
	C.cg_easy_cleanup(c.easy)
	c.easy = nil
	if c.multi != nil {
		C.cg_multi_cleanup(c.multi)
		c.multi = nil
	}
	c.releaseAllocations()
	for m := range c.mimes {
		C.cg_mime_free(m.ptr)
		m.ptr = nil
	}
	c.mimes = nil
	c.attachedMime = nil
	C.free(c.errorBuffer)
	c.errorBuffer = nil
	c.callbackHandle.Delete()
	return nil
}
