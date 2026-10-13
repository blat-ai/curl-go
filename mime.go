package curlgo

/*
#include "native.h"
*/
import "C"

import (
	"errors"
	"strings"
	"unsafe"
)

// Mime builds multipart/form-data with curl's native MIME engine, which honors
// profile-specific form boundaries. Its owning Curl releases it on Close.
type Mime struct {
	curl *Curl
	ptr  *C.curl_mime
}
type MimePart struct {
	Name        string
	ContentType string
	Filename    string
	LocalPath   string
	Data        []byte
}

func (c *Curl) NewMime() (*Mime, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return nil, ErrClosed
	}
	p := C.cg_mime_init(c.easy)
	if p == nil {
		return nil, errors.New("curlgo: MIME allocation failed")
	}
	m := &Mime{curl: c, ptr: p}
	c.mimes[m] = true
	return m, nil
}

// AddPart adds a byte-valued field or file. LocalPath uses libcurl's file-backed
// upload; Data and LocalPath are mutually exclusive. A Filename marks file data.
func (m *Mime) AddPart(part MimePart) error {
	if m == nil || m.curl == nil {
		return ErrClosed
	}
	c := m.curl
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil || m.ptr == nil {
		return ErrClosed
	}
	if part.Name == "" {
		return errors.New("curlgo: MIME part requires a name")
	}
	if part.LocalPath != "" && part.Data != nil {
		return errors.New("curlgo: MIME Data and LocalPath are mutually exclusive")
	}
	for _, s := range []string{part.Name, part.ContentType, part.Filename, part.LocalPath} {
		if strings.ContainsAny(s, "\x00\r\n") {
			return errors.New("curlgo: MIME metadata contains a control character")
		}
	}
	c.clearError()
	p := C.cg_mime_addpart(m.ptr)
	if p == nil {
		return errors.New("curlgo: MIME part allocation failed")
	}
	apply := func(s string, f func(*C.curl_mimepart, *C.char) C.int) error {
		v := C.CString(s)
		defer C.free(unsafe.Pointer(v))
		return c.check(f(p, v), "mime")
	}
	if e := apply(part.Name, func(p *C.curl_mimepart, s *C.char) C.int { return C.cg_mime_name(p, s) }); e != nil {
		return e
	}
	if part.ContentType != "" {
		if e := apply(part.ContentType, func(p *C.curl_mimepart, s *C.char) C.int { return C.cg_mime_type(p, s) }); e != nil {
			return e
		}
	}
	if part.LocalPath != "" {
		if e := apply(part.LocalPath, func(p *C.curl_mimepart, s *C.char) C.int { return C.cg_mime_filedata(p, s) }); e != nil {
			return e
		}
	} else {
		data := C.CBytes(append(append([]byte{}, part.Data...), 0))
		code := C.cg_mime_data(p, (*C.char)(data), C.size_t(len(part.Data)))
		C.free(data)
		if e := c.check(code, "mime data"); e != nil {
			return e
		}
	}
	if part.Filename != "" {
		if e := apply(part.Filename, func(p *C.curl_mimepart, s *C.char) C.int { return C.cg_mime_filename(p, s) }); e != nil {
			return e
		}
	}
	return nil
}
func (m *Mime) Close() error {
	if m == nil || m.curl == nil {
		return nil
	}
	c := m.curl
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.ptr == nil {
		return nil
	}
	if c.attachedMime == m && c.easy != nil {
		if e := c.check(C.cg_setopt_ptr(c.easy, C.int(OptMIMEPost), nil), "detach MIME"); e != nil {
			return e
		}
		c.attachedMime = nil
		c.updateRequestMethod(OptMIMEPost, nil)
	}
	C.cg_mime_free(m.ptr)
	m.ptr = nil
	delete(c.mimes, m)
	return nil
}
