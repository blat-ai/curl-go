package curlgo

/*
#include "native.h"
*/
import "C"

import (
	"fmt"
	"io"
	"runtime/cgo"
	"unsafe"
)

func callback(id C.uintptr_t) *callbackState { return cgo.Handle(id).Value().(*callbackState) }
func callbackPanic(s *callbackState) {
	if r := recover(); r != nil {
		s.err = fmt.Errorf("curlgo: callback panicked: %v", r)
	}
}
func callbackStopped(s *callbackState) bool {
	if s.err != nil {
		return true
	}
	if s.ctx != nil {
		if e := s.ctx.Err(); e != nil {
			s.err = e
			return true
		}
	}
	return false
}

//export goCurlWrite
func goCurlWrite(id C.uintptr_t, header C.int, data *C.char, size C.size_t) (result C.size_t) {
	s := callback(id)
	defer callbackPanic(s)
	if callbackStopped(s) {
		return 0
	}
	if uint64(size) > uint64(1<<31-1) {
		s.err = fmt.Errorf("curlgo: callback buffer too large")
		return 0
	}
	p := C.GoBytes(unsafe.Pointer(data), C.int(size))
	w := s.body
	if header != 0 {
		w = s.header
	}
	n, e := w.Write(p)
	if e != nil {
		s.err = e
		return 0
	}
	if n != len(p) {
		s.err = io.ErrShortWrite
		return 0
	}
	return size
}

//export goCurlRead
func goCurlRead(id C.uintptr_t, data *C.char, size C.size_t) (result C.size_t) {
	result = 0x10000000
	s := callback(id)
	defer callbackPanic(s)
	if callbackStopped(s) {
		return result
	}
	if s.reader == nil {
		return 0
	}
	if uint64(size) > uint64(1<<31-1) {
		s.err = fmt.Errorf("curlgo: callback buffer too large")
		return result
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))
	for emptyReads := 0; emptyReads < 100; emptyReads++ {
		if callbackStopped(s) {
			return result
		}
		n, e := s.reader.Read(p)
		if n < 0 || n > len(p) {
			s.err = fmt.Errorf("curlgo: reader returned invalid count %d", n)
			return result
		}
		if e != nil && e != io.EOF {
			s.err = e
			return result
		}
		if n > 0 || e == io.EOF {
			return C.size_t(n)
		}
	}
	s.err = io.ErrNoProgress
	return result
}

//export goCurlSeek
func goCurlSeek(id C.uintptr_t, offset C.int64_t, origin C.int) (result C.int) {
	result = 1
	s := callback(id)
	defer callbackPanic(s)
	if callbackStopped(s) {
		return result
	}
	if s.seeker == nil {
		return 2
	}
	if _, e := s.seeker.Seek(int64(offset), int(origin)); e != nil {
		s.err = e
		return result
	}
	return 0
}

//export goCurlDebug
func goCurlDebug(id C.uintptr_t, typ C.int, data *C.char, size C.size_t) C.int {
	s := callback(id)
	defer callbackPanic(s)
	if callbackStopped(s) || s.debug == nil {
		return 0
	}
	if uint64(size) > uint64(1<<31-1) {
		s.err = fmt.Errorf("curlgo: debug buffer too large")
		return 0
	}
	s.debug(DebugType(typ), C.GoBytes(unsafe.Pointer(data), C.int(size)))
	return 0
}

//export goCurlProgress
func goCurlProgress(id C.uintptr_t) C.int {
	if callbackStopped(callback(id)) {
		return 1
	}
	return 0
}
