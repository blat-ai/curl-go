package curlgo

/*
#cgo linux LDFLAGS: -ldl
#include "native.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

// NativeVersion is the curl-impersonate release used for the profile registry.
const NativeVersion = "v2.2.3"

var libraryState struct {
	sync.Mutex
	path string
}

// LoadLibrary loads a native curl-impersonate shared library. Loading is process
// wide; a different library cannot replace it after the first successful load.
// No downloads occur when using the library.
func LoadLibrary(path string) error {
	libraryState.Lock()
	defer libraryState.Unlock()
	return loadLibraryLocked(path)
}
func loadLibraryLocked(path string) error {
	if strings.ContainsRune(path, 0) || path == "" {
		return errors.New("curlgo: invalid native library path")
	}
	if libraryState.path != "" {
		if libraryState.path != path {
			return fmt.Errorf("curlgo: native library already loaded from %s", libraryState.path)
		}
		return nil
	}
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var buf [2048]C.char
	if C.cg_load(p, &buf[0], C.size_t(len(buf))) != 0 {
		return fmt.Errorf("curlgo: loading %s: %s", path, C.GoString(&buf[0]))
	}
	libraryState.path = path
	return nil
}
func ensureLibrary() error {
	libraryState.Lock()
	defer libraryState.Unlock()
	if libraryState.path != "" {
		return nil
	}
	if p := os.Getenv("CURL_IMPERSONATE_LIB"); p != "" {
		return loadLibraryLocked(p)
	}
	name := "libcurl-impersonate.so"
	if runtime.GOOS == "darwin" {
		name = "libcurl-impersonate.dylib"
	}
	if runtime.GOOS == "windows" {
		name = "libcurl-impersonate.dll"
	}
	candidates := []string{filepath.Join(".lib", name)}
	if exe, e := os.Executable(); e == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".lib", name), filepath.Join(filepath.Dir(exe), name))
	}
	candidates = append(candidates, name)
	var errs []error
	for _, p := range candidates {
		if e := loadLibraryLocked(p); e == nil {
			return nil
		} else {
			errs = append(errs, e)
		}
	}
	return fmt.Errorf("curlgo: curl-impersonate is required; run go run ./cmd/curl-go-install or set CURL_IMPERSONATE_LIB: %w", errors.Join(errs...))
}

// Version reports the loaded native libcurl version and its compiled features.
func Version() (string, error) {
	if e := ensureLibrary(); e != nil {
		return "", e
	}
	return C.GoString(C.cg_version()), nil
}
