//go:build windows

package curlgo

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeLibraryUnicodePath(t *testing.T) {
	if os.Getenv("CURL_GO_UNICODE_HELPER") == "1" {
		if _, err := Version(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := ensureLibrary(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "浏览器-curl-é")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	libraryState.Lock()
	path := libraryState.path
	libraryState.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "libcurl-impersonate.dll")
	if err = os.WriteFile(destination, data, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestNativeLibraryUnicodePath$")
	cmd.Env = append(os.Environ(), "CURL_GO_UNICODE_HELPER=1", "CURL_IMPERSONATE_LIB="+destination)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Unicode native load failed: %v\n%s", err, output)
	}
}
