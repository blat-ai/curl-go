package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformAsset(t *testing.T) {
	for _, test := range []struct{ os, arch, libc, suffix, library string }{
		{"darwin", "arm64", "auto", "arm64-macos", "libcurl-impersonate.dylib"},
		{"darwin", "amd64", "auto", "x86_64-macos", "libcurl-impersonate.dylib"},
		{"linux", "amd64", "gnu", "x86_64-linux-gnu", "libcurl-impersonate.so"},
		{"linux", "amd64", "musl", "x86_64-linux-musl", "libcurl-impersonate.so"},
		{"linux", "arm64", "musl", "aarch64-linux-musl", "libcurl-impersonate.so"},
		{"linux", "arm", "gnu", "arm-linux-gnueabihf", "libcurl-impersonate.so"},
		{"linux", "386", "gnu", "i386-linux-gnu", "libcurl-impersonate.so"},
		{"linux", "riscv64", "gnu", "riscv64-linux-gnu", "libcurl-impersonate.so"},
		{"windows", "amd64", "auto", "x86_64-win32", "libcurl-impersonate.dll"},
		{"freebsd", "arm64", "auto", "aarch64-freebsd", "libcurl-impersonate.so"},
	} {
		t.Run(test.os+"-"+test.arch+"-"+test.libc, func(t *testing.T) {
			asset, library, err := platformAsset(test.os, test.arch, test.libc)
			if err != nil {
				t.Fatal(err)
			}
			if asset != "libcurl-impersonate-"+releaseVersion+"."+test.suffix+".tar.gz" || library != test.library {
				t.Fatalf("unexpected asset %q and library %q", asset, library)
			}
			if digest, err := hex.DecodeString(releaseChecksums[asset]); err != nil || len(digest) != sha256.Size {
				t.Fatalf("invalid pinned digest for %s", asset)
			}
			cliAsset, executable, err := platformCLIAsset(test.os, test.arch, test.libc)
			if err != nil {
				t.Fatal(err)
			}
			wantExecutable := "curl-impersonate"
			if test.os == "windows" {
				wantExecutable += ".exe"
			}
			if cliAsset != strings.TrimPrefix(asset, "lib") || executable != wantExecutable {
				t.Fatalf("unexpected CLI asset %q and executable %q", cliAsset, executable)
			}
			if digest, err := hex.DecodeString(releaseChecksums[cliAsset]); err != nil || len(digest) != sha256.Size {
				t.Fatalf("invalid pinned digest for %s", cliAsset)
			}
		})
	}
	for _, test := range []struct{ os, arch, libc string }{
		{"plan9", "amd64", "auto"}, {"linux", "arm", "musl"}, {"darwin", "386", "auto"}, {"linux", "amd64", "unknown"},
	} {
		if _, _, err := platformAsset(test.os, test.arch, test.libc); err == nil {
			t.Fatalf("accepted unsupported platform %+v", test)
		}
	}
}

func TestExtractIndependentCLI(t *testing.T) {
	for _, executable := range []string{"curl-impersonate", "curl-impersonate.exe"} {
		t.Run(executable, func(t *testing.T) {
			matches := func(name string) bool { return name == executable }
			archive := testArchive(t,
				archiveEntry{name: executable, data: "independent executable"},
				archiveEntry{name: "curl_chrome150", data: "browser wrapper"},
				archiveEntry{name: "libcurl-impersonate.so.4", data: "library"},
			)
			var out bytes.Buffer
			if err := extractArtifact(bytes.NewReader(archive), &out, executable, matches); err != nil {
				t.Fatal(err)
			}
			if out.String() != "independent executable" {
				t.Fatalf("extracted unintended artifact %q", out.String())
			}
			for name, entries := range map[string][]archiveEntry{
				"wrapper only": {{name: "curl_chrome150", data: "browser wrapper"}},
				"link only":    {{name: executable, target: "wrapper", typeflag: tar.TypeSymlink}},
				"empty":        {{name: executable}},
				"duplicate":    {{name: executable, data: "first"}, {name: "bin/" + executable, data: "second"}},
			} {
				t.Run(name, func(t *testing.T) {
					if err := extractArtifact(bytes.NewReader(testArchive(t, entries...)), io.Discard, executable, matches); err == nil {
						t.Fatal("invalid executable archive was accepted")
					}
				})
			}
		})
	}
}

type archiveEntry struct {
	name, target, data string
	typeflag           byte
}

func testArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := int64(len(e.data))
		if typeflag == tar.TypeSymlink || typeflag == tar.TypeLink {
			size = 0
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Linkname: e.target, Typeflag: typeflag, Mode: 0755, Size: size}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := io.WriteString(tw, e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExtractOnlyLibraryAndFlattenLinks(t *testing.T) {
	archive := testArchive(t,
		archiveEntry{name: "libcurl-impersonate.so", target: "libcurl-impersonate.so.4", typeflag: tar.TypeSymlink},
		archiveEntry{name: "libcurl-impersonate.so.4", data: "native library"},
		archiveEntry{name: "include/curl/curl.h", data: "header"},
		archiveEntry{name: "libcurl-impersonate.a", data: "static archive"},
	)
	var out bytes.Buffer
	if err := extractLibrary(bytes.NewReader(archive), &out, "libcurl-impersonate.so"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "native library" {
		t.Fatalf("extracted unwanted data %q", out.String())
	}
}

func TestRejectUnsafeOrAmbiguousArchive(t *testing.T) {
	for name, entries := range map[string][]archiveEntry{
		"traversal":         {{name: "../libcurl-impersonate.so", data: "x"}},
		"absolute":          {{name: "/libcurl-impersonate.so", data: "x"}},
		"windows traversal": {{name: "..\\libcurl-impersonate.so", data: "x"}},
		"drive":             {{name: "C:/libcurl-impersonate.so", data: "x"}},
		"symlink escape":    {{name: "libcurl-impersonate.so", target: "../outside", typeflag: tar.TypeSymlink}},
		"absolute link":     {{name: "libcurl-impersonate.so", target: "/outside", typeflag: tar.TypeSymlink}},
		"missing":           {{name: "header.h", data: "x"}},
		"empty":             {{name: "libcurl-impersonate.so"}},
		"multiple":          {{name: "libcurl-impersonate.so.4", data: "x"}, {name: "libcurl-impersonate.so.5", data: "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := extractLibrary(bytes.NewReader(testArchive(t, entries...)), &out, "libcurl-impersonate.so"); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestInstallVerifiesChecksumBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive.tar.gz")
	if err := os.WriteFile(archive, testArchive(t, archiveEntry{name: "libcurl-impersonate.so.4", data: "bad library"}), 0644); err != nil {
		t.Fatal(err)
	}
	asset, library, err := platformAsset("linux", "amd64", "gnu")
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "destination")
	_, err = install(context.Background(), destination, asset, library, archive, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected checksum rejection, got %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination was created before checksum validation: %v", err)
	}
}

func TestRejectCorruptGzip(t *testing.T) {
	archive := testArchive(t, archiveEntry{name: "libcurl-impersonate.so.4", data: "native library"})
	archive[len(archive)-8] ^= 0xff
	if err := extractLibrary(bytes.NewReader(archive), io.Discard, "libcurl-impersonate.so"); err == nil {
		t.Fatal("accepted gzip with an invalid checksum")
	}
}
