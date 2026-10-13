// curl-go-install downloads the pinned native curl-impersonate library and,
// optionally, the independent upstream command-line executable.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const releaseVersion = "v2.2.3"
const maxArchiveSize int64 = 128 << 20
const maxExpandedSize int64 = 1 << 30
const maxLibrarySize int64 = 512 << 20

func main() {
	dir := flag.String("dir", ".lib", "directory for the native library")
	goos := flag.String("goos", runtime.GOOS, "target operating system")
	goarch := flag.String("goarch", runtime.GOARCH, "target architecture")
	libc := flag.String("libc", "auto", "Linux libc: auto, gnu, or musl")
	archive := flag.String("archive", "", "install a local release archive instead of downloading")
	withCLI := flag.Bool("with-cli", false, "also install the pinned upstream CLI for integration parity tests")
	cliArchive := flag.String("cli-archive", "", "install the CLI from a local release archive (requires -with-cli)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "curl-go-install: unexpected positional arguments")
		os.Exit(2)
	}
	if *cliArchive != "" && !*withCLI {
		fmt.Fprintln(os.Stderr, "curl-go-install: -cli-archive requires -with-cli")
		os.Exit(2)
	}
	asset, library, err := platformAsset(*goos, *goarch, *libc)
	if err == nil {
		var location string
		location, err = install(context.Background(), *dir, asset, library, *archive, &http.Client{Timeout: 5 * time.Minute})
		if err == nil {
			fmt.Printf("CURL_IMPERSONATE_LIB=%s\n", location)
			if !*withCLI {
				return
			}
			var cliAsset, executable string
			cliAsset, executable, err = platformCLIAsset(*goos, *goarch, *libc)
			if err == nil {
				location, err = installArtifact(context.Background(), *dir, cliAsset, executable, *cliArchive, &http.Client{Timeout: 5 * time.Minute}, func(name string) bool { return name == executable })
				if err == nil {
					fmt.Printf("CURL_IMPERSONATE_BIN=%s\n", location)
					return
				}
			}
		}
	}
	fmt.Fprintln(os.Stderr, "curl-go-install:", err)
	os.Exit(1)
}

func platformCLIAsset(goos, goarch, libc string) (string, string, error) {
	asset, _, err := platformAsset(goos, goarch, libc)
	if err != nil {
		return "", "", err
	}
	asset = strings.TrimPrefix(asset, "lib")
	if _, ok := releaseChecksums[asset]; !ok {
		return "", "", fmt.Errorf("no pinned CLI release for %s/%s (libc %s)", goos, goarch, libc)
	}
	executable := "curl-impersonate"
	if goos == "windows" {
		executable += ".exe"
	}
	return asset, executable, nil
}

func platformAsset(goos, goarch, libc string) (string, string, error) {
	if libc != "auto" && libc != "gnu" && libc != "musl" {
		return "", "", fmt.Errorf("unsupported libc %q; use auto, gnu, or musl", libc)
	}
	var target, library string
	switch goos {
	case "darwin":
		arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[goarch]
		if arch != "" {
			target = arch + "-macos"
		}
		library = "libcurl-impersonate.dylib"
	case "linux":
		if libc == "auto" {
			libc = "gnu"
			if matches, _ := filepath.Glob("/lib/ld-musl-*.so.1"); len(matches) != 0 {
				libc = "musl"
			}
		}
		arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64", "386": "i386", "arm": "arm", "riscv64": "riscv64", "loong64": "loongarch64"}[goarch]
		if arch != "" {
			target = arch + "-linux-" + libc
			if goarch == "arm" && libc == "gnu" {
				target += "eabihf"
			}
		}
		library = "libcurl-impersonate.so"
	case "windows":
		arch := map[string]string{"amd64": "x86_64", "arm64": "arm64", "386": "i686"}[goarch]
		if arch != "" {
			target = arch + "-win32"
		}
		library = "libcurl-impersonate.dll"
	case "freebsd":
		arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[goarch]
		if arch != "" {
			target = arch + "-freebsd"
		}
		library = "libcurl-impersonate.so"
	}
	asset := "libcurl-impersonate-" + releaseVersion + "." + target + ".tar.gz"
	if _, ok := releaseChecksums[asset]; !ok || target == "" {
		return "", "", fmt.Errorf("no pinned native release for %s/%s (libc %s)", goos, goarch, libc)
	}
	return asset, library, nil
}

func install(ctx context.Context, dir, asset, library, localArchive string, client *http.Client) (string, error) {
	return installArtifact(ctx, dir, asset, library, localArchive, client, func(name string) bool { return isDynamicLibrary(name, library) })
}

func installArtifact(ctx context.Context, dir, asset, artifact, localArchive string, client *http.Client, matches func(string) bool) (string, error) {
	expected, exists := releaseChecksums[asset]
	if !exists {
		return "", fmt.Errorf("unrecognized release asset %q", asset)
	}
	var source io.ReadCloser
	if localArchive != "" {
		f, err := os.Open(localArchive)
		if err != nil {
			return "", err
		}
		source = f
	} else {
		url := "https://github.com/lexiforest/curl-impersonate/releases/download/" + releaseVersion + "/" + asset
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("download %s: %w", asset, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return "", fmt.Errorf("download %s: HTTP %s", asset, resp.Status)
		}
		if resp.ContentLength > maxArchiveSize {
			resp.Body.Close()
			return "", errors.New("release archive exceeds compressed size limit")
		}
		source = resp.Body
	}
	defer source.Close()
	compressed, err := os.CreateTemp("", "curl-go-release-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(compressed.Name())
	defer compressed.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(compressed, hash), io.LimitReader(source, maxArchiveSize+1))
	if err != nil {
		return "", fmt.Errorf("read release archive: %w", err)
	}
	if n > maxArchiveSize {
		return "", errors.New("release archive exceeds compressed size limit")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("SHA-256 mismatch for %s: got %s, expected %s", asset, actual, expected)
	}
	if _, err = compressed.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	location, err := filepath.Abs(filepath.Join(dir, artifact))
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(location), 0755); err != nil {
		return "", err
	}
	out, err := os.CreateTemp(filepath.Dir(location), ".curl-go-artifact-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(out.Name())
	defer out.Close()
	if err = extractArtifact(compressed, out, artifact, matches); err != nil {
		return "", err
	}
	if err = out.Chmod(0755); err != nil {
		return "", err
	}
	if err = out.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(out.Name(), location); err != nil {
		return "", err
	}
	return location, nil
}

// We never materialize archive paths or links. Only a single regular artifact
// is copied to a fixed destination; versioned libraries are flattened.
func extractLibrary(compressed io.Reader, out io.Writer, library string) error {
	return extractArtifact(compressed, out, library, func(name string) bool { return isDynamicLibrary(name, library) })
}

func extractArtifact(compressed io.Reader, out io.Writer, artifact string, matches func(string) bool) error {
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("open release gzip: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxExpandedSize + 1}
	tr := tar.NewReader(limited)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read release tar: %w", err)
		}
		if err = safeArchiveName(h.Name); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			link := path.Join(path.Dir(h.Name), h.Linkname)
			if h.Typeflag == tar.TypeLink {
				link = h.Linkname
			}
			if path.IsAbs(h.Linkname) || strings.Contains(h.Linkname, "\\") {
				return fmt.Errorf("unsafe archive link %q -> %q", h.Name, h.Linkname)
			}
			if err = safeArchiveName(link); err != nil {
				return err
			}
			continue
		}
		if h.Size < 0 || h.Size > maxLibrarySize {
			return fmt.Errorf("archive entry %q exceeds size limit", h.Name)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		if !matches(path.Base(h.Name)) {
			continue
		}
		if found {
			return fmt.Errorf("release archive contains multiple regular %s artifacts", artifact)
		}
		if h.Size == 0 {
			return fmt.Errorf("release archive contains an empty %s artifact", artifact)
		}
		if _, err = io.CopyN(out, tr, h.Size); err != nil {
			return fmt.Errorf("extract %s: %w", artifact, err)
		}
		found = true
	}
	// Read through gzip EOF to verify its checksum, and enforce the expansion
	// limit even if trailing data follows the tar end marker.
	if _, err = io.Copy(io.Discard, limited); err != nil {
		return fmt.Errorf("verify release gzip: %w", err)
	}
	if limited.N <= 0 {
		return errors.New("release archive exceeds expanded size limit")
	}
	if !found {
		return fmt.Errorf("release archive contains no regular %s artifact", artifact)
	}
	return nil
}

func safeArchiveName(name string) error {
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || strings.Contains(part, ":") {
			return fmt.Errorf("unsafe archive path %q", name)
		}
	}
	return nil
}

func isDynamicLibrary(name, library string) bool {
	if name == library {
		return true
	}
	switch library {
	case "libcurl-impersonate.so":
		return strings.HasPrefix(name, "libcurl-impersonate.so.")
	case "libcurl-impersonate.dylib":
		return strings.HasPrefix(name, "libcurl-impersonate.") && strings.HasSuffix(name, ".dylib")
	case "libcurl-impersonate.dll":
		return name == "libcurl.dll" || name == "libcurl-impersonate-4.dll" || name == "curl-impersonate.dll"
	}
	return false
}
