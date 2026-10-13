package curlgo

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFingerprintIncrementalTLSBounds(t *testing.T) {
	for _, test := range []struct {
		name               string
		first, second      *ExtraFingerprints
		allowed, forbidden uint16
	}{
		{"minimum-then-maximum", &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_3)}, &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_3)}, tls.VersionTLS13, tls.VersionTLS12},
		{"maximum-then-minimum", &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}, &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_2)}, tls.VersionTLS12, tls.VersionTLS13},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := lowCurl(t)
			if err := c.Impersonate(string(Chrome), true); err != nil {
				t.Fatal(err)
			}
			for _, extra := range []*ExtraFingerprints{test.first, test.second} {
				if err := ApplyFingerprint(c, Fingerprint{Extra: extra}); err != nil {
					t.Fatal(err)
				}
			}
			if err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, test.allowed)); err != nil {
				t.Fatalf("allowed TLS version %#x: %v", test.allowed, err)
			}
			if err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, test.forbidden)); err == nil {
				t.Fatalf("later partial fingerprint erased earlier bound: accepted TLS %#x", test.forbidden)
			}
		})
	}
}

func TestFingerprintDefaultTLSMinimumValidatesRetainedBounds(t *testing.T) {
	for _, setup := range []string{"new-handle", "reset", "direct-default", "explicit-extra-default"} {
		t.Run(setup, func(t *testing.T) {
			c := lowCurl(t)
			switch setup {
			case "reset":
				if err := c.SetOpt(OptSSLVersion, SSLVersionTLS1_3|(SSLVersionTLS1_3<<16)); err != nil {
					t.Fatal(err)
				}
				if err := c.Reset(); err != nil {
					t.Fatal(err)
				}
			case "direct-default", "explicit-extra-default":
				if err := c.Impersonate(string(Safari153), false); err != nil {
					t.Fatal(err)
				}
				var err error
				if setup == "direct-default" {
					err = c.SetOpt(OptSSLVersion, SSLVersionDefault)
				} else {
					err = ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionDefault)}})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			// Native DEFAULT means an effective TLS1.2 minimum, even when
			// replacing an older browser profile's TLS1.0 minimum.
			assertTLSBounds(t, c, tls.VersionTLS12, tls.VersionTLS11)
			err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_1)}})
			if err == nil || !strings.Contains(err.Error(), "minimum version exceeds maximum") {
				t.Fatalf("DEFAULT's retained TLS1.2 minimum was not validated: %v", err)
			}
			assertTLSBounds(t, c, tls.VersionTLS12, tls.VersionTLS11)
		})
	}
}

func TestFingerprintTLSBoundsRespectDirectOptionsAndLifecycle(t *testing.T) {
	t.Run("direct-option-and-independent-duplicate", func(t *testing.T) {
		original := lowCurl(t)
		if err := original.SetOpt(OptSSLVersion, SSLVersionTLS1_2|(SSLVersionTLS1_2<<16)); err != nil {
			t.Fatal(err)
		}
		duplicate, err := original.Duplicate()
		if err != nil {
			t.Fatal(err)
		}
		defer duplicate.Close()
		if err := ApplyFingerprint(duplicate, Fingerprint{Extra: &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
			t.Fatal(err)
		}
		if err := original.SetOpt(OptSSLVersion, SSLVersionTLS1_3|(SSLVersionTLS1_3<<16)); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, duplicate, tls.VersionTLS12, tls.VersionTLS13)
		assertTLSBounds(t, original, tls.VersionTLS13, tls.VersionTLS12)
	})
	t.Run("reset-clears-previous-bound", func(t *testing.T) {
		c := lowCurl(t)
		if err := c.SetOpt(OptSSLVersion, SSLVersionTLS1_2|(SSLVersionTLS1_2<<16)); err != nil {
			t.Fatal(err)
		}
		if err := c.Reset(); err != nil {
			t.Fatal(err)
		}
		if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_3)}}); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, c, tls.VersionTLS13, tls.VersionTLS12)
	})
	t.Run("impersonation-preserves-explicit-bound", func(t *testing.T) {
		c := lowCurl(t)
		if err := c.SetOpt(OptSSLVersion, SSLVersionTLS1_3|SSLVersionMaxDefault); err != nil {
			t.Fatal(err)
		}
		if err := c.Impersonate(string(Safari153), true); err != nil {
			t.Fatal(err)
		}
		if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_3)}}); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, c, tls.VersionTLS13, tls.VersionTLS12)
	})
	t.Run("direct-native-profile-preserves-profile-minimum", func(t *testing.T) {
		c := lowCurl(t)
		if err := c.SetOpt(OptImpersonate, "safari153:no"); err != nil {
			t.Fatal(err)
		}
		if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, c, tls.VersionTLS11, tls.VersionTLS13)
	})
}

func TestFingerprintTLSBoundsEnvironmentAndProfileDefaults(t *testing.T) {
	t.Run("profile-minimum", func(t *testing.T) {
		for _, test := range []struct {
			profile      Profile
			acceptsTLS11 bool
		}{
			{Safari153, true}, {Chrome150, false},
		} {
			t.Run(string(test.profile), func(t *testing.T) {
				c := lowCurl(t)
				if err := c.Impersonate(string(test.profile), false); err != nil {
					t.Fatal(err)
				}
				if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_3)}}); err != nil {
					t.Fatal(err)
				}
				err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, tls.VersionTLS11))
				if (err == nil) != test.acceptsTLS11 {
					t.Fatalf("profile=%s TLS1.1 error=%v, accepts=%v", test.profile, err, test.acceptsTLS11)
				}
			})
		}
	})
	t.Run("environment-selected-profile-survives-reset", func(t *testing.T) {
		t.Setenv("CURL_IMPERSONATE", "safari153")
		c := lowCurl(t)
		if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, c, tls.VersionTLS11, tls.VersionTLS13)
		if err := c.SetOpt(OptSSLVersion, SSLVersionTLS1_3|SSLVersionMaxDefault); err != nil {
			t.Fatal(err)
		}
		if err := c.Reset(); err != nil {
			t.Fatal(err)
		}
		if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
			t.Fatal(err)
		}
		assertTLSBounds(t, c, tls.VersionTLS11, tls.VersionTLS13)
	})
}

func TestFingerprintTLSBoundsNativeCaseInsensitiveAliases(t *testing.T) {
	for _, source := range []string{"direct-native-option", "native-environment"} {
		t.Run(source, func(t *testing.T) {
			if source == "native-environment" {
				t.Setenv("CURL_IMPERSONATE", "SAFARI15_3")
			}
			c := lowCurl(t)
			if source == "direct-native-option" {
				if err := c.SetOpt(OptImpersonate, "SAFARI15_3:no"); err != nil {
					t.Fatal(err)
				}
			}
			if err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, tls.VersionTLS11)); err != nil {
				t.Fatalf("native uppercase Safari alias did not retain its TLS1.0 minimum: %v", err)
			}
			if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
				t.Fatal(err)
			}
			assertTLSBounds(t, c, tls.VersionTLS11, tls.VersionTLS13)
			if source == "native-environment" {
				if err := c.Reset(); err != nil {
					t.Fatal(err)
				}
				if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
					t.Fatal(err)
				}
				assertTLSBounds(t, c, tls.VersionTLS11, tls.VersionTLS13)
			}
		})
	}
}

func TestFingerprintTLSBoundsValidateMergedRangeBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name               string
		configured         SSLVersion
		extra              *ExtraFingerprints
		allowed, forbidden uint16
	}{
		{"lower-maximum", SSLVersionTLS1_3 | SSLVersionMaxDefault, &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}, tls.VersionTLS13, tls.VersionTLS12},
		{"raise-minimum", SSLVersionTLS1_2 | (SSLVersionTLS1_2 << 16), &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_3)}, tls.VersionTLS12, tls.VersionTLS13},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := lowCurl(t)
			if err := c.SetOpt(OptSSLVersion, test.configured); err != nil {
				t.Fatal(err)
			}
			if err := c.SetOpt(OptSSLVersion, "invalid numeric option"); err == nil {
				t.Fatal("invalid direct TLS version option was accepted")
			}
			if err := ApplyFingerprint(c, Fingerprint{Extra: test.extra}); err == nil || !strings.Contains(err.Error(), "minimum version exceeds maximum") {
				t.Fatalf("merged TLS bounds error=%v", err)
			}
			assertTLSBounds(t, c, test.allowed, test.forbidden)
		})
	}
}

func TestFingerprintJA3VersionPrecedesPartialTLSBounds(t *testing.T) {
	const ja3 = "771,4865-4866-4867-49195-49199,0-10-11-13-16-23-43-45-51-65281,29-23-24,0"
	c := lowCurl(t)
	if err := c.Impersonate(string(Chrome), false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetOpt(OptSSLVersion, SSLVersionTLS1_3|(SSLVersionTLS1_3<<16)); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFingerprint(c, Fingerprint{JA3: ja3, Extra: &ExtraFingerprints{TLSMaxVersion: fingerprintPointer(SSLVersionTLS1_2)}}); err != nil {
		t.Fatalf("JA3's TLS1.2 minimum must replace the previous TLS1.3 minimum before Extra maximum: %v", err)
	}
	assertTLSBounds(t, c, tls.VersionTLS12, tls.VersionTLS13)
	if err := ApplyFingerprint(c, Fingerprint{JA3: ja3, Extra: &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionTLS1_3)}}); err != nil {
		t.Fatalf("JA3's default maximum must replace the previous TLS1.2 cap before Extra minimum: %v", err)
	}
	assertTLSBounds(t, c, tls.VersionTLS13, tls.VersionTLS12)
}

func assertTLSBounds(t *testing.T, c *Curl, allowed, forbidden uint16) {
	t.Helper()
	if err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, allowed)); err != nil {
		t.Fatalf("allowed TLS version %#x: %v", allowed, err)
	}
	if err := performTLSBoundsRequest(t, c, tlsBoundsServer(t, forbidden)); err == nil {
		t.Fatalf("accepted TLS version %#x outside retained bounds", forbidden)
	}
}

func tlsBoundsServer(t *testing.T, version uint16) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "bounded TLS") }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func performTLSBoundsRequest(t *testing.T, c *Curl, server *httptest.Server) error {
	t.Helper()
	var body bytes.Buffer
	for _, option := range []fingerprintOption{
		{OptURL, server.URL}, {OptWriteData, &body}, {OptProxy, ""}, {OptNoProxy, "*"},
		{OptSSLVerifyPeer, false}, {OptSSLVerifyHost, 0}, {OptHTTPVersion, HTTPVersion1_1},
		{OptFreshConnect, true}, {OptTimeoutMS, 1000},
	} {
		if err := c.SetOpt(option.option, option.value); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := c.Perform(ctx)
	if err == nil && body.String() != "bounded TLS" {
		t.Fatalf("TLS server response body=%q", body.String())
	}
	return err
}
