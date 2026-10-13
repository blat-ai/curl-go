package curlgo

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type recordingFingerprintCurl struct {
	options map[Option]any
	fail    Option
}

func (c *recordingFingerprintCurl) SetOpt(option Option, value any) error {
	if option == c.fail {
		return errors.New("native rejected option")
	}
	if c.options == nil {
		c.options = make(map[Option]any)
	}
	c.options[option] = value
	return nil
}

func fingerprintPointer[T any](value T) *T { return &value }

func TestProfilesAndAliases(t *testing.T) {
	all := Profiles()
	if len(all) != 38 {
		t.Fatalf("got %d concrete profiles, want 38", len(all))
	}
	seen := make(map[Profile]bool)
	for _, profile := range all {
		if seen[profile] {
			t.Errorf("duplicate profile %q", profile)
		}
		seen[profile] = true
		got, err := NormalizeProfile(profile)
		if err != nil || got != profile {
			t.Errorf("NormalizeProfile(%q) = %q, %v", profile, got, err)
		}
	}
	for alias, target := range ProfileAliases() {
		got, err := NormalizeProfile(alias)
		if err != nil || got != target || !seen[target] {
			t.Errorf("NormalizeProfile(%q) = %q, %v; want %q", alias, got, err, target)
		}
	}
	if got, err := NormalizeProfile(""); got != "" || err != nil {
		t.Errorf("empty profile = %q, %v", got, err)
	}
	for _, profile := range []Profile{"Chrome", " chrome", "chrome2952", "unknown"} {
		if _, err := NormalizeProfile(profile); err == nil {
			t.Errorf("accepted unknown profile %q", profile)
		}
	}
	all[0] = "broken"
	if Profiles()[0] != Edge99 {
		t.Fatal("Profiles exposed its backing array")
	}
	aliases := ProfileAliases()
	aliases[Chrome] = Chrome99
	if ProfileAliases()[Chrome] != Chrome150 {
		t.Fatal("ProfileAliases exposed its backing map")
	}
}

func TestJA3ApplicationMatchesUpstream(t *testing.T) {
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{JA3: "771,4865-4866,0-11-10,29-23,0"}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptSSLVersion, int(SSLVersionTlsv12|SSLVersionMaxDefault))
	assertFingerprintOption(t, c, OptSSLCipherList, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
	assertFingerprintOption(t, c, OptTLSExtensionOrder, "0-11-10")
	assertFingerprintOption(t, c, OptSSLECCurves, "X25519:P-256")
}

func TestJA3PaddingAndPermutation(t *testing.T) {
	for _, order := range []string{"0-21-11-10", "21-0-11-10", "0-11-10-21"} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, Fingerprint{JA3: "771,4865-4866," + order + ",29-23,0"}); err != nil {
			t.Fatal(err)
		}
		assertFingerprintOption(t, c, OptTLSExtensionOrder, "0-11-10")
	}
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{
		JA3:   "771,4865-4866,0-11-10,29-23,0",
		Extra: &ExtraFingerprints{TLSPermuteExtensions: fingerprintPointer(true)},
	}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptTLSExtensionOrder, "0-11-10")
	assertFingerprintOption(t, c, OptSSLPermuteExtensions, 1)
}

func TestJA3EnablesRequestedNativeCapabilities(t *testing.T) {
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{
		JA3: "771,4865-4866-4867-49195-49199,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-17613-65037-65281,4588-29-23-24,0",
	}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptSSLEnableALPS, 1)
	assertFingerprintOption(t, c, OptTLSUseNewALPSCodepoint, 1)
	assertFingerprintOption(t, c, OptTLSStatusRequest, 1)
	assertFingerprintOption(t, c, OptTLSSignedCertTimestamps, 1)
	assertFingerprintOption(t, c, OptSSLCertCompression, "brotli")
	assertFingerprintOption(t, c, OptEch, "grease")
	assertFingerprintOption(t, c, OptTLSRecordSizeLimit, 16385)
}

func TestAkamaiApplicationMatchesUpstream(t *testing.T) {
	for _, separator := range []string{";", ","} {
		c := &recordingFingerprintCurl{}
		fp := Fingerprint{Akamai: "1:65536" + separator + "2:0|15663105|0|m,a,s,p"}
		if err := applyFingerprint(c, fp); err != nil {
			t.Fatal(err)
		}
		assertFingerprintOption(t, c, OptHTTPVersion, int(HTTPVersionV20))
		assertFingerprintOption(t, c, OptHTTP2Settings, "1:65536;2:0")
		assertFingerprintOption(t, c, OptHTTP2WindowUpdate, 15663105)
		assertFingerprintOption(t, c, OptHTTP2Streams, "")
		assertFingerprintOption(t, c, OptHTTP2PseudoHeadersOrder, "masp")
	}
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{Akamai: "1:65536|15663105|1:0:0:201,3:1:1:100|m,s,p,a"}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptHTTP2Streams, "1:0:0:201,3:1:1:100")
	assertFingerprintOption(t, c, OptHTTP2PseudoHeadersOrder, "mspa")
}

func TestPerkApplicationPreservesHTTPVersion(t *testing.T) {
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{Perk: "1:2|m,a,s,p|3:4"}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptHTTP3Settings, "1:2")
	assertFingerprintOption(t, c, OptHTTP3PseudoHeadersOrder, "masp")
	assertFingerprintOption(t, c, OptQUICTransportParameters, "3:4")
	if _, ok := c.options[OptHTTPVersion]; ok {
		t.Fatal("Perk changed explicitly selected HTTP version")
	}
}

func TestPerkNativeExtendedGrammar(t *testing.T) {
	for _, parameters := range []string{
		"1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:;17:1@1,GREASE;32:65536;12583:AUTO;18258:1;GREASE",
		"1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:;17:1@1,GREASE;32:65536;12583:RANDOM;12584:0x4f524947;GREASE",
		"1:30000;4:25165824;5:12582912;6:1048576;7:1048576;8:100;9:100;11:20;14:8;15:AUTO;17:1@GREASE,1;GREASE;32:65535",
	} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, Fingerprint{Perk: "1:65536;6:262144;7:100;51:1;GREASE|masp|" + parameters}); err != nil {
			t.Fatal(err)
		}
		assertFingerprintOption(t, c, OptQUICTransportParameters, parameters)
	}
	for _, parameters := range []string{
		"15:1", "15", "17:GREASE@1", "17:1@", "17:1@1,", "17:1@+1",
		"17:4294967296@1", "12584:0x", "12584:0xabc", "12584:0xgh", "0:0", "2:0",
		"4", "4:1;4:2", "3:4611686018427387904", "12583:BAD", "GREASE\x00",
	} {
		if err := ValidateFingerprint(Fingerprint{Perk: "1:2|masp|" + parameters}); err == nil {
			t.Errorf("accepted invalid native QUIC grammar %q", parameters)
		}
	}
}

func TestExtraFingerprintApplicationMatchesUpstream(t *testing.T) {
	c := &recordingFingerprintCurl{}
	extra := &ExtraFingerprints{
		TLSSignatureAlgorithms:  []string{"rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"},
		TLSMinVersion:           fingerprintPointer(SSLVersionTlsv13),
		TLSGrease:               fingerprintPointer(true),
		TLSPermuteExtensions:    fingerprintPointer(true),
		TLSCertCompression:      fingerprintPointer("zlib"),
		TLSDelegatedCredential:  fingerprintPointer("ecdsa_secp256r1_sha256"),
		TLSRecordSizeLimit:      fingerprintPointer(4001),
		HTTP2StreamWeight:       fingerprintPointer(128),
		HTTP2StreamExclusive:    fingerprintPointer(0),
		HTTP2NoPriority:         fingerprintPointer(true),
		HeaderOrder:             fingerprintPointer("User-Agent,Host,Connection"),
		SplitCookies:            fingerprintPointer(true),
		FormBoundary:            fingerprintPointer("webkit"),
		HTTP3SigHashAlgs:        fingerprintPointer("rsa_pss_rsae_sha256"),
		HTTP3TLSExtensionOrder:  fingerprintPointer("0-10-13"),
		TLSTrustAnchors:         []string{"2.5.4.3", "2.5.4.10"},
		HTTP3TLSSupportedGroups: []string{"X25519Kyber768", "P-256"},
	}
	if err := applyFingerprint(c, Fingerprint{Extra: extra}); err != nil {
		t.Fatal(err)
	}
	expected := map[Option]any{
		OptSSLSigHashAlgs: "rsa_pss_rsae_sha256,ecdsa_secp256r1_sha256",
		OptSSLVersion:     int(SSLVersionTlsv13 | SSLVersionMaxDefault),
		OptTLSGrease:      1, OptSSLPermuteExtensions: 1,
		OptSSLCertCompression: "zlib", OptTLSDelegatedCredentials: "ecdsa_secp256r1_sha256",
		OptTLSRecordSizeLimit: 4001, OptStreamWeight: 128, OptStreamExclusive: 0,
		OptHTTP2NoPriority: 1, OptHTTPHeaderOrder: "User-Agent,Host,Connection",
		OptSplitCookies: 1, OptFormBoundary: "webkit", OptHTTP3SigHashAlgs: "rsa_pss_rsae_sha256",
		OptHTTP3TLSExtensionOrder: "0-10-13", OptTLSTrustAnchors: "2.5.4.3,2.5.4.10",
		OptHTTP3SSLECCurves: "X25519Kyber768Draft00:P-256",
	}
	if !reflect.DeepEqual(c.options, expected) {
		t.Fatalf("got options %#v; want %#v", c.options, expected)
	}
}

func TestUnspecifiedExtraPreservesProfileDefaults(t *testing.T) {
	for _, fp := range []Fingerprint{{}, {Extra: &ExtraFingerprints{}}} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, fp); err != nil {
			t.Fatal(err)
		}
		if len(c.options) != 0 {
			t.Fatalf("empty fingerprint changed options %#v", c.options)
		}
	}
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{
		TLSGrease: fingerprintPointer(false), HTTP2NoPriority: fingerprintPointer(false),
		SplitCookies: fingerprintPointer(false), TLSRecordSizeLimit: fingerprintPointer(0),
		TLSCertCompression: fingerprintPointer(""), TLSTrustAnchors: []string{},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, option := range []Option{OptTLSGrease, OptHTTP2NoPriority, OptSplitCookies, OptTLSRecordSizeLimit} {
		assertFingerprintOption(t, c, option, 0)
	}
	assertFingerprintOption(t, c, OptSSLCertCompression, "")
	assertFingerprintOption(t, c, OptTLSTrustAnchors, "")
}

func TestQUICInitialPacketNumberMatchesUpstream(t *testing.T) {
	for _, value := range []int{-1, 0, 1, 2147483647} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{QUICInitialPacketNumber: &value}}); err != nil {
			t.Fatal(err)
		}
		assertFingerprintOption(t, c, OptQUICInitialPacketNumber, value)
	}
}

func TestExplicitEmptyHeaderOrderClearsNativeOption(t *testing.T) {
	fingerprint := Fingerprint{Extra: &ExtraFingerprints{HeaderOrder: fingerprintPointer("")}}
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, fingerprint); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptHTTPHeaderOrder, nil)
	if len(c.options) != 1 {
		t.Fatalf("clearing header order changed other options: %#v", c.options)
	}
}

func TestNativeExplicitEmptyHeaderOrder(t *testing.T) {
	c, err := NewCurl()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetOpt(OptHTTPHeaderOrder, "Accept,Host,User-Agent"); err != nil {
		t.Fatal(err)
	}
	// The native setter rejects a nonnil empty C string, and accepts NULL to
	// clear ordering. An explicit empty Go override must map to that NULL.
	if err := ApplyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{HeaderOrder: fingerprintPointer("")}}); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintOverridePrecedence(t *testing.T) {
	c := &recordingFingerprintCurl{}
	if err := applyFingerprint(c, Fingerprint{
		JA3:   "771,4865-4866,0-11-10-27,29-23,0",
		Extra: &ExtraFingerprints{TLSCertCompression: fingerprintPointer("zlib")},
	}); err != nil {
		t.Fatal(err)
	}
	assertFingerprintOption(t, c, OptSSLCertCompression, "zlib")
}

func TestInvalidFingerprintsNeverChangeHandle(t *testing.T) {
	invalid := []Fingerprint{
		{JA3: ",,,,"}, {JA3: "771,4865,0,29"},
		{JA3: "770,4865,0,29,0"}, {JA3: "772,4865,0,29,0"},
		{JA3: "771,65535,0,29,0"}, {JA3: "771,4865-4865,0,29,0"},
		{JA3: "771,4865,0-0,29,0"}, {JA3: "771,4865,0-999,29,0"},
		{JA3: "771,4865,0-41,29,0"}, {JA3: "771,4865,0-57,29,0"},
		{JA3: "771,4865,0-17513-17613,29,0"}, {JA3: "771,4865,0,999,0"},
		{JA3: "771,4865,0,29,1"}, {JA3: "771,4865,0-,29,0"},
		{JA3: "771,4865,0,29,0\x00"}, {JA3: "771,4865,0,+29,0"},
		{Akamai: "|||"}, {Akamai: "1:65536|1|0|masp|extra"},
		{Akamai: "1:65536;1:3|1|0|masp"}, {Akamai: "10:1|1|0|masp"},
		{Akamai: "2:2|1|0|masp"}, {Akamai: "4:2147483648|1|0|masp"},
		{Akamai: "5:16383|1|0|masp"}, {Akamai: "1:4294967296|1|0|masp"},
		{Akamai: "1:1|-1|0|masp"}, {Akamai: "1:1|2147483648|0|masp"},
		{Akamai: "1:1|1|0|mmaa"}, {Akamai: "1:1|1|0|massp"},
		{Akamai: "1:1|1|1:0:1:20|masp"}, {Akamai: "1:1|1|1:0:0:257|masp"},
		{Akamai: "1:1|1|1:2:0:20|masp"}, {Akamai: "1:1|1|1:0:0:20,1:0:0:21|masp"},
		{Perk: "1:2|masp"}, {Perk: "1:2|masp|3:4611686018427387904"},
		{Perk: "1:2;1:3|masp|3:4"},
		{Extra: &ExtraFingerprints{TLSMinVersion: fingerprintPointer(SSLVersionSslv3)}},
		{Extra: &ExtraFingerprints{TLSCertCompression: fingerprintPointer("gzip")}},
		{Extra: &ExtraFingerprints{TLSSignatureAlgorithms: []string{"invalid"}}},
		{Extra: &ExtraFingerprints{TLSRecordSizeLimit: fingerprintPointer(63)}},
		{Extra: &ExtraFingerprints{HTTP2StreamWeight: fingerprintPointer(257)}},
		{Extra: &ExtraFingerprints{HTTP2StreamExclusive: fingerprintPointer(2)}},
		{Extra: &ExtraFingerprints{HeaderOrder: fingerprintPointer("x,x")}},
		{Extra: &ExtraFingerprints{HeaderOrder: fingerprintPointer("x\r\ny")}},
		{Extra: &ExtraFingerprints{FormBoundary: fingerprintPointer("true")}},
		{Extra: &ExtraFingerprints{QUICInitialPacketNumber: fingerprintPointer(-2)}},
		{Extra: &ExtraFingerprints{QUICCIDLength: fingerprintPointer("invalid")}},
		{Extra: &ExtraFingerprints{TLSTrustAnchors: []string{".3"}}},
		// Earlier valid settings must not be applied before a later error.
		{JA3: "771,4865,0-11-10,29,0", Akamai: "|||"},
	}
	for i, fp := range invalid {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, fp); err == nil {
			t.Errorf("case %d accepted invalid fingerprint %#v", i, fp)
		}
		if len(c.options) != 0 {
			t.Errorf("case %d changed native options before validation: %#v", i, c.options)
		}
	}
}

func TestFingerprintNativeErrorIncludesOption(t *testing.T) {
	c := &recordingFingerprintCurl{fail: OptTLSGrease}
	err := applyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSGrease: fingerprintPointer(true)}})
	if err == nil || !strings.Contains(err.Error(), "native rejected option") || !strings.Contains(err.Error(), "1011") {
		t.Fatalf("got error %v", err)
	}
	if err := ApplyFingerprint(nil, Fingerprint{}); err == nil {
		t.Fatal("nil Curl accepted")
	}
}

func assertFingerprintOption(t *testing.T, c *recordingFingerprintCurl, option Option, want any) {
	t.Helper()
	if got, ok := c.options[option]; !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("option %d = %#v (present %t), want %#v", option, got, ok, want)
	}
}

// These are the upstream customized-JA3 cases, exercised against a local TLS
// server instead of depending on the external browserleaks service.
func TestNativeCustomizedJA3(t *testing.T) {
	const ciphers = "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53"
	cases := []struct {
		name       string
		ciphers    string
		extensions string
		groups     string
	}{
		{"chrome126", ciphers, "0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16", "25497-29-23-24"},
		{"cipher_order", "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171", "0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16", "25497-29-23-24"},
		{"extension_order", ciphers, "65037-65281-0-11-23-5-18-27-16-17513-10-35-43-45-13-51", "25497-29-23-24"},
		{"without_ech", ciphers, "65281-0-11-23-5-18-27-16-17513-10-35-43-45-13-51", "25497-29-23-24"},
		{"without_ocsp_sct", ciphers, "65281-0-11-23-27-16-17513-10-35-43-45-13-51", "25497-29-23-24"},
		{"without_ticket", ciphers, "65281-0-11-23-5-18-27-16-17513-10-43-45-13-51", "25497-29-23-24"},
		{"new_alps", ciphers, "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281", "4588-29-23-24"},
		{"group_order", ciphers, "0-65037-27-51-13-43-5-18-17513-65281-23-10-45-35-11-16", "25497-24-23-29"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ja3 := "771," + tc.ciphers + "," + tc.extensions + "," + tc.groups + ",0"
			wire := performFingerprintTLSExchange(t, Chrome120, Fingerprint{JA3: ja3})
			hello, err := parseProfileClientHello(wire.Hello)
			if err != nil {
				t.Fatal(err)
			}
			if hello.LegacyVersion != 771 {
				t.Errorf("legacy TLS version=%d, want 771", hello.LegacyVersion)
			}
			if got := fingerprintIDs(withoutProfileGrease(hello.Ciphers)); got != tc.ciphers {
				t.Errorf("cipher fingerprint=%s, want %s", got, tc.ciphers)
			}
			if got := fingerprintIDs(withoutProfileGrease(hello.Groups)); got != tc.groups {
				t.Errorf("group fingerprint=%s, want %s", got, tc.groups)
			}
			var extensions []uint16
			for _, id := range withoutProfileGrease(hello.ExtensionOrder) {
				if id != 21 { // Native TLS padding is managed by BoringSSL.
					extensions = append(extensions, id)
				}
			}
			if got := fingerprintIDs(extensions); got != tc.extensions {
				t.Errorf("extension fingerprint=%s, want %s", got, tc.extensions)
			}
		})
	}
}

func TestNativeJA3PermutationRestrictsExtensionMembership(t *testing.T) {
	const extensions = "0-10-11-13-16-23-43-45-51-65281"
	const ja3 = "771,4865-4866-4867-49195-49199," + extensions + ",29-23-24,0"
	want := strings.Split(extensions, "-")
	sort.Strings(want)
	changed := false
	for i := 0; i < 8; i++ {
		// Firefox inherits delegated-credential and record-size-limit options.
		// Permutation must shuffle the requested list, without leaking either
		// inherited extension back into the custom JA3 membership.
		wire := performFingerprintTLSExchange(t, Firefox147, Fingerprint{
			JA3:   ja3,
			Extra: &ExtraFingerprints{TLSPermuteExtensions: fingerprintPointer(true)},
		})
		hello, err := parseProfileClientHello(wire.Hello)
		if err != nil {
			t.Fatal(err)
		}
		var ids []uint16
		for _, id := range withoutProfileGrease(hello.ExtensionOrder) {
			if id != 21 { // BoringSSL determines TLS padding from message length.
				ids = append(ids, id)
			}
		}
		order := fingerprintIDs(ids)
		changed = changed || order != extensions
		got := strings.Split(order, "-")
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("permuted JA3 extension membership=%v, want %v (wire order %s)", got, want, order)
		}
	}
	if !changed {
		t.Fatal("JA3 extension list remained fixed despite explicit permutation")
	}
}

func TestNativeCustomizedAkamai(t *testing.T) {
	for _, akamai := range []string{
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"2:0;4:4194304;3:100|10485760|0|m,s,p,a",
		"2:0,4:4194304,3:100|10485760|0|m,s,p,a",
	} {
		t.Run(akamai, func(t *testing.T) {
			wire := performFingerprintTLSExchange(t, Firefox147, Fingerprint{Akamai: akamai})
			fields := strings.Split(akamai, "|")
			if wire.Settings != strings.ReplaceAll(fields[0], ",", ";") {
				t.Errorf("settings=%q, want %q", wire.Settings, fields[0])
			}
			if strconv.FormatUint(uint64(wire.WindowUpdate), 10) != fields[1] {
				t.Errorf("window=%d, want %s", wire.WindowUpdate, fields[1])
			}
			if wire.PseudoHeaders != strings.ReplaceAll(fields[3], ",", "") {
				t.Errorf("pseudo headers=%q, want %q", wire.PseudoHeaders, fields[3])
			}
		})
	}
}

func TestNativeExtraFingerprints(t *testing.T) {
	algorithms := []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"}
	wire := performFingerprintTLSExchange(t, Chrome120, Fingerprint{Extra: &ExtraFingerprints{
		TLSSignatureAlgorithms: algorithms,
		TLSGrease:              fingerprintPointer(false),
		TLSCertCompression:     fingerprintPointer("zlib"),
	}})
	hello, err := parseProfileClientHello(wire.Hello)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hello.SignatureAlgorithms, []uint16{0x0403, 0x0804, 0x0401}) {
		t.Fatalf("signature algorithms=%v", hello.SignatureAlgorithms)
	}
	if len(withoutProfileGrease(hello.Ciphers)) != len(hello.Ciphers) {
		t.Fatal("TLSGrease=false still emitted GREASE ciphers")
	}
}

func TestRelativeTrustAnchorValidation(t *testing.T) {
	for _, oid := range []string{
		"3.5.4", "42", "7.1000", "0", "18446744073709551615",
		strings.Repeat("127.", 254) + "127", // Exactly 255 encoded bytes.
	} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSTrustAnchors: []string{oid}}}); err != nil {
			t.Errorf("valid relative OID %q: %v", oid, err)
			continue
		}
		assertFingerprintOption(t, c, OptTLSTrustAnchors, oid)
	}
	for _, oid := range []string{
		"", ".3", "3.", "3..5", "-1", "+1", "1.-1", "1.a", "18446744073709551616",
		strings.Repeat("127.", 255) + "127", // 256 encoded bytes.
		strings.Repeat("128.", 127) + "128", // 256 encoded bytes; each arc takes two.
	} {
		c := &recordingFingerprintCurl{}
		if err := applyFingerprint(c, Fingerprint{Extra: &ExtraFingerprints{TLSTrustAnchors: []string{oid}}}); err == nil {
			t.Errorf("accepted invalid relative OID %q", oid)
		}
		if len(c.options) != 0 {
			t.Errorf("invalid relative OID changed native handle: %#v", c.options)
		}
	}
}

func TestNativeRelativeTrustAnchors(t *testing.T) {
	for _, oid := range []string{"3.5.4", "42", "7.1000"} {
		t.Run(oid, func(t *testing.T) {
			// Native parsing occurs during the real TLS handshake, so a
			// successful HTTP/2 exchange verifies the native relative-OID API.
			wire := performFingerprintTLSExchange(t, Chrome120, Fingerprint{Extra: &ExtraFingerprints{TLSTrustAnchors: []string{oid}}})
			if wire.ALPN != "h2" {
				t.Errorf("TLS negotiated %q, want h2", wire.ALPN)
			}
		})
	}
}

func performFingerprintTLSExchange(t *testing.T, profile Profile, fingerprint Fingerprint) profileWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	certificate := profileTestCertificate(t)
	done := make(chan profileWire, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- profileWire{Err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		recorded := &profileRecordingConn{Conn: conn}
		tlsConn := tls.Server(recorded, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			done <- profileWire{Err: fmt.Errorf("TLS handshake: %w", err)}
			return
		}
		wire := readProfileHTTP2(tlsConn)
		wire.Hello, err = recorded.clientHello()
		wire.ALPN = tlsConn.ConnectionState().NegotiatedProtocol
		if wire.Err == nil {
			wire.Err = err
		}
		done <- wire
		drainCaptureHTTP2(tlsConn)
	}()
	c, err := NewCurl()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Impersonate(string(profile), true); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFingerprint(c, fingerprint); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	var body bytes.Buffer
	for _, option := range []fingerprintOption{
		{OptURL, "https://localhost:" + port + "/fingerprint"}, {OptWriteData, &body},
		{OptProxy, ""}, {OptNoProxy, "*"}, {OptTimeoutMS, 10000},
		{OptSSLVerifyPeer, false}, {OptSSLVerifyHost, 0},
	} {
		if err := c.SetOpt(option.option, option.value); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := c.Perform(ctx); err != nil {
		t.Fatal(err)
	}
	if body.String() != "ok" {
		t.Fatalf("response body=%q", body.String())
	}
	return awaitProfileWire(t, done)
}

func fingerprintIDs(ids []uint16) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(int(id))
	}
	return strings.Join(parts, "-")
}
