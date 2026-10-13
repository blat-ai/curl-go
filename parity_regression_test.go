package curlgo

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// This small wire fixture exercises the comparator independently of whether the
// two clients happen to agree. Its extensions include an intentionally unknown
// payload, so broad normalization cannot accidentally turn a regression green.
func regressionParityExtensions() []parityTLSExtension {
	return []parityTLSExtension{
		{ID: 0x0a0a, Data: []byte{}},
		{ID: 10, Data: []byte{0, 6, 0x0a, 0x0a, 0, 29, 0, 23}},
		{ID: 11, Data: []byte{1, 0}},
		{ID: 13, Data: []byte{0, 4, 4, 3, 8, 4}},
		{ID: 16, Data: []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}},
		{ID: 27, Data: []byte{2, 0, 2}},
		{ID: 43, Data: []byte{6, 0x0a, 0x0a, 3, 4, 3, 3}},
		{ID: 51, Data: append([]byte{0, 41, 0x0a, 0x0a, 0, 1, 0, 0, 29, 0, 32}, bytes.Repeat([]byte{7}, 32)...)},
		{ID: 60000, Data: []byte{0x10, 0x20, 0x30}},
		{ID: 0x1a1a, Data: []byte{0}},
		{ID: 21, Data: bytes.Repeat([]byte{0}, 32)},
	}
}

func regressionParityHello(extensions []parityTLSExtension) []byte {
	var body, extensionBlock bytes.Buffer
	write16 := func(out *bytes.Buffer, value uint16) {
		_ = binary.Write(out, binary.BigEndian, value)
	}
	write16(&body, tls.VersionTLS12)
	body.Write(bytes.Repeat([]byte{1}, 32))
	body.WriteByte(32)
	body.Write(bytes.Repeat([]byte{2}, 32))
	write16(&body, 6)
	for _, cipher := range []uint16{0x0a0a, 4865, 49195} {
		write16(&body, cipher)
	}
	body.Write([]byte{1, 0})
	for _, extension := range extensions {
		write16(&extensionBlock, extension.ID)
		write16(&extensionBlock, uint16(len(extension.Data)))
		extensionBlock.Write(extension.Data)
	}
	write16(&body, uint16(extensionBlock.Len()))
	body.Write(extensionBlock.Bytes())
	return body.Bytes()
}

func regressionParityCapture(t *testing.T) parityCapture {
	t.Helper()
	hello := regressionParityHello(regressionParityExtensions())
	handshake := append([]byte{1, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	record := append([]byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	capture, err := captureParityClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	capture.NegotiatedVersion = tls.VersionTLS13
	capture.NegotiatedCipher = tls.TLS_AES_128_GCM_SHA256
	capture.NegotiatedProtocol = "h2"
	capture.ServerName = "localhost"
	headers := []parityHeader{
		{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "localhost:443"},
		{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/parity?probe=1"},
		{Name: "user-agent", Value: "parity-regression"}, {Name: "x-duplicate", Value: "one"},
		{Name: "x-duplicate", Value: "two"},
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, header := range headers {
		if err := encoder.WriteField(hpack.HeaderField{Name: header.Name, Value: header.Value}); err != nil {
			t.Fatal(err)
		}
	}
	return parityCapture{TLS: capture, HTTP: parityHTTPCapture{
		Protocol: "HTTP/2.0", Method: "GET", Target: "/parity?probe=1", Headers: headers, Body: []byte{},
		HTTP2: &parityHTTP2Capture{Preface: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), HeaderBlock: block.Bytes(), Frames: []parityHTTP2Frame{
			{Type: 4, Length: 6, Payload: []byte{0, 1, 0, 0, 16, 0}, Settings: []parityHTTP2Setting{{ID: 1, Value: 4096}}},
			{Type: 1, Flags: 5, StreamID: 1, Length: uint32(block.Len()), Payload: block.Bytes(), HeaderFragment: block.Bytes()},
		}},
	}}
}

func regressionCloneCapture(t *testing.T, capture parityCapture) parityCapture {
	t.Helper()
	data, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	var clone parityCapture
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func regressionReplaceHello(t *testing.T, capture *parityCapture, mutate func(*parityClientHello)) {
	t.Helper()
	hello, err := parseParityClientHello(capture.TLS.RawClientHello)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&hello)
	capture.TLS.RawClientHello = regressionParityHello(hello.Extensions)
	capture.TLS.ClientHello, err = parseParityClientHello(capture.TLS.RawClientHello)
	if err != nil {
		t.Fatal(err)
	}
	length := len(capture.TLS.RawClientHello)
	capture.TLS.Records[0].Length = uint16(length + 4)
	capture.TLS.Records[0].Payload = append([]byte{1, byte(length >> 16), byte(length >> 8), byte(length)}, capture.TLS.RawClientHello...)
}

func regressionExtension(hello *parityClientHello, id uint16) *parityTLSExtension {
	for i := range hello.Extensions {
		if hello.Extensions[i].ID == id {
			return &hello.Extensions[i]
		}
	}
	panic("regression fixture missing extension")
}

func regressionCanonical(t *testing.T, profile Profile, capture parityCapture) []byte {
	t.Helper()
	canonical, err := canonicalParityCapture(profile, capture)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParityComparatorDetectsStableWireChanges(t *testing.T) {
	base := regressionParityCapture(t)
	want := regressionCanonical(t, Chrome110, base)
	changes := map[string]func(*parityCapture){
		"unknown-extension-payload": func(c *parityCapture) {
			regressionReplaceHello(t, c, func(h *parityClientHello) { regressionExtension(h, 60000).Data[1] ^= 0xff })
		},
		"signature-algorithm": func(c *parityCapture) {
			regressionReplaceHello(t, c, func(h *parityClientHello) { regressionExtension(h, 13).Data[3] = 1 })
		},
		"certificate-compression": func(c *parityCapture) {
			regressionReplaceHello(t, c, func(h *parityClientHello) { regressionExtension(h, 27).Data[2] = 3 })
		},
		"supported-version": func(c *parityCapture) {
			regressionReplaceHello(t, c, func(h *parityClientHello) { regressionExtension(h, 43).Data[4] = 3 })
		},
		"grease-extension-payload": func(c *parityCapture) {
			regressionReplaceHello(t, c, func(h *parityClientHello) { regressionExtension(h, 0x1a1a).Data[0] = 1 })
		},
		"header-value": func(c *parityCapture) { c.HTTP.Headers[4].Value += "-changed" },
		"duplicate-header-order": func(c *parityCapture) {
			c.HTTP.Headers[5], c.HTTP.Headers[6] = c.HTTP.Headers[6], c.HTTP.Headers[5]
		},
		"request-body": func(c *parityCapture) { c.HTTP.Body = []byte{0, 1, 0xff} },
		"http2-settings-value": func(c *parityCapture) {
			c.HTTP.HTTP2.Frames[0].Settings[0].Value++
			c.HTTP.HTTP2.Frames[0].Payload[5]++
		},
		"http2-frame-flags":  func(c *parityCapture) { c.HTTP.HTTP2.Frames[1].Flags ^= 0x20 },
		"http2-hpack":        func(c *parityCapture) { c.HTTP.HTTP2.HeaderBlock[0] ^= 1 },
		"negotiated-version": func(c *parityCapture) { c.TLS.NegotiatedVersion = tls.VersionTLS12 },
		"tls-record-version": func(c *parityCapture) { c.TLS.Records[0].Version++ },
		"tls-record-length":  func(c *parityCapture) { c.TLS.Records[0].Length++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := regressionCloneCapture(t, base)
			change(&changed)
			canonical, err := canonicalParityCapture(Chrome110, changed)
			if err != nil {
				// Invalid protocol shapes must fail before comparison.
				return
			}
			data, err := json.Marshal(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(data, want) {
				t.Fatal("stable wire mutation was hidden by normalization")
			}
		})
	}
}

func TestParityExtensionPermutationUsesProfileMetadata(t *testing.T) {
	base := regressionParityCapture(t)
	permuted := regressionCloneCapture(t, base)
	regressionReplaceHello(t, &permuted, func(hello *parityClientHello) {
		hello.Extensions[2], hello.Extensions[3] = hello.Extensions[3], hello.Extensions[2]
	})
	for _, test := range []struct {
		profile Profile
		equal   bool
	}{{Chrome99, false}, {Chrome110, true}} {
		t.Run(string(test.profile), func(t *testing.T) {
			meta, err := parityProfileMetadata(test.profile)
			if err != nil || meta.PermuteExtensions != test.equal {
				t.Fatalf("unexpected pinned permutation metadata: %+v, %v", meta, err)
			}
			equal := bytes.Equal(regressionCanonical(t, test.profile, base), regressionCanonical(t, test.profile, permuted))
			if equal != test.equal {
				t.Fatalf("extension permutation equality=%v, want %v", equal, test.equal)
			}
		})
	}
}

func TestParityCapturePreservesUnknownExtension(t *testing.T) {
	base := regressionParityCapture(t)
	want := []byte{0x10, 0x20, 0x30}
	unknown := regressionExtension(&base.TLS.ClientHello, 60000)
	if !bytes.Equal(unknown.Data, want) {
		t.Fatalf("capture lost unknown extension: %x", unknown.Data)
	}
	decoded, err := parseParityClientHello(base.TLS.RawClientHello)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, base.TLS.ClientHello) {
		t.Fatal("raw ClientHello and captured decoded fields differ")
	}
	before, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	_ = regressionCanonical(t, Chrome110, base)
	after, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("comparison mutated original raw capture evidence")
	}
}

func TestParityComparatorNormalizesFreshKeysAndRandoms(t *testing.T) {
	base := regressionParityCapture(t)
	changed := regressionCloneCapture(t, base)
	regressionReplaceHello(t, &changed, func(hello *parityClientHello) {
		share := regressionExtension(hello, 51)
		copy(share.Data[len(share.Data)-32:], bytes.Repeat([]byte{9}, 32))
	})
	// Fixed-width ClientHello random and legacy session ID are independently
	// fresh for every connection; changing their bytes is expected.
	for i := 2; i < 34; i++ {
		changed.TLS.RawClientHello[i] ^= 0xff
	}
	for i := 35; i < 67; i++ {
		changed.TLS.RawClientHello[i] ^= 0xff
	}
	copy(changed.TLS.Records[0].Payload[4:], changed.TLS.RawClientHello)
	if !bytes.Equal(regressionCanonical(t, Chrome110, base), regressionCanonical(t, Chrome110, changed)) {
		t.Fatal("fresh cryptographic randoms should not change fingerprint equality")
	}
}

func regressionECH(payloadLength int) []byte {
	value := []byte{0, 0, 1, 0, 1, 0x42, 0, 32}
	value = append(value, bytes.Repeat([]byte{0x11}, 32)...)
	value = append(value, byte(payloadLength>>8), byte(payloadLength))
	return append(value, bytes.Repeat([]byte{0x22}, payloadLength)...)
}

func regressionECHCapture(t *testing.T, ech []byte) parityCapture {
	t.Helper()
	capture := regressionParityCapture(t)
	regressionReplaceHello(t, &capture, func(hello *parityClientHello) {
		extensions := append([]parityTLSExtension{}, hello.Extensions[:len(hello.Extensions)-2]...)
		extensions = append(extensions, parityTLSExtension{ID: 65037, Data: ech}, hello.Extensions[len(hello.Extensions)-2])
		unpaddedLength := len(regressionParityHello(extensions)) + 4
		if unpaddedLength > 255 && unpaddedLength < 512 {
			extensions = append(extensions, parityTLSExtension{ID: 21, Data: make([]byte, max(1, 512-unpaddedLength-4))})
		}
		hello.Extensions = extensions
	})
	return capture
}

func TestParityECHNormalizationValidatesNativeGrammar(t *testing.T) {
	var first []byte
	for _, length := range []int{144, 176, 208, 240} {
		capture := regressionECHCapture(t, regressionECH(length))
		data := regressionCanonical(t, Chrome150, capture)
		if first == nil {
			first = data
		} else if !bytes.Equal(first, data) {
			t.Fatalf("ECH's valid random payload length %d and native padding changed equality", length)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"bad-length", func(_ []byte) []byte { return regressionECH(145) }},
		{"bad-kdf", func(b []byte) []byte { b[2] = 2; return b }},
		{"bad-aead", func(b []byte) []byte { b[4] = 2; return b }},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture := regressionECHCapture(t, test.mutate(regressionECH(144)))
			if _, err := canonicalParityCapture(Chrome150, capture); err == nil {
				t.Fatal("invalid ECH GREASE structure was normalized")
			}
		})
	}
}

func TestParityECHPaddingRejectsStructuralChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*parityClientHello)
	}{
		{"length", func(h *parityClientHello) {
			padding := regressionExtension(h, 21)
			padding.Data = padding.Data[:len(padding.Data)-1]
		}},
		{"nonzero-content", func(h *parityClientHello) { regressionExtension(h, 21).Data[0] = 1 }},
		{"missing", func(h *parityClientHello) { h.Extensions = h.Extensions[:len(h.Extensions)-1] }},
		{"position", func(h *parityClientHello) {
			last := len(h.Extensions) - 1
			h.Extensions[last], h.Extensions[2] = h.Extensions[2], h.Extensions[last]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture := regressionECHCapture(t, regressionECH(144))
			regressionReplaceHello(t, &capture, test.mutate)
			if _, err := canonicalParityCapture(Chrome150, capture); err == nil {
				t.Fatal("invalid ECH-dependent padding was normalized")
			}
		})
	}
}

func TestParityPermutationRetainsAnchoredExtensions(t *testing.T) {
	base := regressionParityCapture(t)
	want := regressionCanonical(t, Chrome110, base)
	for _, test := range []struct {
		name string
		a, b int
	}{{"leading-grease", 0, 2}, {"trailing-grease", 9, 2}, {"padding", 10, 2}} {
		t.Run(test.name, func(t *testing.T) {
			changed := regressionCloneCapture(t, base)
			regressionReplaceHello(t, &changed, func(h *parityClientHello) {
				h.Extensions[test.a], h.Extensions[test.b] = h.Extensions[test.b], h.Extensions[test.a]
			})
			canonical, err := canonicalParityCapture(Chrome110, changed)
			if err != nil {
				return
			}
			data, err := json.Marshal(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(data, want) {
				t.Fatal("anchored extension movement was hidden by permutation normalization")
			}
		})
	}
}

func TestParityQUICRandomRangesAreBounded(t *testing.T) {
	base := parityCapture{QUIC: &parityQUICCapture{InitialPackets: []parityQUICInitialPacket{
		{Version: 1, DestinationCIDLength: 8, SourceCIDLength: 3, TokenLength: 0, PacketNumber: 1, PacketNumberLength: 1},
	}}}
	for _, test := range []struct {
		name   string
		mutate func(*parityQUICInitialPacket)
	}{
		{"short-cid", func(p *parityQUICInitialPacket) { p.DestinationCIDLength = 7 }},
		{"long-cid", func(p *parityQUICInitialPacket) { p.DestinationCIDLength = 21 }},
		{"zero-number", func(p *parityQUICInitialPacket) { p.PacketNumber = 0 }},
		{"large-number", func(p *parityQUICInitialPacket) { p.PacketNumber = 1025 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := regressionCloneCapture(t, base)
			test.mutate(&changed.QUIC.InitialPackets[0])
			if _, err := canonicalParityCapture(Firefox147, changed); err == nil {
				t.Fatal("out-of-range random QUIC field was normalized")
			}
		})
	}
	first := regressionCanonical(t, Firefox147, base)
	base.QUIC.InitialPackets[0].DestinationCIDLength = 20
	base.QUIC.InitialPackets[0].PacketNumber = 1024
	base.QUIC.InitialPackets[0].PacketNumberLength = 2
	if !bytes.Equal(first, regressionCanonical(t, Firefox147, base)) {
		t.Fatal("valid native QUIC random ranges did not normalize equally")
	}
}
