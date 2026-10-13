package curlgo

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// All payloads remain available in addition to their decoded fields. In
// particular, an unfamiliar extension is captured rather than silently lost.
type parityTLSCapture struct {
	Records            []parityTLSRecord `json:"records"`
	RawClientHello     []byte            `json:"raw_client_hello"`
	ClientHello        parityClientHello `json:"client_hello"`
	NegotiatedVersion  uint16            `json:"negotiated_version"`
	NegotiatedCipher   uint16            `json:"negotiated_cipher"`
	NegotiatedProtocol string            `json:"negotiated_protocol"`
	ServerName         string            `json:"server_name"`
	Resumed            bool              `json:"resumed"`
}

type parityTLSRecord struct {
	Type    uint8  `json:"type"`
	Version uint16 `json:"version"`
	Length  uint16 `json:"length"`
	Payload []byte `json:"payload"`
}

type parityClientHello struct {
	JA3                           string               `json:"ja3"`
	JA3MD5                        string               `json:"ja3_md5"`
	LegacyVersion                 uint16               `json:"legacy_version"`
	Random                        []byte               `json:"random"`
	SessionID                     []byte               `json:"session_id"`
	Ciphers                       []uint16             `json:"ciphers"`
	CompressionMethods            []byte               `json:"compression_methods"`
	Extensions                    []parityTLSExtension `json:"extensions"`
	ServerNames                   []parityServerName   `json:"server_names"`
	SupportedGroups               []uint16             `json:"supported_groups"`
	PointFormats                  []byte               `json:"point_formats"`
	SignatureAlgorithms           []uint16             `json:"signature_algorithms"`
	SupportedVersions             []uint16             `json:"supported_versions"`
	ALPN                          []string             `json:"alpn"`
	ALPS                          []string             `json:"alps"`
	KeyShares                     []parityTLSKeyShare  `json:"key_shares"`
	CertificateCompression        []uint16             `json:"certificate_compression"`
	DelegatedCredentialAlgorithms []uint16             `json:"delegated_credential_algorithms"`
	PSKKeyExchangeModes           []byte               `json:"psk_key_exchange_modes"`
	RecordSizeLimit               *uint16              `json:"record_size_limit"`
	ECH                           *parityECH           `json:"ech"`
}

type parityTLSExtension struct {
	ID   uint16 `json:"id"`
	Data []byte `json:"data"`
}

type parityServerName struct {
	Type uint8  `json:"type"`
	Name string `json:"name"`
}

type parityTLSKeyShare struct {
	Group uint16 `json:"group"`
	Data  []byte `json:"data"`
}

type parityECH struct {
	Type     uint8  `json:"type"`
	KDF      uint16 `json:"kdf"`
	AEAD     uint16 `json:"aead"`
	ConfigID uint8  `json:"config_id"`
	Enc      []byte `json:"enc"`
	Payload  []byte `json:"payload"`
}

type parityCursor struct {
	data []byte
	err  error
}

func (c *parityCursor) take(n int) []byte {
	if c.err != nil || n < 0 || len(c.data) < n {
		c.err = errors.New("truncated TLS ClientHello field")
		return nil
	}
	b := c.data[:n]
	c.data = c.data[n:]
	return append([]byte{}, b...)
}

func (c *parityCursor) u8() uint8 {
	b := c.take(1)
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func (c *parityCursor) u16() uint16 {
	b := c.take(2)
	if len(b) == 0 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (c *parityCursor) uint16s(n int) []uint16 {
	b := c.take(n)
	if n%2 != 0 {
		c.err = errors.New("odd TLS uint16 vector length")
		return nil
	}
	var result []uint16
	for len(b) >= 2 {
		result = append(result, binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	return result
}

func (c *parityCursor) strings16() []string {
	list := &parityCursor{data: c.take(int(c.u16()))}
	var result []string
	for len(list.data) > 0 && list.err == nil {
		result = append(result, string(list.take(int(list.u8()))))
	}
	if list.err != nil {
		c.err = list.err
	}
	return result
}

// parseParityClientHello accepts the ClientHello body without its four-byte
// handshake header, so both TLS records and QUIC CRYPTO frames can use it.
func parseParityClientHello(data []byte) (parityClientHello, error) {
	c := &parityCursor{data: data}
	hello := parityClientHello{LegacyVersion: c.u16()}
	hello.Random = c.take(32)
	hello.SessionID = c.take(int(c.u8()))
	hello.Ciphers = c.uint16s(int(c.u16()))
	hello.CompressionMethods = c.take(int(c.u8()))
	extensions := &parityCursor{data: c.take(int(c.u16()))}
	if c.err != nil {
		return hello, c.err
	}
	if len(c.data) != 0 {
		return hello, errors.New("trailing TLS ClientHello bytes")
	}
	for len(extensions.data) > 0 && extensions.err == nil {
		id := extensions.u16()
		value := extensions.take(int(extensions.u16()))
		hello.Extensions = append(hello.Extensions, parityTLSExtension{ID: id, Data: value})
		field := &parityCursor{data: value}
		switch id {
		case 0:
			list := &parityCursor{data: field.take(int(field.u16()))}
			for len(list.data) > 0 && list.err == nil {
				hello.ServerNames = append(hello.ServerNames, parityServerName{Type: list.u8(), Name: string(list.take(int(list.u16())))})
			}
			field.err = list.err
		case 10:
			hello.SupportedGroups = field.uint16s(int(field.u16()))
		case 11:
			hello.PointFormats = field.take(int(field.u8()))
		case 13:
			hello.SignatureAlgorithms = field.uint16s(int(field.u16()))
		case 16:
			hello.ALPN = field.strings16()
		case 27:
			hello.CertificateCompression = field.uint16s(int(field.u8()))
		case 28:
			limit := field.u16()
			hello.RecordSizeLimit = &limit
		case 34:
			hello.DelegatedCredentialAlgorithms = field.uint16s(int(field.u16()))
		case 43:
			hello.SupportedVersions = field.uint16s(int(field.u8()))
		case 45:
			hello.PSKKeyExchangeModes = field.take(int(field.u8()))
		case 51:
			list := &parityCursor{data: field.take(int(field.u16()))}
			for len(list.data) > 0 && list.err == nil {
				hello.KeyShares = append(hello.KeyShares, parityTLSKeyShare{Group: list.u16(), Data: list.take(int(list.u16()))})
			}
			field.err = list.err
		case 17513, 17613:
			hello.ALPS = field.strings16()
		case 65037:
			ech := &parityECH{Type: field.u8()}
			if ech.Type == 0 {
				ech.KDF, ech.AEAD, ech.ConfigID = field.u16(), field.u16(), field.u8()
				ech.Enc = field.take(int(field.u16()))
				ech.Payload = field.take(int(field.u16()))
			}
			hello.ECH = ech
		default:
			// Unknown and deliberately opaque fields retain all raw bytes.
			continue
		}
		if field.err != nil {
			return hello, fmt.Errorf("ClientHello extension %d: %w", id, field.err)
		}
		if len(field.data) != 0 {
			return hello, fmt.Errorf("ClientHello extension %d has %d trailing bytes", id, len(field.data))
		}
	}
	if extensions.err != nil {
		return hello, extensions.err
	}
	hello.JA3 = parityJA3(hello)
	digest := md5.Sum([]byte(hello.JA3))
	hello.JA3MD5 = hex.EncodeToString(digest[:])
	return hello, nil
}

func parityJA3(hello parityClientHello) string {
	vector := func(values []uint16) string {
		var fields []string
		for _, value := range values {
			if value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value) {
				continue
			}
			fields = append(fields, strconv.Itoa(int(value)))
		}
		return strings.Join(fields, "-")
	}
	var extensions []uint16
	for _, extension := range hello.Extensions {
		extensions = append(extensions, extension.ID)
	}
	var points []uint16
	for _, format := range hello.PointFormats {
		points = append(points, uint16(format))
	}
	return strings.Join([]string{strconv.Itoa(int(hello.LegacyVersion)), vector(hello.Ciphers), vector(extensions), vector(hello.SupportedGroups), vector(points)}, ",")
}

func captureParityClientHello(data []byte) (*parityTLSCapture, error) {
	capture := &parityTLSCapture{}
	var handshake []byte
	for len(data) >= 5 {
		length := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < length+5 {
			return nil, errors.New("truncated captured TLS record")
		}
		capture.Records = append(capture.Records, parityTLSRecord{Type: data[0], Version: binary.BigEndian.Uint16(data[1:3]), Length: uint16(length), Payload: append([]byte{}, data[5:5+length]...)})
		if data[0] == 22 {
			handshake = append(handshake, data[5:5+length]...)
		}
		data = data[5+length:]
		if len(handshake) >= 4 {
			if handshake[0] != 1 {
				return nil, errors.New("first captured TLS handshake is not ClientHello")
			}
			helloLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) >= helloLength+4 {
				capture.RawClientHello = append([]byte{}, handshake[4:4+helloLength]...)
				hello, err := parseParityClientHello(capture.RawClientHello)
				capture.ClientHello = hello
				return capture, err
			}
		}
	}
	return nil, errors.New("complete TLS ClientHello was not captured")
}
