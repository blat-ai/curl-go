package curlgo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
)

var parityMetadata struct {
	sync.Once
	profiles map[string]profileSignature
	err      error
}

func parityProfileMetadata(profile Profile) (profileSignature, error) {
	parityMetadata.Do(func() {
		data, err := os.ReadFile("testdata/profile_signatures.json")
		if err != nil {
			parityMetadata.err = err
			return
		}
		var fixture struct {
			Release  string                      `json:"native_release"`
			Profiles map[string]profileSignature `json:"profiles"`
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			parityMetadata.err = err
			return
		}
		if fixture.Release != NativeVersion {
			parityMetadata.err = errors.New("parity normalization metadata does not match pinned release")
			return
		}
		parityMetadata.profiles = fixture.Profiles
	})
	if parityMetadata.err != nil {
		return profileSignature{}, parityMetadata.err
	}
	name, err := NormalizeProfile(profile)
	if err != nil {
		return profileSignature{}, err
	}
	meta, ok := parityMetadata.profiles[string(name)]
	if !ok {
		return profileSignature{}, fmt.Errorf("missing normalization metadata for %q", name)
	}
	return meta, nil
}

// Canonicalization is deliberately a protocol allowlist. It retains every
// unknown extension/frame byte, all headers (including order and duplicates),
// bodies, HPACK/QPACK bytes, and nonrandom settings. Random keys and identifiers
// are compared by their structure; optional permutation comes from pinned source
// metadata, never inferred by sorting whichever fields happen to differ.
func canonicalParityCapture(profile Profile, capture parityCapture) (map[string]any, error) {
	meta, err := parityProfileMetadata(profile)
	if err != nil {
		return nil, err
	}
	// Work on a deep copy: raw evidence remains intact for saved artifacts.
	data, err := json.Marshal(capture)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		return nil, err
	}
	result := map[string]any{}
	if capture.TLS != nil {
		canonical, err := canonicalParityTLS(*capture.TLS, meta)
		if err != nil {
			return nil, err
		}
		result["tls"] = canonical
	}
	if h2 := capture.HTTP.HTTP2; h2 != nil {
		var frames []parityHTTP2Frame
		for _, frame := range h2.Frames {
			// A SETTINGS acknowledgement can arrive before or after request
			// END_STREAM depending on scheduling. It has no configurable
			// payload. The capture includes it; fingerprint equality does not.
			if frame.Type == 4 && frame.Flags == 1 && frame.StreamID == 0 && len(frame.Payload) == 0 {
				continue
			}
			frames = append(frames, frame)
		}
		h2.Frames = frames
	}
	if h3 := capture.HTTP.HTTP3; h3 != nil {
		canonical, err := canonicalParityHTTP3(*h3, meta)
		if err != nil {
			return nil, err
		}
		result["http3"] = canonical
		capture.HTTP.HTTP3 = nil
	}
	result["http"] = capture.HTTP
	if quic := capture.QUIC; quic != nil {
		if len(quic.InitialPackets) == 0 {
			return nil, errors.New("HTTP/3 has no captured QUIC Initial")
		}
		// Subsequent packet counts/sizes and retransmissions depend on
		// network scheduling. The initial offer's version, IDs, token and
		// packet number are fingerprint parameters and remain checked.
		first := quic.InitialPackets[0]
		cid := any(first.DestinationCIDLength)
		if meta.QUICCIDLength == "firefox" {
			if first.DestinationCIDLength < 8 || first.DestinationCIDLength > 20 {
				return nil, fmt.Errorf("Firefox QUIC destination CID length %d outside native range 8..20", first.DestinationCIDLength)
			}
			cid = "native-firefox-random-8..20"
		}
		number := any(first.PacketNumber)
		numberLength := any(first.PacketNumberLength)
		if meta.QUICInitialPacketNumber < 0 {
			if first.PacketNumber < 1 || first.PacketNumber > 1024 {
				return nil, fmt.Errorf("random QUIC packet number %d outside native range 1..1024", first.PacketNumber)
			}
			number = "native-firefox-random-1..1024"
			// ngtcp2 v1.20.0 pktns_select_pkt_numlen with no packet ACKed
			// chooses from 2*PN+1: one byte through PN127, then two.
			expectedLength := 1
			if first.PacketNumber >= 128 {
				expectedLength = 2
			}
			if first.PacketNumberLength != expectedLength {
				return nil, fmt.Errorf("QUIC initial packet number %d uses %d bytes; native encoder requires %d", first.PacketNumber, first.PacketNumberLength, expectedLength)
			}
			numberLength = "native-encoding-derived-from-random-packet-number"
		}
		parameters, err := canonicalParityQUICParameters(quic.TransportParameters, meta)
		if err != nil {
			return nil, err
		}
		result["quic"] = map[string]any{
			"version": first.Version, "destination_cid_length": cid,
			"source_cid_length": first.SourceCIDLength, "token_length": first.TokenLength,
			"initial_packet_number": number, "packet_number_length": numberLength,
			"transport_parameters": parameters,
		}
	}
	return result, nil
}

func parityGrease(id uint16) bool {
	return id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id)
}

// Pinned BoringSSL ssl/extensions.cc:ssl_add_clienthello_tlsext validates the
// RFC 7685/F5 padding and nonempty-final-extension workaround. Fresh ECH offers
// vary in length, so padding presence and length vary with them. We normalize
// only padding that exactly follows that algorithm, including its position.
func parityValidateECHPadding(raw []byte, extensions []parityTLSExtension) (int, error) {
	unpadded := len(raw) + 4
	paddingIndex, paddingLength := -1, 0
	var last *parityTLSExtension
	for i := range extensions {
		extension := &extensions[i]
		if extension.ID == 21 {
			if paddingIndex >= 0 {
				return 0, errors.New("duplicate TLS padding extension")
			}
			paddingIndex, paddingLength = i, len(extension.Data)
			unpadded -= 4 + paddingLength
			if !bytes.Equal(extension.Data, make([]byte, paddingLength)) {
				return 0, errors.New("TLS padding contains nonzero bytes")
			}
		} else {
			last = extension
		}
	}
	messageLength, expected := unpadded, 0
	if last != nil && last.ID != 41 && len(last.Data) == 0 {
		expected = 1
		messageLength += 5
	}
	if messageLength > 255 && messageLength < 512 {
		expected = max(1, 512-unpadded-4)
	}
	if expected == 0 {
		if paddingIndex >= 0 {
			return 0, errors.New("TLS padding present outside native padding conditions")
		}
		return 0, nil
	}
	if paddingIndex < 0 || paddingLength != expected {
		return 0, fmt.Errorf("TLS padding length=%d present=%t; native rule requires %d", paddingLength, paddingIndex >= 0, expected)
	}
	if paddingIndex != len(extensions)-1 && !(paddingIndex == len(extensions)-2 && extensions[len(extensions)-1].ID == 41) {
		return 0, errors.New("TLS padding must be last before optional PSK")
	}
	return 4 + paddingLength, nil
}

func canonicalParityTLS(capture parityTLSCapture, meta profileSignature) (map[string]any, error) {
	hello, err := parseParityClientHello(capture.RawClientHello)
	if err != nil {
		return nil, err
	}
	paddingBytes := 0
	if len(capture.Records) > 0 {
		var withoutPadding []parityTLSExtension
		for i, extension := range hello.Extensions {
			if extension.ID != 21 {
				withoutPadding = append(withoutPadding, extension)
			} else if i != len(hello.Extensions)-1 && !(i == len(hello.Extensions)-2 && hello.Extensions[len(hello.Extensions)-1].ID == 41) {
				return nil, errors.New("TLS padding must be last before optional PSK")
			}
		}
		if meta.Grease {
			// BoringSSL adds these two extensions outside the permutation
			// loop. Validate their anchors before sorting real extensions.
			if len(withoutPadding) < 2 || !parityGrease(withoutPadding[0].ID) || len(withoutPadding[0].Data) != 0 || !parityGrease(withoutPadding[len(withoutPadding)-1].ID) || !bytes.Equal(withoutPadding[len(withoutPadding)-1].Data, []byte{0}) {
				return nil, errors.New("native TLS GREASE extensions must anchor first(empty) and last(00), before optional padding")
			}
		}
		if meta.ECH && hello.ECH != nil {
			paddingBytes, err = parityValidateECHPadding(capture.RawClientHello, hello.Extensions)
			if err != nil {
				return nil, err
			}
		}
	}
	ciphers := append([]uint16(nil), hello.Ciphers...)
	for i, id := range ciphers {
		if meta.Grease && parityGrease(id) {
			ciphers[i] = 0x0a0a
		}
	}
	var extensions []map[string]any
	echPayloadVariation := 0
	for _, extension := range hello.Extensions {
		if extension.ID == 21 && paddingBytes > 0 {
			// Its exact source-defined length/presence has been validated.
			// ECH's randomly chosen ciphertext length changes this padding.
			continue
		}
		id := extension.ID
		value := any(hex.EncodeToString(extension.Data))
		if meta.Grease && parityGrease(id) {
			id = 0x0a0a
		} else {
			switch id {
			case 10, 43:
				// Normalize reserved GREASE IDs while preserving list positions.
				payload := append([]byte(nil), extension.Data...)
				prefix := 2
				if id == 43 {
					prefix = 1
				}
				for i := prefix; i+1 < len(payload); i += 2 {
					if meta.Grease && parityGrease(binary.BigEndian.Uint16(payload[i:i+2])) {
						binary.BigEndian.PutUint16(payload[i:i+2], 0x0a0a)
					}
				}
				value = hex.EncodeToString(payload)
			case 51:
				var shares []map[string]any
				for _, share := range hello.KeyShares {
					group := share.Group
					key := any(hex.EncodeToString(share.Data))
					if meta.Grease && parityGrease(group) {
						group, key = 0x0a0a, hex.EncodeToString(share.Data)
					} else if length, known := map[uint16]int{23: 65, 24: 97, 25: 133, 29: 32, 256: 256, 257: 384, 25497: 1216, 4588: 1216}[group]; known {
						if len(share.Data) != length {
							return nil, fmt.Errorf("TLS key share group %d length=%d, want %d", group, len(share.Data), length)
						}
						if group >= 23 && group <= 25 && share.Data[0] != 4 {
							return nil, fmt.Errorf("TLS group %d point is not uncompressed", group)
						}
						key = "fresh-public-key"
					}
					shares = append(shares, map[string]any{"group": group, "length": len(share.Data), "key": key})
				}
				value = shares
			case 65037:
				if meta.ECH && hello.ECH != nil && hello.ECH.Type == 0 {
					// Pinned BoringSSL setup_ech_grease selects 32*N+16
					// bytes for N=4..7. Validate its exact structural grammar
					// before masking this random length and fresh ciphertext.
					length := len(hello.ECH.Payload)
					if hello.ECH.KDF != 1 || (hello.ECH.AEAD != 1 && hello.ECH.AEAD != 3) || len(hello.ECH.Enc) != 32 || length < 144 || length > 240 || (length-144)%32 != 0 {
						return nil, fmt.Errorf("ECH GREASE does not match pinned BoringSSL structure: KDF=%d AEAD=%d enc=%d payload=%d", hello.ECH.KDF, hello.ECH.AEAD, len(hello.ECH.Enc), length)
					}
					echPayloadVariation = length - 144
					value = map[string]any{
						"type": hello.ECH.Type, "kdf": hello.ECH.KDF, "aead": hello.ECH.AEAD,
						"config_id": "fresh-grease-config-id", "enc_length": len(hello.ECH.Enc),
						"payload_length": "native-grease-choice-144,176,208,240",
					}
				}
			case 57:
				parameters, err := parityReadQUICParameters(extension.Data)
				if err != nil {
					return nil, err
				}
				value, err = canonicalParityQUICParameters(parameters, meta)
				if err != nil {
					return nil, err
				}
			}
		}
		extensions = append(extensions, map[string]any{"id": id, "value": value})
	}
	if meta.PermuteExtensions {
		sort.SliceStable(extensions, func(i, j int) bool {
			if extensions[i]["id"] != extensions[j]["id"] {
				return extensions[i]["id"].(uint16) < extensions[j]["id"].(uint16)
			}
			a, _ := json.Marshal(extensions[i]["value"])
			b, _ := json.Marshal(extensions[j]["value"])
			return bytes.Compare(a, b) < 0
		})
	}
	var records []map[string]any
	for _, record := range capture.Records {
		length := int(record.Length) - paddingBytes
		if echPayloadVariation != 0 {
			if len(capture.Records) != 1 || length < echPayloadVariation {
				return nil, errors.New("ECH length normalization requires a complete single-record ClientHello")
			}
			length -= echPayloadVariation
		}
		records = append(records, map[string]any{"type": record.Type, "version": record.Version, "length": length})
	}
	return map[string]any{
		"legacy_version": hello.LegacyVersion, "random_length": len(hello.Random),
		"session_id_length": len(hello.SessionID), "ciphers": ciphers,
		"compression_methods": hello.CompressionMethods, "extensions": extensions,
		"records": records, "negotiated_version": capture.NegotiatedVersion,
		"negotiated_cipher": capture.NegotiatedCipher, "negotiated_protocol": capture.NegotiatedProtocol,
		"server_name": capture.ServerName, "resumed": capture.Resumed,
	}, nil
}

func canonicalParityQUICParameters(parameters []parityQUICParameter, meta profileSignature) ([]map[string]any, error) {
	var result []map[string]any
	for _, parameter := range parameters {
		id := parameter.ID
		if id > (uint64(1)<<62)-1 {
			return nil, errors.New("QUIC transport parameter ID exceeds varint range")
		}
		value := any(hex.EncodeToString(parameter.Data))
		idWidth := any(parameter.IDEncodedLength)
		if parameter.LengthEncodedLength != 0 && parameter.LengthEncodedLength != quicvarint.Len(uint64(len(parameter.Data))) {
			return nil, errors.New("QUIC parameter length does not use native minimal varint encoding")
		}
		switch {
		case id >= 27 && (id-27)%31 == 0 && strings.Contains(meta.QUICTransportParameters, ";GREASE"):
			if len(parameter.Data) < 1 || len(parameter.Data) > 8 {
				return nil, errors.New("QUIC GREASE payload outside native length range 1..8")
			}
			if parameter.IDEncodedLength != 0 && parameter.IDEncodedLength != quicvarint.Len(id) {
				return nil, errors.New("QUIC GREASE ID does not use native minimal varint encoding")
			}
			idWidth = "native-minimal-grease-id-width"
			id, value = 27, "native-grease-id-and-1..8-random-bytes"
		case id == 15:
			// Source CID bytes are fresh for every connection; length is fixed.
			value = map[string]any{"length": len(parameter.Data), "value": "fresh-source-cid"}
		case id == 17 && strings.Contains(meta.QUICTransportParameters, "17:"):
			if len(parameter.Data) < 8 || len(parameter.Data)%4 != 0 {
				return nil, errors.New("malformed QUIC version_information")
			}
			var versions []uint32
			for data := parameter.Data; len(data) > 0; data = data[4:] {
				version := binary.BigEndian.Uint32(data[:4])
				if version&0x0f0f0f0f == 0x0a0a0a0a {
					version = 0x0a0a0a0a
				}
				versions = append(versions, version)
			}
			value = versions
		case id == 12583 && strings.Contains(meta.QUICTransportParameters, "12583:AUTO"):
			valueNumber, err := parityQUICParameterNumber(parameter.Data)
			if err != nil || len(parameter.Data) != 4 || valueNumber < 283000 || valueNumber > 348535 {
				return nil, fmt.Errorf("QUIC AUTO initial RTT=%d outside native range 283000..348535: %v", valueNumber, err)
			}
			value = "native-auto-initial-rtt-283000..348535"
		}
		result = append(result, map[string]any{"id": id, "value": value, "id_encoded_length": idWidth, "length_encoded_length": parameter.LengthEncodedLength})
	}
	if meta.PermuteExtensions {
		sort.SliceStable(result, func(i, j int) bool { return result[i]["id"].(uint64) < result[j]["id"].(uint64) })
	}
	return result, nil
}

func parityQUICParameterNumber(data []byte) (uint64, error) {
	if len(data) == 0 || len(data) != 1<<((data[0]&0xc0)>>6) {
		return 0, errors.New("invalid QUIC integer parameter")
	}
	value := uint64(data[0] & 0x3f)
	for _, b := range data[1:] {
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func canonicalParityHTTP3(capture parityHTTP3Capture, meta profileSignature) (map[string]any, error) {
	normalizeSettings := func(settings []parityHTTP3Setting) ([]map[string]any, error) {
		var result []map[string]any
		for _, setting := range settings {
			id, value := setting.ID, any(setting.Value)
			idWidth, valueWidth := any(setting.IDEncodedLength), any(setting.ValueEncodedLength)
			if id >= 33 && (id-33)%31 == 0 && strings.Contains(meta.HTTP3Settings, "GREASE") {
				if id > 133143986178 || setting.Value > 4294967295 {
					return nil, errors.New("HTTP/3 GREASE SETTINGS exceeds native uint32 random generator range")
				}
				if (setting.IDEncodedLength != 0 && setting.IDEncodedLength != quicvarint.Len(id)) || (setting.ValueEncodedLength != 0 && setting.ValueEncodedLength != quicvarint.Len(setting.Value)) {
					return nil, errors.New("HTTP/3 GREASE setting does not use native minimal varint encoding")
				}
				idWidth, valueWidth = "native-minimal-grease-id-width", "native-minimal-grease-value-width"
				id, value = 33, "fresh-grease-setting"
			}
			result = append(result, map[string]any{"id": id, "value": value, "id_encoded_length": idWidth, "value_encoded_length": valueWidth})
		}
		return result, nil
	}
	normalizeFrames := func(frames []parityHTTP3Frame) ([]map[string]any, error) {
		var result []map[string]any
		for _, frame := range frames {
			payload := any(hex.EncodeToString(frame.Payload))
			if frame.LengthEncodedLength != 0 && frame.LengthEncodedLength != quicvarint.Len(uint64(len(frame.Payload))) {
				return nil, errors.New("HTTP/3 frame length does not use native minimal varint encoding")
			}
			if frame.Type == 4 {
				settings, err := parityReadHTTP3Settings(frame.Payload)
				if err != nil {
					return nil, err
				}
				payload, err = normalizeSettings(settings)
				if err != nil {
					return nil, err
				}
			}
			result = append(result, map[string]any{"type": frame.Type, "payload": payload, "type_encoded_length": frame.TypeEncodedLength, "length_encoded_length": frame.LengthEncodedLength})
		}
		return result, nil
	}
	control, err := normalizeFrames(capture.ControlFrames)
	if err != nil {
		return nil, err
	}
	request, err := normalizeFrames(capture.RequestFrames)
	if err != nil {
		return nil, err
	}
	sort.Slice(capture.UniStreams, func(i, j int) bool { return capture.UniStreams[i].ID < capture.UniStreams[j].ID })
	var streams []map[string]any
	for _, stream := range capture.UniStreams {
		frames, err := normalizeFrames(stream.Frames)
		if err != nil {
			return nil, err
		}
		streams = append(streams, map[string]any{"id": stream.ID, "type": stream.Type, "frames": frames, "raw": stream.Raw})
	}
	settings, err := normalizeSettings(capture.Settings)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"settings": settings, "control_frames": control,
		"request_frames": request, "request_stream_id": capture.StreamID,
		"header_block": capture.HeaderBlock, "uni_streams": streams,
	}, nil
}

func parityJSONDiff(got, want []byte) string {
	var a, b any
	decoder := json.NewDecoder(bytes.NewReader(got))
	decoder.UseNumber()
	_ = decoder.Decode(&a)
	decoder = json.NewDecoder(bytes.NewReader(want))
	decoder.UseNumber()
	_ = decoder.Decode(&b)
	var differences []string
	var visit func(string, any, any)
	visit = func(path string, got, want any) {
		if len(differences) >= 20 || reflect.DeepEqual(got, want) {
			return
		}
		switch g := got.(type) {
		case map[string]any:
			if w, ok := want.(map[string]any); ok {
				keys := make(map[string]bool)
				for k := range g {
					keys[k] = true
				}
				for k := range w {
					keys[k] = true
				}
				var names []string
				for k := range keys {
					names = append(names, k)
				}
				sort.Strings(names)
				for _, k := range names {
					visit(path+"."+k, g[k], w[k])
				}
				return
			}
		case []any:
			if w, ok := want.([]any); ok && len(g) == len(w) {
				for i := range g {
					visit(path+"["+strconv.Itoa(i)+"]", g[i], w[i])
				}
				return
			}
		}
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		short := func(s []byte) string {
			if len(s) > 500 {
				return string(s[:500]) + "..."
			}
			return string(s)
		}
		differences = append(differences, path+":\n  Go:     "+short(g)+"\n  native: "+short(w))
	}
	visit("$", a, b)
	return strings.Join(differences, "\n")
}
