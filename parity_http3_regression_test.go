package curlgo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

// Mutation tests protect against a canonicalizer that makes different native
// settings look equal. Unknown protocol fields and raw encoding remain strict.
func TestParityHTTP3NormalizationRetainsFingerprintParameters(t *testing.T) {
	for _, profile := range []Profile{Chrome150, Firefox147} {
		t.Run(string(profile), func(t *testing.T) {
			original := parityHTTP3RegressionCapture(profile)
			want, err := canonicalParityCapture(profile, original)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*parityCapture){
				"settings-value": func(c *parityCapture) { c.HTTP.HTTP3.Settings[0].Value++ },
				"settings-order": func(c *parityCapture) {
					settings := c.HTTP.HTTP3.Settings
					settings[0], settings[1] = settings[1], settings[0]
				},
				"unknown-frame":  func(c *parityCapture) { c.HTTP.HTTP3.RequestFrames[0].Payload[0]++ },
				"qpack-encoding": func(c *parityCapture) { c.HTTP.HTTP3.HeaderBlock[0]++ },
				"header-value":   func(c *parityCapture) { c.HTTP.Headers[1].Value = "different" },
				"header-order": func(c *parityCapture) {
					headers := c.HTTP.Headers
					headers[0], headers[1] = headers[1], headers[0]
				},
				"body":                        func(c *parityCapture) { c.HTTP.Body[0]++ },
				"transport-value":             func(c *parityCapture) { c.QUIC.TransportParameters[0].Data = quicvarint.Append(nil, 30001) },
				"unknown-transport-parameter": func(c *parityCapture) { c.QUIC.TransportParameters[2].Data[0]++ },
				"source-cid-length":           func(c *parityCapture) { c.QUIC.InitialPackets[0].SourceCIDLength++ },
				"source-cid-parameter-length": func(c *parityCapture) {
					c.QUIC.TransportParameters[1].Data = append(c.QUIC.TransportParameters[1].Data, 1)
				},
				"quic-version":           func(c *parityCapture) { c.QUIC.InitialPackets[0].Version++ },
				"initial-token":          func(c *parityCapture) { c.QUIC.InitialPackets[0].TokenLength++ },
				"packet-number-encoding": func(c *parityCapture) { c.QUIC.InitialPackets[0].PacketNumberLength++ },
			} {
				t.Run(name, func(t *testing.T) {
					capture := parityCloneHTTP3Regression(t, original)
					mutate(&capture)
					got, err := canonicalParityCapture(profile, capture)
					if err == nil && reflect.DeepEqual(got, want) {
						t.Fatal("changed observable fingerprint normalized to the original")
					}
				})
			}
		})
	}
}

func TestParityHTTP3NormalizationPermitsOnlyConfiguredRandomness(t *testing.T) {
	for _, profile := range []Profile{Chrome150, Firefox147} {
		t.Run(string(profile), func(t *testing.T) {
			original := parityHTTP3RegressionCapture(profile)
			want, err := canonicalParityCapture(profile, original)
			if err != nil {
				t.Fatal(err)
			}
			capture := parityCloneHTTP3Regression(t, original)
			if profile == Firefox147 {
				capture.QUIC.InitialPackets[0].DestinationCIDLength = 20
				capture.QUIC.InitialPackets[0].PacketNumber = 1024
				capture.QUIC.InitialPackets[0].PacketNumberLength = 2
				capture.QUIC.TransportParameters[1].Data = []byte{4, 5, 6}
			} else {
				capture.HTTP.HTTP3.Settings[2] = parityHTTP3Setting{ID: 126, Value: 987}
				capture.QUIC.TransportParameters[3] = parityQUICParameter{ID: 58, Data: []byte{6, 7, 8}}
			}
			got, err := canonicalParityCapture(profile, capture)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("configured fresh random values changed normalized fingerprint")
			}
			for name, mutate := range map[string]func(*parityCapture){
				"fixed-packet-number": func(c *parityCapture) {
					if profile == Chrome150 {
						c.QUIC.InitialPackets[0].PacketNumber = 2
					} else {
						c.QUIC.InitialPackets[0].PacketNumber = 1025
					}
				},
				"destination-cid-range":   func(c *parityCapture) { c.QUIC.InitialPackets[0].DestinationCIDLength = 21 },
				"unknown-parameter-bytes": func(c *parityCapture) { c.QUIC.TransportParameters[2].Data = []byte{0xaa, 0xbb} },
			} {
				t.Run(name, func(t *testing.T) {
					capture := parityCloneHTTP3Regression(t, original)
					mutate(&capture)
					got, err := canonicalParityCapture(profile, capture)
					if err == nil && reflect.DeepEqual(got, want) {
						t.Fatal("non-profile randomness normalized to the original")
					}
				})
			}
		})
	}
}

func TestParityHTTP3NormalizationRejectsImpossibleRandomValues(t *testing.T) {
	meta, err := parityProfileMetadata(Chrome145)
	if err != nil {
		t.Fatal(err)
	}
	for name, parameter := range map[string]parityQUICParameter{
		"rtt-above-two-byte-random-range": {ID: 12583, Data: quicvarint.Append(nil, 348536)},
		"rtt-below-native-range":          {ID: 12583, Data: quicvarint.Append(nil, 282999)},
		"grease-empty":                    {ID: 27, Data: []byte{}},
		"grease-too-large":                {ID: 27, Data: make([]byte, 9)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalParityQUICParameters([]parityQUICParameter{parameter}, meta); err == nil {
				t.Fatal("impossible native random parameter accepted")
			}
		})
	}
	for name, setting := range map[string]parityHTTP3Setting{
		"grease-id-exceeds-uint32-generator":    {ID: 31*(uint64(1)<<32) + 33, Value: 0},
		"grease-value-exceeds-uint32-generator": {ID: 33, Value: uint64(1) << 32},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalParityHTTP3(parityHTTP3Capture{Settings: []parityHTTP3Setting{setting}}, meta); err == nil {
				t.Fatal("impossible native random setting accepted")
			}
		})
	}
}

func TestParityQUICVersionInformationRetainsVersionOrder(t *testing.T) {
	meta, err := parityProfileMetadata(Firefox147)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(versions ...uint32) []byte {
		var data []byte
		for _, version := range versions {
			data = binary.BigEndian.AppendUint32(data, version)
		}
		return data
	}
	want, err := canonicalParityQUICParameters([]parityQUICParameter{{ID: 17, Data: encode(1, 0x0a1a2a3a, 1)}}, meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalParityQUICParameters([]parityQUICParameter{{ID: 17, Data: encode(1, 0xfaea9a8a, 1)}}, meta)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("legal reserved version did not normalize: %v", err)
	}
	got, err = canonicalParityQUICParameters([]parityQUICParameter{{ID: 17, Data: encode(1, 1, 0x0a1a2a3a)}}, meta)
	if err == nil && reflect.DeepEqual(got, want) {
		t.Fatal("available-version order was discarded")
	}
}

func TestParityQUICTransportParameterOrderUsesNativePermutation(t *testing.T) {
	parameters := []parityQUICParameter{{ID: 1, Data: quicvarint.Append(nil, 30000)}, {ID: 4, Data: quicvarint.Append(nil, 25165824)}}
	reversed := []parityQUICParameter{parameters[1], parameters[0]}
	for _, profile := range []Profile{Chrome150, Firefox147} {
		t.Run(string(profile), func(t *testing.T) {
			meta, err := parityProfileMetadata(profile)
			if err != nil {
				t.Fatal(err)
			}
			want, err := canonicalParityQUICParameters(parameters, meta)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalParityQUICParameters(reversed, meta)
			if err != nil {
				t.Fatal(err)
			}
			if equal := reflect.DeepEqual(got, want); equal != meta.PermuteExtensions {
				t.Fatalf("parameter order normalized equally=%v; native permutation=%v", equal, meta.PermuteExtensions)
			}
		})
	}
}

func TestParityFirefoxInitialPacketNumberEncoding(t *testing.T) {
	var want map[string]any
	for _, number := range []uint64{1, 127, 128, 1024} {
		capture := parityHTTP3RegressionCapture(Firefox147)
		capture.QUIC.InitialPackets[0].PacketNumber = number
		length := 1
		if number >= 128 {
			length = 2
		}
		capture.QUIC.InitialPackets[0].PacketNumberLength = length
		got, err := canonicalParityCapture(Firefox147, capture)
		if err != nil {
			t.Fatalf("native packet number %d/%d bytes: %v", number, length, err)
		}
		if want == nil {
			want = got
		} else if !reflect.DeepEqual(got, want) {
			t.Fatalf("valid native packet-number encoding for %d did not normalize equally", number)
		}
		capture.QUIC.InitialPackets[0].PacketNumberLength = 3 - length
		if _, err := canonicalParityCapture(Firefox147, capture); err == nil {
			t.Fatalf("accepted packet number %d encoded with %d bytes", number, 3-length)
		}
	}
}

func TestParityQUICParsersPreserveEncodedVarintWidths(t *testing.T) {
	meta, err := parityProfileMetadata(Chrome150)
	if err != nil {
		t.Fatal(err)
	}
	minimal, err := parityReadQUICParameters([]byte{1, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalParityQUICParameters(minimal, meta)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"id-width":     {0x40, 1, 1, 2},
		"length-width": {1, 0x40, 1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			parameters, err := parityReadQUICParameters(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if parameters[0].IDEncodedLength+parameters[0].LengthEncodedLength != 3 {
				t.Fatal("parser lost nonminimal varint width")
			}
			got, err := canonicalParityQUICParameters(parameters, meta)
			if err == nil && reflect.DeepEqual(got, want) {
				t.Fatal("different raw QUIC varint encodings normalized equally")
			}
		})
	}
	minimalSettings, err := parityReadHTTP3Settings([]byte{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	wantH3, err := canonicalParityHTTP3(parityHTTP3Capture{Settings: minimalSettings}, meta)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"settings-id-width":    {0x40, 1, 2},
		"settings-value-width": {1, 0x40, 2},
	} {
		t.Run(name, func(t *testing.T) {
			settings, err := parityReadHTTP3Settings(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if settings[0].IDEncodedLength+settings[0].ValueEncodedLength != 3 {
				t.Fatal("SETTINGS parser lost nonminimal varint width")
			}
			got, err := canonicalParityHTTP3(parityHTTP3Capture{Settings: settings}, meta)
			if err == nil && reflect.DeepEqual(got, wantH3) {
				t.Fatal("different SETTINGS varint encodings normalized equally")
			}
		})
	}
	frame, err := parityReadHTTP3Frame(bufio.NewReader(bytes.NewReader([]byte{0x40, 0, 0x40, 1, 0xab})))
	if err != nil {
		t.Fatal(err)
	}
	if frame.TypeEncodedLength != 2 || frame.LengthEncodedLength != 2 || frame.Type != 0 || !bytes.Equal(frame.Payload, []byte{0xab}) {
		t.Fatal("HTTP/3 frame parser lost original type or length encodings")
	}
}

func parityHTTP3RegressionCapture(profile Profile) parityCapture {
	source := []byte{}
	settings := []parityHTTP3Setting{{ID: 1, Value: 65536}, {ID: 7, Value: 20}}
	parameters := []parityQUICParameter{
		{ID: 1, Data: quicvarint.Append(nil, 30000)},
		{ID: 15, Data: source},
		{ID: 20000, Data: []byte{0x41, 0x42}},
	}
	initial := parityQUICInitialPacket{Version: 1, DestinationCIDLength: 8, SourceCIDLength: 0, PacketNumber: 1, PacketNumberLength: 1}
	if profile == Firefox147 {
		initial.SourceCIDLength, initial.PacketNumber = 3, 7
		parameters[1].Data = []byte{1, 2, 3}
	} else {
		settings = append(settings, parityHTTP3Setting{ID: 64, Value: 123})
		parameters = append(parameters, parityQUICParameter{ID: 27, Data: []byte{1}})
	}
	return parityCapture{
		HTTP: parityHTTPCapture{
			Protocol: "HTTP/3", Method: "POST", Target: "/parity",
			Headers: []parityHeader{{Name: ":method", Value: "POST"}, {Name: "x-parity", Value: "original"}},
			Body:    []byte("fixed body"),
			HTTP3:   &parityHTTP3Capture{Settings: settings, StreamID: 0, HeaderBlock: []byte{0, 0}, RequestFrames: []parityHTTP3Frame{{Type: 200, Payload: []byte{1, 2, 3}}}},
		},
		QUIC: &parityQUICCapture{InitialPackets: []parityQUICInitialPacket{initial}, TransportParameters: parameters},
	}
}

func parityCloneHTTP3Regression(t *testing.T, capture parityCapture) parityCapture {
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
