package curlgo

import (
	"fmt"
	"strconv"
	"strings"
)

// Fingerprint overrides the TLS, HTTP/2, and HTTP/3 settings of a native browser
// profile. Empty strings and nil Extra fields leave the profile defaults intact.
// JA3 is a comma-separated TLS fingerprint, Akamai is an HTTP/2 fingerprint,
// and Perk is an HTTP/3 settings|pseudo-header-order|QUIC-parameters string.
type Fingerprint struct {
	JA3    string
	Akamai string
	Perk   string
	Extra  *ExtraFingerprints
}

// ExtraFingerprints exposes curl-impersonate's individual fingerprint controls.
// A nil pointer preserves the browser's existing setting. TLSMinVersion and
// TLSMaxVersion use SSLVersion constants, not TLS wire version numbers.
type ExtraFingerprints struct {
	TLSMinVersion          *SSLVersion
	TLSMaxVersion          *SSLVersion
	TLSGrease              *bool
	TLSPermuteExtensions   *bool
	TLSCertCompression     *string
	TLSSignatureAlgorithms []string
	TLSDelegatedCredential *string
	TLSRecordSizeLimit     *int
	// TLSTrustAnchors contains decimal relative OIDs, with at least one arc.
	// Each OID's ASN.1 base-128 encoding must fit the native 255-byte limit.
	TLSTrustAnchors      []string
	HTTP2StreamWeight    *int
	HTTP2StreamExclusive *int
	HTTP2NoPriority      *bool
	// HeaderOrder preserves the existing order when nil; an explicit empty
	// string clears custom ordering through the native NULL option value.
	HeaderOrder  *string
	SplitCookies *bool
	// FormBoundary is "webkit" or "firefox". The native option is a string,
	// despite the boolean annotation in curl_cffi's ExtraFingerprints class.
	FormBoundary            *string
	HTTP3SigHashAlgs        *string
	HTTP3TLSExtensionOrder  *string
	QUICInitialPacketNumber *int
	HTTP3Settings           *string
	HTTP3PseudoHeadersOrder *string
	HTTP3TLSSupportedGroups []string
	HTTP3PermuteExtensions  *bool
	QUICTransportParameters *string
	// QUICCIDLength selects the native connection-ID style: webkit or firefox.
	QUICCIDLength *string
}

type fingerprintOption struct {
	option Option
	value  any
}

type fingerprintSetter interface {
	SetOpt(Option, any) error
}

// ApplyFingerprint applies custom fingerprint settings to a Curl handle. All
// inputs are validated before changing the handle. Native errors are returned
// with the failing option; unsupported extensions never silently disappear.
func ApplyFingerprint(c *Curl, fingerprint Fingerprint) error {
	if c == nil {
		return fmt.Errorf("curlgo: cannot apply a fingerprint to a nil Curl")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.easy == nil {
		return ErrClosed
	}
	options, err := fingerprintOptionsWithSSLVersion(fingerprint, c.sslVersion)
	if err != nil {
		return err
	}
	return applyFingerprintOptions(options, func(option Option, value any) error {
		return c.setOptLocked(option, value, true)
	})
}

func applyFingerprint(c fingerprintSetter, fingerprint Fingerprint) error {
	options, err := fingerprintOptions(fingerprint)
	if err != nil {
		return err
	}
	return applyFingerprintOptions(options, c.SetOpt)
}

func applyFingerprintOptions(options []fingerprintOption, set func(Option, any) error) error {
	for _, option := range options {
		if err := set(option.option, option.value); err != nil {
			return fmt.Errorf("curlgo: apply fingerprint option %d: %w", option.option, err)
		}
	}
	return nil
}

// ValidateFingerprint checks a custom fingerprint without loading the native
// library or changing an existing Curl handle.
func ValidateFingerprint(fingerprint Fingerprint) error {
	_, err := fingerprintOptions(fingerprint)
	return err
}

func fingerprintOptions(fp Fingerprint) ([]fingerprintOption, error) {
	return fingerprintOptionsWithSSLVersion(fp, SSLVersionDefault|SSLVersionMaxDefault)
}

func fingerprintOptionsWithSSLVersion(fp Fingerprint, sslVersion SSLVersion) ([]fingerprintOption, error) {
	var options []fingerprintOption
	if fp.JA3 != "" {
		permute := fp.Extra != nil && fp.Extra.TLSPermuteExtensions != nil && *fp.Extra.TLSPermuteExtensions
		ja3, err := ja3Options(fp.JA3, permute)
		if err != nil {
			return nil, err
		}
		options = append(options, ja3...)
		// JA3 sets a complete version option before Extra overrides. Preserve
		// that value, rather than earlier handle settings, when merging Extra.
		sslVersion = SSLVersionTlsv12 | SSLVersionMaxDefault
	}
	// Match curl_cffi's override precedence: JA3, extra settings, then Akamai.
	if fp.Extra != nil {
		extra, err := extraFingerprintOptions(fp.Extra, sslVersion)
		if err != nil {
			return nil, err
		}
		options = append(options, extra...)
	}
	if fp.Akamai != "" {
		akamai, err := akamaiOptions(fp.Akamai)
		if err != nil {
			return nil, err
		}
		options = append(options, akamai...)
	}
	if fp.Perk != "" {
		perk, err := perkOptions(fp.Perk)
		if err != nil {
			return nil, err
		}
		options = append(options, perk...)
	}
	return options, nil
}

func ja3Options(ja3 string, permute bool) ([]fingerprintOption, error) {
	fields := strings.Split(ja3, ",")
	if len(fields) != 5 {
		return nil, fmt.Errorf("curlgo: JA3 must have exactly five comma-separated fields")
	}
	if fields[0] != "771" {
		return nil, fmt.Errorf("curlgo: JA3 supports TLS ClientHello version 771 (TLS 1.2) only")
	}
	ciphers, err := mappedTLSList("JA3 cipher", fields[1], tlsCipherNames)
	if err != nil {
		return nil, err
	}
	extensions, ids, err := validateExtensionOrder(fields[2], true)
	if err != nil {
		return nil, fmt.Errorf("curlgo: JA3 %w", err)
	}
	curves, err := mappedTLSList("JA3 supported group", fields[3], tlsCurveNames)
	if err != nil {
		return nil, err
	}
	if fields[4] != "0" {
		return nil, fmt.Errorf("curlgo: JA3 supports only uncompressed EC point format 0")
	}
	if ids[17513] && ids[17613] {
		return nil, fmt.Errorf("curlgo: JA3 cannot use both old and new ALPS extension IDs")
	}
	if ids[57] {
		return nil, fmt.Errorf("curlgo: JA3 extension 57 is available only for QUIC; use HTTP3TLSExtensionOrder")
	}
	options := []fingerprintOption{
		{OptSSLVersion, int(SSLVersionTlsv12 | SSLVersionMaxDefault)},
		{OptSSLCipherList, strings.Join(ciphers, ":")},
		{OptSSLECCurves, strings.Join(curves, ":")},
		{OptSSLEnableAlpn, boolNumber(ids[16])},
		{OptSSLEnableALPS, boolNumber(ids[17513] || ids[17613])},
		{OptTLSUseNewALPSCodepoint, boolNumber(ids[17613])},
		{OptSSLEnableTicket, boolNumber(ids[35])},
		{OptTLSStatusRequest, boolNumber(ids[5])},
		{OptTLSSignedCertTimestamps, boolNumber(ids[18])},
		{OptSSLPermuteExtensions, boolNumber(permute)},
	}
	if ids[27] {
		options = append(options, fingerprintOption{OptSSLCertCompression, "brotli"})
	} else {
		options = append(options, fingerprintOption{OptSSLCertCompression, ""})
	}
	if ids[65037] {
		options = append(options, fingerprintOption{OptEch, "grease"})
	} else {
		options = append(options, fingerprintOption{OptEch, "false"})
	}
	// The explicit list defines membership as well as order. Native BoringSSL
	// shuffles that list when permutation is enabled; omitting it would retain
	// profile-only extensions such as Firefox's delegated credentials.
	options = append(options, fingerprintOption{OptTLSExtensionOrder, extensions})
	if ids[34] {
		options = append(options, fingerprintOption{OptTLSDelegatedCredentials, "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1"})
	}
	if ids[28] {
		options = append(options, fingerprintOption{OptTLSRecordSizeLimit, 16385})
	}
	return options, nil
}

func akamaiOptions(akamai string) ([]fingerprintOption, error) {
	fields := strings.Split(akamai, "|")
	if len(fields) != 4 {
		return nil, fmt.Errorf("curlgo: Akamai must have four pipe-separated fields")
	}
	settings, err := validateHTTP2Settings(fields[0])
	if err != nil {
		return nil, err
	}
	window, err := decimal(fields[1], 31)
	if err != nil {
		return nil, fmt.Errorf("curlgo: invalid Akamai window update: %w", err)
	}
	if err := validateHTTP2Streams(fields[2]); err != nil {
		return nil, err
	}
	order, err := pseudoHeaderOrder(fields[3])
	if err != nil {
		return nil, err
	}
	streams := fields[2]
	if streams == "0" {
		streams = ""
	}
	return []fingerprintOption{
		{OptHTTPVersion, int(HTTPVersionV20)},
		{OptHTTP2Settings, settings},
		{OptHTTP2WindowUpdate, int(window)},
		// Clear inherited Firefox PRIORITY streams when Akamai specifies none.
		{OptHTTP2Streams, streams},
		{OptHTTP2PseudoHeadersOrder, order},
	}, nil
}

func perkOptions(perk string) ([]fingerprintOption, error) {
	fields := strings.Split(perk, "|")
	if len(fields) != 3 {
		return nil, fmt.Errorf("curlgo: Perk must have three pipe-separated fields")
	}
	settings, err := validateVarintPairs("HTTP/3 settings", fields[0])
	if err != nil {
		return nil, err
	}
	order, err := pseudoHeaderOrder(fields[1])
	if err != nil {
		return nil, err
	}
	parameters, err := validateVarintPairs("QUIC transport parameters", fields[2])
	if err != nil {
		return nil, err
	}
	// Perk changes HTTP/3 parameters, and preserves the caller's HTTP version.
	return []fingerprintOption{{OptHTTP3Settings, settings}, {OptHTTP3PseudoHeadersOrder, order}, {OptQUICTransportParameters, parameters}}, nil
}

func validateHTTP2Settings(settings string) (string, error) {
	settings = strings.ReplaceAll(settings, ",", ";")
	parts := strings.Split(settings, ";")
	if settings == "" || len(parts) > 8 {
		return "", fmt.Errorf("curlgo: HTTP/2 settings require one to eight entries")
	}
	seen := make(map[uint64]bool)
	for _, part := range parts {
		pair := strings.Split(part, ":")
		if len(pair) != 2 {
			return "", fmt.Errorf("curlgo: invalid HTTP/2 setting %q", part)
		}
		id, err := decimal(pair[0], 16)
		if err != nil || (id != 1 && id != 2 && id != 3 && id != 4 && id != 5 && id != 6 && id != 8 && id != 9) {
			return "", fmt.Errorf("curlgo: unsupported HTTP/2 setting ID %q", pair[0])
		}
		if seen[id] {
			return "", fmt.Errorf("curlgo: duplicate HTTP/2 setting ID %d", id)
		}
		seen[id] = true
		value, err := decimal(pair[1], 32)
		if err != nil {
			return "", fmt.Errorf("curlgo: invalid HTTP/2 setting %d value: %w", id, err)
		}
		if ((id == 2 || id == 8 || id == 9) && value > 1) || (id == 4 && value > 2147483647) || (id == 5 && (value < 16384 || value > 16777215)) {
			return "", fmt.Errorf("curlgo: HTTP/2 setting %d value %d is out of range", id, value)
		}
	}
	return settings, nil
}

func validateHTTP2Streams(streams string) error {
	if streams == "0" || streams == "" {
		return nil
	}
	seen := make(map[uint64]bool)
	for _, stream := range strings.Split(streams, ",") {
		values := strings.Split(stream, ":")
		if len(values) != 4 {
			return fmt.Errorf("curlgo: invalid Akamai stream %q; expected ID:exclusive:dependency:weight", stream)
		}
		parsed := make([]uint64, 4)
		for i, value := range values {
			var err error
			parsed[i], err = decimal(value, 31)
			if err != nil {
				return fmt.Errorf("curlgo: invalid Akamai stream %q: %w", stream, err)
			}
		}
		if parsed[0] == 0 || parsed[0] == parsed[2] || parsed[1] > 1 || parsed[3] < 1 || parsed[3] > 256 || seen[parsed[0]] {
			return fmt.Errorf("curlgo: invalid Akamai stream %q", stream)
		}
		seen[parsed[0]] = true
	}
	return nil
}

func pseudoHeaderOrder(order string) (string, error) {
	order = strings.ReplaceAll(order, ",", "")
	if len(order) != 4 {
		return "", fmt.Errorf("curlgo: pseudo-header order must contain m, a, s, and p exactly once")
	}
	seen := make(map[rune]bool)
	for _, c := range order {
		if !strings.ContainsRune("masp", c) || seen[c] {
			return "", fmt.Errorf("curlgo: pseudo-header order must contain m, a, s, and p exactly once")
		}
		seen[c] = true
	}
	return order, nil
}

func decimal(value string, bits int) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("missing decimal integer")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid decimal integer %q", value)
		}
	}
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("decimal integer %q is out of range", value)
	}
	return n, nil
}

func mappedTLSList(label, value string, names map[uint64]string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("curlgo: %s list cannot be empty", label)
	}
	var out []string
	seen := make(map[uint64]bool)
	for _, part := range strings.Split(value, "-") {
		id, err := decimal(part, 16)
		if err != nil {
			return nil, fmt.Errorf("curlgo: invalid %s: %w", label, err)
		}
		name, ok := names[id]
		if !ok {
			return nil, fmt.Errorf("curlgo: unsupported %s ID %d", label, id)
		}
		if seen[id] {
			return nil, fmt.Errorf("curlgo: duplicate %s ID %d", label, id)
		}
		seen[id] = true
		out = append(out, name)
	}
	return out, nil
}

func validateExtensionOrder(value string, stripPadding bool) (string, map[uint64]bool, error) {
	var order []string
	seen := make(map[uint64]bool)
	if value == "" {
		return "", seen, nil
	}
	for _, part := range strings.Split(value, "-") {
		id, err := decimal(part, 16)
		if err != nil {
			return "", nil, fmt.Errorf("invalid TLS extension order: %w", err)
		}
		if seen[id] {
			return "", nil, fmt.Errorf("duplicate TLS extension ID %d", id)
		}
		seen[id] = true
		if id == 21 && stripPadding {
			continue
		}
		if !supportedTLSExtensions[id] {
			return "", nil, fmt.Errorf("unsupported TLS extension ID %d", id)
		}
		order = append(order, strconv.FormatUint(id, 10))
	}
	return strings.Join(order, "-"), seen, nil
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}

func extraFingerprintOptions(fp *ExtraFingerprints, sslVersion SSLVersion) ([]fingerprintOption, error) {
	var options []fingerprintOption
	add := func(option Option, value any) {
		options = append(options, fingerprintOption{option, value})
	}
	if fp.TLSMinVersion != nil || fp.TLSMaxVersion != nil {
		minVersion := sslVersion & 0xffff
		maxVersion := sslVersion &^ 0xffff
		if fp.TLSMinVersion != nil {
			minVersion = *fp.TLSMinVersion
			if minVersion != SSLVersionDefault && minVersion != SSLVersionTlsv1 && (minVersion < SSLVersionTlsv10 || minVersion > SSLVersionTlsv13) {
				return nil, fmt.Errorf("curlgo: invalid TLS minimum version %d", minVersion)
			}
			// Native curl resolves an explicitly requested DEFAULT minimum to
			// TLS 1.2. Validate that effective value against the retained cap.
			minVersion = effectiveSSLVersion(minVersion)
		}
		if fp.TLSMaxVersion != nil {
			if *fp.TLSMaxVersion < SSLVersionTlsv10 || *fp.TLSMaxVersion > SSLVersionTlsv13 {
				return nil, fmt.Errorf("curlgo: invalid TLS maximum version %d", *fp.TLSMaxVersion)
			}
			maxVersion = *fp.TLSMaxVersion << 16
		}
		if maximum := maxVersion >> 16; maximum >= SSLVersionTlsv10 && minVersion > maximum {
			return nil, fmt.Errorf("curlgo: TLS minimum version exceeds maximum version")
		}
		add(OptSSLVersion, int(minVersion|maxVersion))
	}
	for _, setting := range []struct {
		option Option
		value  *bool
	}{
		{OptTLSGrease, fp.TLSGrease}, {OptSSLPermuteExtensions, fp.TLSPermuteExtensions},
		{OptHTTP2NoPriority, fp.HTTP2NoPriority}, {OptSplitCookies, fp.SplitCookies},
		{OptHTTP3SSLPermuteExtensions, fp.HTTP3PermuteExtensions},
	} {
		if setting.value != nil {
			add(setting.option, boolNumber(*setting.value))
		}
	}
	if fp.TLSCertCompression != nil {
		if err := validateCertCompression(*fp.TLSCertCompression); err != nil {
			return nil, err
		}
		add(OptSSLCertCompression, *fp.TLSCertCompression)
	}
	if fp.TLSSignatureAlgorithms != nil {
		if err := validateSignatureAlgorithms(fp.TLSSignatureAlgorithms); err != nil {
			return nil, err
		}
		add(OptSSLSigHashAlgs, strings.Join(fp.TLSSignatureAlgorithms, ","))
	}
	if fp.TLSDelegatedCredential != nil {
		algorithms := strings.FieldsFunc(*fp.TLSDelegatedCredential, func(c rune) bool { return c == ':' || c == ',' })
		if *fp.TLSDelegatedCredential != "" {
			if err := validateSignatureAlgorithms(algorithms); err != nil {
				return nil, err
			}
		}
		add(OptTLSDelegatedCredentials, *fp.TLSDelegatedCredential)
	}
	if fp.TLSRecordSizeLimit != nil {
		if *fp.TLSRecordSizeLimit != 0 && (*fp.TLSRecordSizeLimit < 64 || *fp.TLSRecordSizeLimit > 16385) {
			return nil, fmt.Errorf("curlgo: TLS record size limit must be 0 or between 64 and 16385")
		}
		add(OptTLSRecordSizeLimit, *fp.TLSRecordSizeLimit)
	}
	if fp.TLSTrustAnchors != nil {
		for _, oid := range fp.TLSTrustAnchors {
			if err := validateOID(oid); err != nil {
				return nil, err
			}
		}
		add(OptTLSTrustAnchors, strings.Join(fp.TLSTrustAnchors, ","))
	}
	if fp.HTTP2StreamWeight != nil {
		if *fp.HTTP2StreamWeight < 1 || *fp.HTTP2StreamWeight > 256 {
			return nil, fmt.Errorf("curlgo: HTTP/2 stream weight must be between 1 and 256")
		}
		add(OptStreamWeight, *fp.HTTP2StreamWeight)
	}
	if fp.HTTP2StreamExclusive != nil {
		if *fp.HTTP2StreamExclusive != 0 && *fp.HTTP2StreamExclusive != 1 {
			return nil, fmt.Errorf("curlgo: HTTP/2 stream exclusive must be 0 or 1")
		}
		add(OptStreamExclusive, *fp.HTTP2StreamExclusive)
	}
	if fp.HeaderOrder != nil {
		if err := validateHeaderOrder(*fp.HeaderOrder); err != nil {
			return nil, err
		}
		if *fp.HeaderOrder == "" {
			add(OptHTTPHeaderOrder, nil)
		} else {
			add(OptHTTPHeaderOrder, *fp.HeaderOrder)
		}
	}
	if fp.FormBoundary != nil {
		if *fp.FormBoundary != "webkit" && *fp.FormBoundary != "firefox" {
			return nil, fmt.Errorf("curlgo: form boundary must be webkit or firefox")
		}
		add(OptFormBoundary, *fp.FormBoundary)
	}
	if fp.HTTP3SigHashAlgs != nil {
		algorithms := strings.FieldsFunc(*fp.HTTP3SigHashAlgs, func(c rune) bool { return c == ':' || c == ',' })
		if err := validateSignatureAlgorithms(algorithms); err != nil {
			return nil, err
		}
		add(OptHTTP3SigHashAlgs, *fp.HTTP3SigHashAlgs)
	}
	if fp.HTTP3TLSExtensionOrder != nil {
		order, _, err := validateExtensionOrder(*fp.HTTP3TLSExtensionOrder, true)
		if err != nil {
			return nil, err
		}
		add(OptHTTP3TLSExtensionOrder, order)
	}
	if fp.QUICInitialPacketNumber != nil {
		if *fp.QUICInitialPacketNumber < -1 || int64(*fp.QUICInitialPacketNumber) > 2147483647 {
			return nil, fmt.Errorf("curlgo: QUIC initial packet number must be between -1 and 2147483647")
		}
		add(OptQUICInitialPacketNumber, *fp.QUICInitialPacketNumber)
	}
	if fp.HTTP3Settings != nil {
		value, err := validateVarintPairs("HTTP/3 settings", *fp.HTTP3Settings)
		if err != nil {
			return nil, err
		}
		add(OptHTTP3Settings, value)
	}
	if fp.HTTP3PseudoHeadersOrder != nil {
		value, err := pseudoHeaderOrder(*fp.HTTP3PseudoHeadersOrder)
		if err != nil {
			return nil, err
		}
		add(OptHTTP3PseudoHeadersOrder, value)
	}
	if fp.HTTP3TLSSupportedGroups != nil {
		groups := make([]string, len(fp.HTTP3TLSSupportedGroups))
		for i, group := range fp.HTTP3TLSSupportedGroups {
			if group == "X25519Kyber768" {
				group = "X25519Kyber768Draft00"
			}
			found := false
			for _, supported := range tlsCurveNames {
				if group == supported {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("curlgo: unsupported HTTP/3 supported group %q", group)
			}
			groups[i] = group
		}
		add(OptHTTP3SSLECCurves, strings.Join(groups, ":"))
	}
	if fp.QUICTransportParameters != nil {
		value, err := validateVarintPairs("QUIC transport parameters", *fp.QUICTransportParameters)
		if err != nil {
			return nil, err
		}
		add(OptQUICTransportParameters, value)
	}
	if fp.QUICCIDLength != nil {
		if *fp.QUICCIDLength != "webkit" && *fp.QUICCIDLength != "firefox" {
			return nil, fmt.Errorf("curlgo: QUIC connection ID style must be webkit or firefox")
		}
		add(OptQUICCIDLength, *fp.QUICCIDLength)
	}
	return options, nil
}

func validateCertCompression(value string) error {
	if value == "" {
		return nil // An explicit empty list disables compression.
	}
	seen := make(map[string]bool)
	for _, algorithm := range strings.Split(value, ",") {
		if (algorithm != "zlib" && algorithm != "brotli" && algorithm != "zstd") || seen[algorithm] {
			return fmt.Errorf("curlgo: unsupported or duplicate certificate compression %q", algorithm)
		}
		seen[algorithm] = true
	}
	return nil
}

func validateSignatureAlgorithms(algorithms []string) error {
	if len(algorithms) == 0 {
		return fmt.Errorf("curlgo: signature algorithms cannot be empty")
	}
	for _, algorithm := range algorithms {
		if !supportedSignatureAlgorithms[algorithm] {
			return fmt.Errorf("curlgo: unsupported TLS signature algorithm %q", algorithm)
		}
	}
	return nil
}

func validateHeaderOrder(order string) error {
	if order == "" {
		return nil
	}
	seen := make(map[string]bool)
	for _, field := range strings.Split(order, ",") {
		field = strings.TrimSpace(field)
		if field == "" || seen[strings.ToLower(field)] {
			return fmt.Errorf("curlgo: empty or duplicate header in header order")
		}
		seen[strings.ToLower(field)] = true
		for _, c := range field {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
				continue
			}
			return fmt.Errorf("curlgo: invalid header name %q in header order", field)
		}
	}
	return nil
}

func validateOID(oid string) error {
	// The native option uses ASN.1 RELATIVE-OID, so every arc is encoded
	// independently. Absolute-OID first/second-arc restrictions do not apply.
	parts := strings.Split(strings.Trim(oid, " \t"), ".")
	encodedLength := 0
	for _, part := range parts {
		n, err := decimal(part, 64)
		if err != nil {
			return fmt.Errorf("curlgo: invalid trust-anchor relative OID %q", oid)
		}
		encodedLength++
		for n >= 128 {
			encodedLength++
			n >>= 7
		}
		if encodedLength > 255 {
			return fmt.Errorf("curlgo: trust-anchor relative OID %q exceeds 255 encoded bytes", oid)
		}
	}
	return nil
}

func validateVarintPairs(label, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("curlgo: %s cannot be empty", label)
	}
	seen := make(map[uint64]bool)
	for _, part := range strings.Split(value, ";") {
		if part == "GREASE" {
			continue
		}
		if label == "QUIC transport parameters" {
			id, err := validateQUICParameter(part)
			if err != nil {
				return "", err
			}
			if seen[id] {
				return "", fmt.Errorf("curlgo: duplicate %s ID %d", label, id)
			}
			seen[id] = true
			continue
		}
		pair := strings.Split(part, ":")
		if len(pair) != 2 {
			return "", fmt.Errorf("curlgo: invalid %s entry %q", label, part)
		}
		id, err := decimal(pair[0], 62)
		if err != nil {
			return "", fmt.Errorf("curlgo: invalid %s ID: %w", label, err)
		}
		if seen[id] {
			return "", fmt.Errorf("curlgo: duplicate %s ID %d", label, id)
		}
		seen[id] = true
		if _, err := decimal(pair[1], 62); err != nil {
			return "", fmt.Errorf("curlgo: invalid %s value: %w", label, err)
		}
	}
	return value, nil
}

// QUIC parameters additionally support GREASE, byte strings, automatically
// generated connection IDs and RTTs, and chosen@available version information.
// This mirrors the native fork rather than losing those values during parsing.
func validateQUICParameter(parameter string) (uint64, error) {
	key, value, hasValue := strings.Cut(parameter, ":")
	id, err := decimal(key, 62)
	if err != nil {
		return 0, fmt.Errorf("curlgo: invalid QUIC transport parameter ID: %w", err)
	}
	if id == 0 || id == 2 || id == 13 || id == 16 {
		return 0, fmt.Errorf("curlgo: QUIC transport parameter %d is server-only", id)
	}
	if !hasValue {
		if (id >= 1 && id <= 11) || id == 14 || id == 15 || id == 17 || id == 32 || id == 18258 || id == 16741339 {
			return 0, fmt.Errorf("curlgo: QUIC transport parameter %d requires a value", id)
		}
		return id, nil
	}
	if id == 15 && (value == "" || value == "AUTO") {
		return id, nil
	}
	if id == 12583 && (value == "AUTO" || value == "RANDOM") {
		return id, nil
	}
	if id == 17 || id == 16741339 {
		chosen, available, ok := strings.Cut(value, "@")
		if !ok {
			return 0, fmt.Errorf("curlgo: QUIC version information requires chosen@available versions")
		}
		if _, err := strconv.ParseUint(chosen, 0, 32); err != nil || strings.HasPrefix(chosen, "+") {
			return 0, fmt.Errorf("curlgo: invalid chosen QUIC version %q", chosen)
		}
		for _, version := range strings.Split(available, ",") {
			if version == "GREASE" {
				continue
			}
			if _, err := strconv.ParseUint(version, 0, 32); err != nil || strings.HasPrefix(version, "+") {
				return 0, fmt.Errorf("curlgo: invalid available QUIC version %q", version)
			}
		}
		return id, nil
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		bytes := value[2:]
		if len(bytes) == 0 || len(bytes)%2 != 0 {
			return 0, fmt.Errorf("curlgo: invalid QUIC byte string %q", value)
		}
		for _, c := range bytes {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				continue
			}
			return 0, fmt.Errorf("curlgo: invalid QUIC byte string %q", value)
		}
		return id, nil
	}
	if id == 15 {
		return 0, fmt.Errorf("curlgo: QUIC initial source connection ID requires AUTO, an empty value, or a byte string")
	}
	bits := 62
	if id == 18258 {
		bits = 32
	}
	if _, err := decimal(value, bits); err != nil {
		return 0, fmt.Errorf("curlgo: invalid QUIC transport parameter %d value: %w", id, err)
	}
	return id, nil
}

// Cipher and group spellings mirror curl_cffi's IANA-to-BoringSSL tables.
var tlsCipherNames = map[uint64]string{
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256", 0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
	0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
}

var tlsCurveNames = map[uint64]string{
	19: "P-192", 21: "P-224", 23: "P-256", 24: "P-384", 25: "P-521", 29: "X25519",
	256: "ffdhe2048", 257: "ffdhe3072", 4588: "X25519MLKEM768", 25497: "X25519Kyber768Draft00",
}

// This is the BoringSSL fork's explicit-order allowlist, rather than every
// extension assigned by IANA. Padding (21) is handled by the TLS engine.
var supportedTLSExtensions = map[uint64]bool{
	0: true, 5: true, 10: true, 11: true, 13: true, 16: true, 18: true, 23: true,
	27: true, 28: true, 34: true, 35: true, 43: true, 45: true,
	51: true, 57: true, 17513: true, 17613: true,
	65037: true, 65281: true,
}

var supportedSignatureAlgorithms = map[string]bool{
	"rsa_pkcs1_md5_sha1": true, "rsa_pkcs1_sha1": true, "rsa_pkcs1_sha256": true,
	"rsa_pkcs1_sha384": true, "rsa_pkcs1_sha512": true, "ecdsa_sha1": true,
	"ecdsa_secp256r1_sha256": true, "ecdsa_secp384r1_sha384": true, "ecdsa_secp521r1_sha512": true,
	"rsa_pss_rsae_sha256": true, "rsa_pss_rsae_sha384": true, "rsa_pss_rsae_sha512": true,
	"ed25519": true, "mldsa44": true, "mldsa65": true, "mldsa87": true,
}
