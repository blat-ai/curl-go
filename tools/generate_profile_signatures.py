#!/usr/bin/env python3
"""Extract wire expectations from the pinned release's lib/impersonate.c patch.

Usage: python3 tools/generate_profile_signatures.py path/to/curl.patch
This runs only during development; tests and the library never fetch source.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

CIPHERS = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA8,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": 0xC008,
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": 0xC012,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xC027,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xC028,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
    "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
}
for short, long in {
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
}.items():
    CIPHERS[short] = CIPHERS[long]

GROUPS = {"X25519": 29, "P-256": 23, "P-384": 24, "P-521": 25,
          "ffdhe2048": 256, "ffdhe3072": 257,
          "X25519Kyber768Draft00": 25497, "X25519MLKEM768": 4588}
SIGNATURES = {"ecdsa_secp256r1_sha256": 0x0403, "ecdsa_secp384r1_sha384": 0x0503,
              "ecdsa_secp521r1_sha512": 0x0603, "ecdsa_sha1": 0x0203,
              "rsa_pss_rsae_sha256": 0x0804, "rsa_pss_rsae_sha384": 0x0805,
              "rsa_pss_rsae_sha512": 0x0806, "rsa_pkcs1_sha256": 0x0401,
              "rsa_pkcs1_sha384": 0x0501, "rsa_pkcs1_sha512": 0x0601,
              "rsa_pkcs1_sha1": 0x0201, "mldsa44": 0x0904,
              "mldsa65": 0x0905, "mldsa87": 0x0906}
DEFAULT_SIGNATURES = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
STRINGS = re.compile(r'"(?:\\.|[^"\\])*"')


def strings(value):
    return [json.loads(token) for token in STRINGS.findall(value)]


def main():
    source = Path(sys.argv[1]).read_bytes()
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != "b198abcd1e7ad065d5fc1d9d68ce99226ebc89bc7e1fa23c6aa9304b7e265bf1":
        raise SystemExit("Source patch does not match curl-impersonate v2.2.3; update the pinned release intentionally.")
    patch = source.decode().split("+++ b/lib/impersonate.c\n", 1)[1].split("diff --git", 1)[0]
    c = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+"))
    expected = {}
    for name, block in re.findall(r'\{\s*\.target\s*=\s*"(.*?)"(.*?)\n  \}', c, re.S):
        # The native patch also has an unadvertised okhttp4_android target,
        # annotated "not working". curl_cffi does not expose this target; the
        # public binding supports its 38 documented browser profiles.
        if name == "okhttp4_android":
            continue
        fields = {m.group(1): m.group(2) for m in re.finditer(
            r'\.(\w+)\s*=\s*(.*?)(?=\n\s*\.\w+\s*=|$)', block, re.S)}

        def string(field, default=""):
            return "".join(strings(fields.get(field, ""))) or default

        def number(field, default=0):
            return int(fields.get(field, str(default)).strip().rstrip(","))

        sig = string("sig_hash_algs")
        extension_order = string("tls_extension_order")
        expected[name] = {
            "headers": strings(fields["http_headers"]),
            "ciphers": [CIPHERS[s] for s in string("ciphers").split(":")],
            "groups": [GROUPS[s] for s in string("curves", "X25519:P-256:P-384").split(":")],
            "signature_algorithms": [SIGNATURES[s] for s in sig.split(":")] if sig else DEFAULT_SIGNATURES,
            "grease": fields.get("tls_grease", "false,").strip().startswith("true"),
            "permute_extensions": fields.get("tls_permute_extensions", "false,").strip().startswith("true"),
            "ech": string("ech") == "true",
            "extension_order": [int(v) for v in extension_order.split("-")] if extension_order else [],
            "http3_settings": string("http3_settings"),
            "quic_transport_parameters": string("quic_transport_parameters"),
            "quic_cid_length": string("quic_cid_length"),
            "quic_initial_packet_number": number("quic_initial_packet_number"),
            "http2_settings": string("http2_settings"),
            "http2_window_update": number("http2_window_update"),
            "http2_pseudo_headers_order": string("http2_pseudo_headers_order", "masp"),
        }
    output = {"native_release": "v2.2.3", "source": "patches/curl.patch:lib/impersonate.c",
              "source_commit": "6e8f87760a4dd96771e96fc9d55440dcd8845243",
              "source_sha256": source_sha256, "profiles": expected}
    destination = Path(__file__).resolve().parent.parent / "testdata" / "profile_signatures.json"
    destination.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {len(expected)} profile expectations to {destination}")


if __name__ == "__main__":
    main()
