#!/usr/bin/env python3
"""Generate the typed SetOpt table from the pinned vendored native header."""
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
source = (root / "internal/include/curl/curl.h").read_text()
bases = {"LONG": 0, "VALUES": 0, "STRINGPOINT": 10000, "SLISTPOINT": 10000,
         "OBJECTPOINT": 10000, "CBPOINT": 10000, "FUNCTIONPOINT": 20000,
         "OFF_T": 30000, "BLOB": 40000}
kinds = {}
for name, kind, number in re.findall(
        r"CURLOPT(?:DEPRECATED)?\(CURLOPT_(\w+),\s*CURLOPTTYPE_(\w+),\s*(\d+)", source):
    kinds[bases[kind] + int(number)] = {"STRINGPOINT": "string", "SLISTPOINT": "list",
                                     "BLOB": "blob"}.get(kind, "")
lines = ["// Code generated from pinned native curl.h; DO NOT EDIT.", "package curlgo",
         "var optionKinds = map[Option]string{"]
lines += [f'{number}: "{kind}",' for number, kind in sorted(kinds.items())]
lines.append("}")
destination = root / "option_kinds.go"
destination.write_text("\n".join(lines) + "\n")
subprocess.run(["gofmt", "-w", str(destination)], check=True)
