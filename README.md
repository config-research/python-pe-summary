# python-pe-summary

`pe_summary.py` is a lightweight static triage script for Windows PE files. It is intended for first-stage malware analysis, where the goal is to quickly get a readable overview of a suspicious executable or DLL before opening heavier tools like PEStudio, capa, FLOSS, IDA, or x64dbg.

The script creates a text report by default and can optionally also write a detailed JSON report.

## Features

- File hashes: MD5, SHA1, SHA256, imphash, authentihash
- PE header summary
- Compile timestamp checks
- Section layout, entropy, flags, and anomalies
- Entry point location and section context
- Import capability hints
- API combination findings
- Delay imports and exports
- Resource inspection with full resource paths
- Embedded file/magic detection in resources and overlay
- Overlay, TLS, certificate, and .NET detection
- Version info and Rich Header information
- ASCII and UTF-16LE string scanning
- Confidence-ranked string candidates and findings
- URL, domain, IP, registry path, file path, UNC path, named pipe, and PDB path candidates
- Base64/hex blob candidate decoding
- Runtime/bundled-binary context detection, including Node/V8 and Node SEA artifacts
- Structured findings and recommended next steps


## Install

```bash
pip install pefile
```
## Usage
Generate the default text report:
```bash
python pe_summary.py sample.exe
```

Also write a detailed JSON report:
```bash
python pe_summary.py sample.exe -j
```

Print the text report to the console as well:
```bash
python pe_summary.py sample.exe -p
```

Write the text report to a specific path:
```bash
python pe_summary.py sample.exe -o report.txt
```

Show help:
```bash
python pe_summary.py -h
```

The text report is intended for human-readable triage. The JSON report is more detailed and better suited for later parsing, comparison, or tooling.
