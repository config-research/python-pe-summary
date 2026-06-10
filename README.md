# python-pe-summary

`pe_summary.py` is a lightweight static triage script for Windows PE files. It is intended for first-stage malware analysis, where the goal is to quickly get a readable overview of a suspicious executable or DLL before opening heavier tools such as PEStudio, capa, FLOSS, IDA, or x64dbg.

By default, the script writes both a plain text report and a static HTML report. A detailed JSON report can also be written for later parsing, comparison, or tooling.

## Features

* File hashes: MD5, SHA1, SHA256, imphash, and authentihash
* PE header, compile timestamp, entry point, section, and data directory summary
* Section entropy, flags, layout anomalies, and suspicious section indicators
* Import capability hints, API combination findings, delay imports, and exports
* Resource inspection with full resource paths and embedded file/magic detection
* Overlay, TLS, certificate, .NET, version info, and Rich Header detection
* ASCII and UTF-16LE string scanning
* Confidence-ranked findings and string candidates
* URL, domain, IP, registry path, file path, UNC path, named pipe, and PDB path extraction
* Base64 and hex blob candidate decoding
* Runtime/bundled-binary context detection, including Node/V8 and Node SEA artifacts
* Recommended next steps for manual triage

## Install

```bash
pip install pefile
```

## Usage

Generate the default text and HTML reports:

```bash
python pe_summary.py sample.exe
```

Write the text report to a specific path:

```bash
python pe_summary.py sample.exe -o report.txt
```

Write the HTML report to a specific path:

```bash
python pe_summary.py sample.exe --html-output report.html
```

Disable HTML output:

```bash
python pe_summary.py sample.exe --no-html
```

Also write a detailed JSON report:

```bash
python pe_summary.py sample.exe -j
```

Write the JSON report to a specific path:

```bash
python pe_summary.py sample.exe -j --json-output details.json
```

Print the text report to the console:

```bash
python pe_summary.py sample.exe -p
```

Show help:

```bash
python pe_summary.py -h
```

## Output

Default output names:

```text
<sample>_pe_summary.txt
<sample>_pe_report.html
```

Optional JSON output:

```text
<sample>_pe_details.json
```

The text report is intended for quick terminal or editor-based triage. The HTML report is intended for easier navigation and review. The JSON report is more detailed and better suited for automation.
