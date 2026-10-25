#!/usr/bin/env python3
"""Stand-in for govulncheck in tests: same output format, fixed answers."""
import sys

if "-version" in sys.argv:
    print("Go: go1.24.7\nScanner: govulncheck@v1.1.4\nDB: https://vuln.go.dev\nDB updated: 2026-10-20 00:00:00")
    sys.exit(0)
print("""{
  "config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scan_mode": "binary"}
}
{
  "osv": {"id": "GO-2099-0001", "aliases": ["CVE-2099-7777", "GHSA-aaaa-bbbb-cccc"]}
}
{
  "osv": {"id": "GO-2099-0002", "aliases": ["CVE-2099-7778"]}
}
{
  "finding": {"osv": "GO-2099-0001", "fixed_version": "v1.21.5",
              "trace": [{"module": "stdlib", "version": "v1.21.0", "package": "net/http", "function": "Serve"}]}
}
{
  "finding": {"osv": "GO-2099-0002", "fixed_version": "v1.21.5",
              "trace": [{"module": "stdlib", "version": "v1.21.0"}]}
}""")
