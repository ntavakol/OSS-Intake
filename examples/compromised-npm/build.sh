#!/usr/bin/env sh
# Rebuild the published sample report from the lockfile in this folder.
# Needs oss-intake, Trivy and Grype on PATH, and network access (OSV, deps.dev).
# Only the lockfile is read: nothing is downloaded from npm or installed, so the malicious code never runs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The file is stored under another name so repository scanners (OpenSSF Scorecard) do not report these
# deliberately malicious versions as dependencies of this project.
cp "$here/package-lock.sample.json" "$work/package-lock.json"
oss-intake scan --path "$work/package-lock.json" --out "$work/out" --formats csv,html --quiet
mkdir -p "$repo/site/samples/compromised-npm"
cp "$work/out/report.html" "$work/out/findings.csv" "$repo/site/samples/compromised-npm/"
echo "Updated site/samples/compromised-npm/ (report.html, findings.csv). Review, then commit."
