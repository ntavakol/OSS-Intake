# Threat model

What oss-intake protects, where untrusted input enters, and what stops it doing harm. This document is being
written one trust boundary at a time (see BACKLOG.md); each section names the threats, the mitigations in the
code, and what is left open.

## VS Code extensions (`--path` with a .vsix or an extensions folder)

**What enters:** a `.vsix` file or an installed extension's files, chosen by the user but written by whoever
published the extension. The person running oss-intake is usually checking it precisely because they do not
trust it yet, so every byte of it is treated as hostile.

**Assets at risk:** the files of the user running oss-intake (a hostile archive could try to write outside the
folder it is unpacked into), the machine's disk and memory (an archive that expands without end), the honesty of
the report (an extension that hides what it does, or claims another project's identity), and the user's own
machine if the extension ever ran.

| Threat | Mitigation | Where |
|---|---|---|
| The extension's code runs during the check | Nothing in an extension is run, installed or imported: its files are only read as bytes and text. No XML parser runs on its manifest (a regular expression reads one element). | `vscode.py` |
| Path traversal ("zip slip"): a member named `../x`, `/x`, `C:/x` or with `\` writes outside the folder | Every member name is checked before anything is written; any of these refuses the whole file (exit 2). | `vscode._member_path` |
| A link inside the archive points outside the folder | Members marked as symbolic links are refused. When reading an installed folder, links are not followed. | `vscode.unpack`, `vscode.analyse` |
| Zip bomb: a small file that expands to fill the disk | At most 50,000 members, 300 MB a member and 1 GB in all, counted as the bytes are written (not trusted from the archive's directory), and no member over 1 MB that expands more than 200 times. | `vscode.unpack` |
| The archive plants the file oss-intake keeps its manifest copy in | The copy is written after unpacking, replacing any file of that name. | `vscode.unpack` |
| An unpacked copy is left behind | It is unpacked into a new temporary folder, removed in a `finally` whatever happens. | `cli.cmd_scan` |
| Reading a huge installed folder exhausts memory or time | Files over 20 MB are not read, reading stops at 400 MB in all, and at 50,000 files; what was not read is listed in the report. | `vscode.analyse` |
| Dependencies hidden by bundling make the report look clean | A large main file with no `node_modules` is reported as bundled, with a warning that no findings does not mean none. | `vscode.analyse`, `vscode.warnings` |
| Code hidden in invisible characters (GlassWorm) or reordered text (Trojan Source) | Variation selectors, tag characters, runs of zero-width characters and bidirectional controls are reported with file and line. | `vscode.analyse` |
| The extension claims a trusted project's repository, to borrow its health score | The `repository` field is shown as the publisher's claim and never checked automatically; `--repo` is the user's choice. | `report.extensions_section` |
| The extension claims another extension's identity | A folder name or `.vsix` manifest that disagrees with `package.json` is reported. | `vscode.analyse` |
| The removal list is unavailable, so a malicious extension passes a CI gate | The report says the list was not checked, and `--fail-on malicious` and `act` exit 1 rather than passing. A response with fewer than 100 rows is not taken as the list. | `vscode.load_removed`, `cli._gate_unknown` |
| The report itself is used to attack its reader (a name or path with markup) | Extension names, paths and details go through the same escaping as every other report value. | `report._md_cell`, `report_html` |

**Left open:**

- The Marketplace signature is not checked, so a `.vsix` repackaged after publication is not detected.
- The indicators are patterns in text: a determined author can avoid them (by fetching code at run time, for
  example). A clean result means none were found, not that the extension is safe.
- The removal list is fetched over HTTPS from GitHub and trusted as published; it is not signed.
- Bundled code is read for indicators but its dependencies cannot be named, so they are not checked.
