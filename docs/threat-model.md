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
| Path traversal ("zip slip"): a member named `../x`, `/x`, `C:/x`, `a/D:/x` or with `\` writes outside the folder, on any system | Every member name is checked before anything is written: no colon or backslash anywhere, no root or drive, no empty, `.` or `..` part, no part ending in a dot or space (Windows drops them), no reserved device name (`con`, `nul`, `com1`...), no control character. Any of these refuses the whole file (exit 2). | `vscode._member_path` |
| Two members that are one file on macOS or Windows (`extension/x` and `EXTENSION/x`), so the file checked is not the one installed | Names are compared after Unicode normalisation and case folding; a repeat refuses the whole file. | `vscode.unpack` |
| A damaged, encrypted or oddly compressed archive crashes the run | Read errors are refused as input errors (exit 2), with the reason. | `vscode.unpack` |
| A link inside the archive points outside the folder | Members marked as symbolic links are refused. Inside an installed extension, links are not followed. An extension that is itself installed as a link (as for one being developed) is followed, since it is installed. | `vscode.unpack`, `vscode._files`, `vscode.extension_folders` |
| A folder named `extension` inside an installed extension stands in for it (a decoy that hides the real one and every other extension in the folder) | The `<name>/extension` layout is read only in the temporary folder a `.vsix` was unpacked into; a folder the user gives is read as installed extensions. | `vscode.assess` |
| Zip bomb: a small file that expands to fill the disk | At most 50,000 members, 300 MB a member and 1 GB in all, counted as the bytes are written (not trusted from the archive's directory), and no member over 1 MB that expands more than 200 times. | `vscode.unpack` |
| The archive plants the file oss-intake keeps its manifest copy in | The copy is written after unpacking, replacing any file of that name, and is read only for an unpacked `.vsix`. | `vscode.unpack`, `vscode.assess` |
| An unpacked copy is left behind | It is unpacked into a new temporary folder, removed in a `finally` whatever happens. | `cli.cmd_scan` |
| Reading a huge installed folder, or text crafted to make the checks slow, exhausts memory or time | Files over 20 MB are not read, reading stops at 400 MB in all and at 50,000 files an extension, and what was not read is listed in the report. The patterns are matched in linear time (encoded strings are found as whole runs and measured in code), each indicator stops at 20 hits, and line numbers come from one pass. | `vscode.analyse` |
| Code hidden where it is not read: a main file with an odd name or none, or code under a `node_modules` folder of its own | Every file of the extension's own is read as text unless it is binary or a source map, and its main file always is. `child_process` and `eval` are not looked for in documentation and markup files (a `.md`, `.txt` or `.yml` that code requires would get past those two checks, though not the hidden-character and encoded-string checks). The top-level `node_modules`, its dependencies, is left to the scanners, except for hidden characters, which are looked for there too (a private package is unknown to any database). | `vscode.analyse` |
| An extension's own `.obsolete` file marks it "old version, not in use", hiding its indicators | `.obsolete` is read only in a folder of extensions, never inside an extension's own folder or a `.vsix`. One in the extensions folder itself needs code that already runs on the machine to write it. | `vscode.assess` |
| Findings matched to the wrong extension, or matching made slow by a crafted SBOM or lockfile | Each shipped SBOM or lockfile is read once, within the reading limit, into the exact package names and versions it lists; findings are looked up in that, not searched for in the text. One that is over the limit is reported. | `vscode._listed`, `vscode.attribute` |
| An absolute path of the user's machine written into the report | The extension's folder is used only while findings are matched and never reaches `assessment.json`. | `vscode.attribute` |
| Dependencies hidden by bundling make the report look clean | A large main file with no npm package the scanners can see (an empty `node_modules`, or one behind a link, shows none) is reported as bundled, with a warning that no findings does not mean none. | `vscode.analyse`, `vscode.warnings` |
| Code hidden in invisible characters (GlassWorm) or reordered text (Trojan Source) | Variation selectors, tag characters, runs of zero-width characters and bidirectional controls are reported with file and line. | `vscode.analyse` |
| The extension claims a trusted project's repository, to borrow its health score | The `repository` field is shown as the publisher's claim and never checked automatically; `--repo` is the user's choice. | `report.extensions_section` |
| The extension claims another extension's identity, or rewrites its own to dodge the removal list | A folder name or `.vsix` manifest that disagrees with `package.json` is reported, and every one of those names is looked up in the list. IDs are compared after case folding and Unicode compatibility normalisation, with spaces and invisible format characters removed. | `vscode.analyse`, `vscode._key` |
| The removal list is unavailable, so a malicious extension passes a CI gate | The report says the list was not checked, and `--fail-on malicious` and `act` exit 1 rather than passing. A response with fewer than 100 rows is not taken as the list. | `vscode.load_removed`, `cli._gate_unknown` |
| The report itself is used to attack its reader (a name or path with markup) | Extension names, paths and details go through the same escaping as every other report value. | `report._md_cell`, `report_html` |

**Left open:**

- A copy of listed malware republished under a new name is a different extension: the list does not name it,
  so only the indicators can show it.
- Reading is shared across a folder: an extension early in the order can use up the 400 MB, so later ones are
  listed as not read rather than checked.
- The archive's directory is read whole by Python's zipfile before the member count is checked.
- Trivy reads the unpacked files, so a flaw in Trivy's parsers is exposed to them; pin and verify Trivy as the
  guide describes.
- The Marketplace signature is not checked, so a `.vsix` repackaged after publication is not detected.
- The indicators are patterns in text: a determined author can avoid them (by fetching code at run time, for
  example). A clean result means none were found, not that the extension is safe.
- The removal list is fetched over HTTPS from GitHub and trusted as published; it is not signed.
- Bundled code is read for indicators but its dependencies cannot be named, so they are not checked.
