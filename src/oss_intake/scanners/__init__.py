"""Scanner adapters. External scanners are invoked as separate executables; none are bundled."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .. import jsonsafe

# Docker or containerd failing to export a locally stored image (pruned layers, other-platform pulls).
AUTH_ERROR = re.compile(r"unauthori[sz]ed|authentication required|no basic auth credentials|access denied|"
                        r"denied: |\b401\b|\b403\b|could not find credentials|NoCredentialProviders", re.I)
LOCAL_IMAGE_ERROR = re.compile(r"unable to export the image|content digest sha256:[0-9a-f]+: not found|"
                               r"unable to inspect the image", re.IGNORECASE)


class ScannerError(Exception):
    """Raised when a scanner cannot be run, fails or times out, or its output is not valid JSON."""
    pass


def find_executable(name: str, explicit: str | None = None) -> str:
    """Resolve a scanner binary. An explicit path wins; otherwise PATH (handles .exe on Windows)."""
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise ScannerError(f"{name} not found at {p}")
        return str(p.resolve())
    found = shutil.which(name)
    if not found:
        raise ScannerError(
            f"{name} not found on PATH. Install a pinned, checksum-verified release or pass --{name}-path."
        )
    return found


def path_arg(path: str | Path) -> str:
    """A path as a scanner argument: one starting with '-' (a folder named '-x', or '--config=...') would be read
    as an option, so it is given as './-x'. Absolute paths and others are unchanged."""
    s = str(path)
    return os.path.join(".", s) if s.startswith("-") else s


# Credentials oss-intake reads for its own requests, which no program it starts needs: a scanner, docker, crane
# or cosign that was swapped (Trivy 0.69.4 was a release that stole credentials) must not get them.
SECRET_ENV = ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


# What a program oss-intake starts is given of this environment (external audit SEC-14): what any program needs
# to run, find files and reach the network, and each tool's own settings, nothing else. Cloud credentials,
# publishing tokens, SSH agents and anything unlisted stay out unless the user passes them on (--scanner-env).
# This keeps secrets held in environment variables (as on CI) from a swapped scanner; it is not a sandbox, as
# the program still runs as the user and can read their files.
BASE_ENV = (
    "PATH", "HOME", "USER", "USERNAME", "LOGNAME", "SHELL", "TERM", "TZ", "LANG", "LANGUAGE", "LC_*",
    "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    # Windows needs these to start a program at all
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
    "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "PUBLIC", "OS", "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
)
TOOL_ENV = {  # each tool's own settings, given to that tool only (TRIVY_PASSWORD is Trivy's, not Grype's)
    "trivy": ("TRIVY_*", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT",
              "CONTAINER_HOST", "REGISTRY_AUTH_FILE"),
    "grype": ("GRYPE_*", "SYFT_*", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
              "DOCKER_CONTEXT", "CONTAINER_HOST", "REGISTRY_AUTH_FILE"),
    "docker": ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT"),
    "crane": ("DOCKER_CONFIG", "REGISTRY_AUTH_FILE"),
    "govulncheck": ("GOPATH", "GOROOT", "GOCACHE", "GOTOOLCHAIN", "GOPROXY", "GONOPROXY", "GOPRIVATE", "GOFLAGS"),
    "cosign": ("COSIGN_*", "SIGSTORE_*", "TUF_ROOT"),
}
_extra_env: list[str] = []  # --scanner-env patterns for this run


def set_extra_env(patterns: list[str] | None) -> None:
    """The --scanner-env patterns: more variables to pass on to every program started (never the GitHub
    tokens)."""
    _extra_env[:] = list(patterns or [])


def _tool(cmd0: str) -> str:
    name = re.split(r"[\\/]", cmd0)[-1].lower()  # either separator: a Windows path read anywhere
    for suffix in (".exe", ".cmd", ".bat"):
        name = name.removesuffix(suffix)
    return next((t for t in TOOL_ENV if name == t or name.startswith(t + "-") or name.startswith(t + "_")), name)


def child_env(cmd0: str = "") -> dict[str, str]:
    """The environment for a program oss-intake starts: BASE_ENV, the tool's own settings (TOOL_ENV, from the
    program's name), and the --scanner-env patterns; never the GitHub tokens."""
    from fnmatch import fnmatchcase

    keep = (*BASE_ENV, *TOOL_ENV.get(_tool(cmd0), ()), *_extra_env)
    return {k: v for k, v in os.environ.items()
            if k.upper() not in SECRET_ENV and any(fnmatchcase(k.upper(), p.upper()) for p in keep)}


# What a program oss-intake starts may write before it is stopped (external audit SEC-02): a scanner report can
# run to hundreds of MB for a large image; its error output is a few lines.
MAX_STDOUT = 1024 * 1024 * 1024
MAX_STDERR = 1024 * 1024


class OutputTooLarge(ScannerError):
    pass


def capped_run(cmd: list[str], timeout: float, max_stdout: int = MAX_STDOUT,
               max_stderr: int = MAX_STDERR) -> subprocess.CompletedProcess:
    """subprocess.run without a shell, with child_env(), a timeout, and a limit on what is collected from stdout and
    stderr: past either, the program is killed and OutputTooLarge raised, so a broken or hostile program cannot
    exhaust memory. Raises subprocess.TimeoutExpired and OSError as subprocess.run does."""
    import threading

    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=child_env(cmd[0]))
    out, err, over = bytearray(), bytearray(), []

    def pump(stream, buf: bytearray, limit: int, name: str) -> None:
        for chunk in iter(lambda: stream.read(1 << 16), b""):
            if len(buf) + len(chunk) > limit:
                over.append(name)
                proc.kill()
                break
            buf += chunk
        stream.close()

    readers = [threading.Thread(target=pump, args=(proc.stdout, out, max_stdout, "output"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err, max_stderr, "error output"), daemon=True)]
    for t in readers:
        t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        for t in readers:
            t.join(timeout=10)
    if over:
        limit = max_stdout if over[0] == "output" else max_stderr
        raise OutputTooLarge(f"{Path(cmd[0]).name} wrote more than {limit // (1024 * 1024)} MB of {over[0]}, so "
                             "it was stopped")
    return subprocess.CompletedProcess(cmd, proc.returncode, bytes(out), bytes(err))


def run(cmd: list[str], timeout: int) -> bytes:
    """Run a command without a shell and return stdout bytes. Raises ScannerError on failure."""
    try:
        proc = capped_run(cmd, timeout)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"{Path(cmd[0]).name} timed out after {timeout}s") from None
    except OSError as exc:
        raise ScannerError(f"could not run {Path(cmd[0]).name}: {exc}") from None
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        if not err:
            err = proc.stdout.decode("utf-8", errors="replace").strip() or "(no output; rerun the scanner by hand)"
        tail = err.splitlines()[-5:]
        msg = f"{Path(cmd[0]).name} exited {proc.returncode}: " + " | ".join(tail)
        if AUTH_ERROR.search(err):
            msg += (" (if the registry's credentials come from your environment, as for ECR, ACR or GCR, pass "
                    "them on with --scanner-env, for example --scanner-env 'AWS_*'; programs oss-intake starts "
                    "get only the variables they need)")
        if LOCAL_IMAGE_ERROR.search(err):
            msg += (" (the local container engine could not export the image; rerun with --image-src remote to pull "
                    "it from the registry, or remove and re-pull the local copy)")
        raise ScannerError(msg)
    return proc.stdout


def load_json_bytes(data: bytes, what: str) -> dict:
    """Parse JSON bytes that may be UTF-16 with a BOM (PowerShell 5.1 redirection) or UTF-8 with or without a BOM.
    Raises ScannerError naming what if it is not valid JSON."""
    # Windows PowerShell 5.1 redirection (trivy ... > out.json) writes UTF-16 with a byte order mark.
    encoding = "utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    try:
        return jsonsafe.loads(data.decode(encoding))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # ValueError: also an integer too long to read
        raise ScannerError(f"{what} is not valid JSON: {exc or 'nested too deeply'}") from None


def report_kind(data: object) -> str:
    """'trivy', 'grype' or 'unknown', from the shape of a JSON report."""
    if not isinstance(data, dict):
        return "unknown"
    if "SchemaVersion" in data and isinstance(data.get("Results", []), list) and "matches" not in data:
        return "trivy"
    name = (data.get("descriptor") or {}).get("name") if isinstance(data.get("descriptor"), dict) else None
    if "SchemaVersion" not in data and "matches" in data and name in (None, "grype"):
        # Grype writes [] for a clean scan; very old releases wrote null, which only counts with Grype's descriptor.
        if isinstance(data["matches"], list) or (data["matches"] is None and name == "grype"):
            return "grype"
    if data.get("bomFormat") == "CycloneDX" or "spdxVersion" in data:
        return "sbom"
    return "unknown"


def check_report(data: object, tool: str, what: str) -> None:
    """Refuse a report that is not the tool's JSON, so a wrong or empty file never reads as 'no findings'."""
    kind = report_kind(data)
    if kind == tool and isinstance(data, dict):
        problem = _shape_problem(data, tool)
        if problem:
            raise ReportShapeError(f"{what} is not a well-formed {tool.capitalize()} report: {problem}")
        # A report that names nothing it scanned and lists nothing is a truncated or hand-made file, not a clean
        # scan: Trivy always writes ArtifactName and Grype its descriptor and source, even when they find nothing.
        named = data.get("ArtifactName") if tool == "trivy" else (data.get("descriptor") or data.get("source"))
        listed = data.get("Results") if tool == "trivy" else data.get("matches")
        if not named and not listed:
            raise ReportShapeError(f"{what} names nothing it scanned and lists nothing (no "
                                   + ("ArtifactName or Results" if tool == "trivy" else "descriptor, source or matches")
                                   + "), so it is not a scan's report and cannot read as clean")
        return
    looks = {"trivy": "a Trivy report", "grype": "a Grype report",
             "sbom": "an SBOM (CycloneDX or SPDX), which lists packages but not vulnerabilities"}.get(kind)
    expected = {"trivy": "a Trivy JSON report (trivy ... --format json), with SchemaVersion and Results",
                "grype": "a Grype JSON report (grype ... -o json), with matches"}[tool]
    raise ReportShapeError(f"{what} is not {expected}" + (f"; it looks like {looks}" if looks else
                                                         "; it has neither shape"))


_STR_FIELDS = {
    "trivy_result": ("Target", "Type", "Class"),
    "trivy_vuln": ("VulnerabilityID", "PkgID", "PkgName", "PkgPath", "InstalledVersion", "FixedVersion", "Severity",
                   "SeveritySource", "PublishedDate", "LastModifiedDate", "Title", "Description", "PrimaryURL"),
    "trivy_pkg": ("ID", "Name", "Version", "SrcName", "SrcVersion", "SrcRelease"),
    "grype_artifact": ("name", "version", "type", "purl"),
    "grype_vuln": ("id", "severity", "namespace", "dataSource", "description"),
}
# Lists of text and objects the readers iterate.
_STR_LISTS = {"trivy_vuln": ("CweIDs", "VendorIDs", "References"), "grype_vuln": ("urls",),
              "grype_artifact": ("cpes",)}
_OBJECTS = {"trivy_vuln": ("PkgIdentifier", "CVSS", "DataSource", "VendorSeverity"), "trivy_pkg": ("Identifier",),
            "grype_vuln": ("fix",), "grype_artifact": ("metadata",)}


def _bad_fields(obj: dict, kind: str) -> str | None:
    for k in _STR_FIELDS[kind]:
        if obj.get(k) is not None and not isinstance(obj[k], str):
            return k
    for k in _STR_LISTS.get(kind, ()):
        v = obj.get(k)
        if v is not None and not (isinstance(v, list) and all(isinstance(e, str) for e in v)):
            return k
    for k in _OBJECTS.get(kind, ()):
        if obj.get(k) is not None and not isinstance(obj[k], dict):
            return k
    for k in ("PkgIdentifier", "Identifier"):
        if isinstance(obj.get(k), dict) and not all(isinstance(obj[k].get(f) or "", str) for f in ("PURL", "UID")):
            return f"{k}.PURL"
    if kind == "grype_vuln" and isinstance(obj.get("fix"), dict):
        fix = obj["fix"]
        if not (isinstance(fix.get("state") or "", str) and isinstance(fix.get("versions") or [], list)
                and all(isinstance(e, str) for e in fix.get("versions") or [])):
            return "fix"
    return None


def _shape_problem(data: dict, tool: str) -> str | None:
    """The first place a report of the right kind has a value of the wrong type, as the fields oss-intake reads
    (here and after parsing) expect; None when it is well formed. Deeper oddities are caught when parsing."""
    def lists(obj: dict, key: str) -> list | None:
        v = obj.get(key)
        return [] if v is None else v if isinstance(v, list) and all(isinstance(e, dict) for e in v) else None

    if tool == "trivy":
        if not isinstance(data.get("Metadata", {}) or {}, dict):
            return "Metadata is not an object"
        results = lists(data, "Results")
        if results is None:
            return "Results must be a list of objects"
        for n, r in enumerate(results, 1):
            if (k := _bad_fields(r, "trivy_result")) is not None:
                return f"result {n}: {k} is not text"
            for key, kind in (("Vulnerabilities", "trivy_vuln"), ("Packages", "trivy_pkg")):
                entries = lists(r, key)
                if entries is None:
                    return f"result {n}: {key} must be a list of objects"
                for m, e in enumerate(entries, 1):
                    if (k := _bad_fields(e, kind)) is not None:
                        return f"result {n}, {key} entry {m}: {k} is not of the right type"
        return None
    matches = lists(data, "matches")
    if matches is None:
        return "matches must be a list of objects"
    for key in ("descriptor", "distro", "source"):
        if not isinstance(data.get(key) or {}, dict):
            return f"{key} is not an object"
    for n, m in enumerate(matches, 1):
        for key, kind in (("artifact", "grype_artifact"), ("vulnerability", "grype_vuln")):
            obj = m.get(key) or {}
            if not isinstance(obj, dict):
                return f"match {n}: {key} is not an object"
            if (k := _bad_fields(obj, kind)) is not None:
                return f"match {n}: {key}.{k} is not of the right type"
        if lists(m, "relatedVulnerabilities") is None:
            return f"match {n}: relatedVulnerabilities must be a list of objects"
        locations = lists(m.get("artifact") or {}, "locations")
        if locations is None or not all(isinstance(loc.get("path") or "", str) for loc in locations):
            return f"match {n}: artifact.locations must be a list of objects with a text path"
    return None


class ReportShapeError(ValueError):
    """Raised when a JSON report is not the expected Trivy or Grype shape; the message says what it looks like."""
    pass
