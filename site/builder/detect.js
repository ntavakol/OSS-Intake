// oss-intake command builder: "Paste what you were given". Reads a link, an install command, a package, an image
// or a file name, and says what to check. Everything happens here, in the page: nothing is looked up, so a link
// with no version, or a repository's contents, cannot be filled in and is asked about instead.
//
// detect(text, ctx) gives one of:
//   { status: "ok", what, values, says }       ready: what to check (a wizard answer) and its option values
//   { status: "ask", says, choices: [...] }    one question; each choice is an "ok" or a "no" result, with a label
//   { status: "no", says }                     understood, but not something to check as it is (says what to do)
//   { status: "unknown", says }                not recognised
// ctx is { wiz, rules }: wizard.json (lockfile names, ecosystems and their purl types, the CLI's version rule) and rules.json
// (the image checks the CLI makes). Every "ok" package passes the checks the CLI's --package makes (inputs.packages).

const MAX = 2000;
const ASK_ECOSYSTEMS = [["npm", "npm"], ["pypi", "PyPI"], ["nuget", "NuGet"], ["cargo", "Cargo (Rust)"],
  ["gem", "RubyGems"], ["composer", "Composer (PHP)"]];
const LABELS = { npm: "an npm", pypi: "a PyPI", maven: "a Maven", nuget: "a NuGet", cargo: "a Cargo (Rust)",
  gem: "a RubyGems", composer: "a Composer (PHP)", golang: "a Go", cran: "a CRAN", hex: "a Hex", pub: "a Pub" };
const no = (says) => ({ status: "no", says });
const decoded = (x) => { try { return decodeURIComponent(x); } catch { return x; } };

/** A short folder name from what is checked: report-chalk-5.6.1, report-nginx-1.27, report-web. */
export function slug(values) {
  let base;
  if (values.package) {
    let p = values.package[0];
    try { p = decodeURIComponent(p); } catch { /* keep as is */ }
    base = p.split("?")[0].replace(/^pkg:[a-z]+\//i, "").replace(/^\.?[a-z.]+:/i, "");
  } else if (values.image) base = values.image.replace(/@sha256:.*/, "").split("/").slice(-2).join("-");
  else if (values.repo) base = values.repo;
  else {
    // A lockfile is named for its project's folder; any other file for itself, without its extension.
    const parts = String(values.path ?? "").split(/[\\/]/).filter((x) => x && x !== "~" && x !== "." && x !== "..");
    const file = parts.pop() ?? "";
    const generic = /^(package-lock|npm-shrinkwrap|yarn|pnpm-lock|poetry|uv|pdm|Pipfile|Cargo|composer|Gemfile|go|gradle|renv)\.|^(requirements[\w.-]*\.txt|pom\.xml|packages\.lock\.json)$/;
    base = generic.test(file) && parts.length ? parts.pop() : file.replace(/\.(tar\.gz|cdx\.json|spdx\.json|[A-Za-z]+)$/i, "");
  }
  const s = String(base).replace(/[^A-Za-z0-9.]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").toLowerCase();
  return (s || "check").slice(0, 60);
}

function ok(what, values, says) {
  return { status: "ok", what, values: { ...values, out: values.out ?? `report-${slug(values)}` }, says };
}

// ---------------------------------------------------------------- packages, checked as the CLI checks them

/** Why the CLI's --package would refuse this, or "" (inputs.packages: the version rule, names, Maven). */
function packageProblem(ctx, ptype, rawName, rawVersion) {
  // The CLI decodes %xx in names and versions before it checks them, so this does too.
  const name = decoded(rawName);
  const version = decoded(rawVersion ?? "");
  if (!version) return "it has no version";
  if (new RegExp(ctx.wiz.version_not_allowed, "i").test(version)) return `"${version}" is a range or a placeholder, not one version`;
  // A tag such as next, beta or canary names whatever was published last, like latest: not one version.
  if (!/^v?\d/i.test(version)) return `"${version}" is a tag, not a version number`;
  if (/\s/.test(name) || !name.replace(/^[/@]+|[/@]+$/g, "")) return "the name is not valid";
  if (name.startsWith("@") && !name.includes("/")) return "a scoped npm name is @scope/name";
  if (name.slice(1).includes("@")) return "the name has an @ in it";
  if (name.replace(/^@/, "").split("/").includes("")) return "the name has an empty part";
  if (ptype === "maven") {
    const [group, artifact] = name.replace("/", ":").split(":");
    if (!group || !artifact) return "a Maven name is group:artifact, such as org.apache.logging.log4j:log4j-core";
  }
  return "";
}

function packageResult(ctx, eco, name, version) {
  const ptype = ctx.wiz.ecosystems[eco] ?? eco;
  const label = LABELS[ptype] ?? `a ${eco}`;
  const problem = packageProblem(ctx, ptype, name, version);
  if (problem) {
    const fix = /version|range|tag/.test(problem) ? ` Give the exact version you use, such as ${eco}:${name}@1.2.3.` : "";
    return no(`${label} package ${name}, but ${problem}.${fix}`);
  }
  return ok("package", { package: [`${ptype}:${name}@${version}`] }, `${label} package: ${name} ${version}`);
}

function packagesResult(results) {
  const bad = results.find((r) => r.status !== "ok");
  if (bad) return bad;
  const seen = new Set();
  results = results.filter((r) => !seen.has(r.values.package[0]) && seen.add(r.values.package[0]));
  if (results.length === 1) return results[0];
  const list = results.map((r) => r.values.package[0]);
  return ok("package", { package: list }, `${results.length} packages: `
    + results.map((r) => r.says.replace(/^.*? package: /, "")).join(", "));
}

function needVersion(label, name, how) {
  return no(`${label} package ${name}, but with no version. Add the version you use (${how}), then paste again: `
    + "oss-intake checks one exact version, and this page does not look anything up.");
}

// ---------------------------------------------------------------- images, repositories, files

function imageProblem(ref, rules) {
  const name = ref.split("@")[0].replace(/:[^/:]*$/, "");
  if (/[A-Z]/.test(name)) return "image names are lowercase";
  for (const f of rules.fields.filter((x) => x.dest === "image" && x.pattern)) {
    if (!new RegExp(f.pattern).test(ref)) return f.message.replace(/^must /, "it must ");
  }
  return "";
}

function imageResult(ref, rules) {
  const problem = imageProblem(ref, rules);
  if (problem) {
    return no(`a container image, ${ref}, but ${problem}. Give the image with the tag you run, such as `
      + `${ref.split("@")[0].replace(/:[^/:]*$/, "").toLowerCase()}:1.2.3.`);
  }
  const latest = /:latest$/.test(ref) ? " (\"latest\" moves: the report is for what it points to today)" : "";
  return ok("image", { image: ref }, `a container image: ${ref}${latest}`);
}

const GITHUB_RESERVED = new Set(["orgs", "users", "marketplace", "settings", "sponsors", "topics", "apps",
  "features", "pricing", "login", "join", "explore", "notifications", "search", "collections", "events",
  "trending", "about", "contact", "security", "enterprise", "codespaces", "issues", "pulls", "new", "organizations"]);

function repoResult(owner, name, rules) {
  const repo = `${owner}/${name.replace(/\.git$/, "")}`;
  const field = rules.fields.find((x) => x.dest === "repo" && x.pattern);
  if (field && !new RegExp(field.pattern).test(repo)) {
    return no(`${repo} is not a GitHub project name. A project is owner/name, such as https://github.com/owner/name.`);
  }
  return ok("repo", { repo }, `a GitHub project: ${repo}. This checks the project's health; to check its `
    + "dependencies, download its lockfile and paste the file's name");
}

const MANIFESTS = {
  "package.json": "package-lock.json (make it without running anything: npm install --package-lock-only --ignore-scripts)",
  "build.gradle": "gradle.lockfile (gradle dependencies --write-locks)",
  "build.gradle.kts": "gradle.lockfile (gradle dependencies --write-locks)",
  "packages.config": "packages.lock.json",
  "requirements.in": "the requirements.txt made from it",
  "Pipfile": "Pipfile.lock",
  "pyproject.toml": "its lockfile (poetry.lock, uv.lock or pdm.lock)",
  "Gemfile": "Gemfile.lock",
  "Cargo.toml": "Cargo.lock",
  "composer.json": "composer.lock",
};

// What the CLI scans as built files (Trivy rootfs): Java archives and programs. Other files are not guessed.
const BUILT = /\.(jar|war|ear|par|sar|hpi|jpi|exe|dll|so|dylib|bin)$/i;
const OTHER_LOCKS = /^(pubspec\.lock|mix\.lock|Podfile\.lock|Package\.resolved|flake\.lock|conan\.lock)$/;

const lastPart = (text) => text.replace(/[\\/]+$/, "").split(/[\\/]/).filter(Boolean).pop() ?? "";
const hasExtension = (name) => /\.[A-Za-z][A-Za-z0-9]*$/.test(name);
const pathLike = (text) => /^(~|\.{1,2})?[\\/]|^[A-Za-z]:([\\/]|$)|^\.{1,2}$|[\\/]$/.test(text);

/** A file named the way the CLI reads files by name (inputs.classify), or null. Anything with an extension that
 * is not a lockfile, package list or SBOM is a file the CLI scans as built files. */
function fileResult(text, ctx) {
  const name = lastPart(text);
  const lower = name.toLowerCase();
  if (MANIFESTS[name]) return no(`${name} lists version ranges, not the versions installed. Check ${MANIFESTS[name]} instead.`);
  if (name === "renv.lock" || new RegExp(ctx.wiz.lockfile_names).test(name)) {
    return ok("lockfile", { path: text }, `a project's dependency list: ${name}`);
  }
  if (!hasExtension(name)) return null;
  if (lower.endsWith(".csv")) return ok("inventory", { path: text }, `a package list: ${name}`);
  if (/(\.cdx\.json|\.spdx\.json|bom\.json|sbom.*\.json)$/.test(lower)) return ok("inventory", { path: text }, `an SBOM: ${name}`);
  if (/\.(spdx|xml|rdf|ya?ml|tag-value)$/.test(lower) && /bom|spdx/.test(lower)) {
    return no(`${name}: oss-intake reads SBOMs as JSON (CycloneDX or SPDX). Export it as JSON and paste that name.`);
  }
  if (/^requirements|req.*\.txt$|\.txt$/.test(lower) && /req/.test(lower)) {
    return no(`${name}: oss-intake reads a pip requirements file by its name, requirements*.txt. Copy it to a name `
      + `such as requirements-${lower.replace(/\.txt$/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "app"}.txt and paste that.`);
  }
  if (OTHER_LOCKS.test(name)) return no(`${name} is not a lockfile oss-intake reads. Check the built app or an SBOM made from it instead.`);
  if (lower.endsWith(".vsix")) {
    return no("a VS Code extension package (.vsix). oss-intake cannot open .vsix files yet: check the extension's "
      + "source instead, by its GitHub link or its package-lock.json.");
  }
  if (lower.endsWith(".crx") || lower.endsWith(".xpi")) return no("a browser extension. oss-intake does not check browser extensions.");
  if (BUILT.test(lower)) return ok("artifact", { path: text }, `a file you downloaded or built: ${name}`);
  if (/\.(zip|tar|tgz|tar\.gz|tar\.xz|7z|rar|nupkg|gem|crate)$/.test(lower)) {
    return no(`${name} is an archive. Unpack it, then paste the folder it unpacked to.`);
  }
  if (!pathLike(text) && !/[\\/]/.test(text)) {
    return no(`"${text}" is not a file oss-intake reads, or a package with no version. A package is name@1.2.3; `
      + "a file is a lockfile, a package list (.csv), an SBOM (.json), or a JAR, WAR, EAR or program.");
  }
  return no(`${name} is not a kind of file oss-intake reads. It reads lockfiles, package lists (.csv), SBOMs (.json), `
    + "and built files: a JAR, WAR, EAR or program, or a folder of them.");
}

function folderResult(text) {
  if (/^[A-Za-z]:[\\/]?$/.test(text)) return no("a whole drive. Paste the folder or file to check.");
  const name = lastPart(text);
  return ok("artifact", { path: text }, `a folder or program: ${name || text}, scanned as built files. For a `
    + "source checkout, give its lockfile instead");
}

// ---------------------------------------------------------------- links

function fromUrl(url, ctx) {
  const host = url.hostname.toLowerCase().replace(/^www\./, "");
  let parts;
  try { parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent); } catch { return null; }
  if (url.protocol === "file:") {
    if (host && host !== "localhost") return no("a file on another computer. Copy it to this one and paste its path.");
    let p = parts.join("/");
    p = /^[A-Za-z]:$/.test(parts[0] ?? "") ? p : `/${p}`;
    return fileResult(p, ctx) ?? folderResult(p);
  }
  if (host === "github.com") {
    if (parts.length < 2 || GITHUB_RESERVED.has(parts[0].toLowerCase())) {
      return no("a GitHub page that is not a project. Paste the project's own link, such as https://github.com/owner/name.");
    }
    if (parts[2] === "pkgs" && parts[3] === "container") {
      return no(`a container image published on GitHub. Paste it as ghcr.io/${parts[0].toLowerCase()}/${(parts[4] ?? parts[1]).toLowerCase()}:1.2.3, `
        + "with the tag you run.");
    }
    const r = repoResult(parts[0], parts[1], ctx.rules);
    if (parts[2] === "blob" && parts.length > 4) r.says += `. The link is to a file, ${parts.at(-1)}: to check it, download it and paste its name`;
    return r;
  }
  if (host === "npmjs.com" && parts[0] === "package") {
    const scoped = parts[1]?.startsWith("@");
    const name = scoped ? `${parts[1]}/${parts[2] ?? ""}` : parts[1];
    const rest = parts.slice(scoped ? 3 : 2);
    if (!name) return null;
    const version = rest[0] === "v" ? rest[1] : null;
    return version ? packageResult(ctx, "npm", name, version)
      : needVersion("an npm", name, `the link to a version ends in /v/1.2.3, or type npm:${name}@1.2.3`);
  }
  if (host === "pypi.org" && parts[0] === "project" && parts[1]) {
    return parts[2] ? packageResult(ctx, "pypi", parts[1], parts[2])
      : needVersion("a PyPI", parts[1], `the link to a version ends in /${parts[1]}/1.2.3/, or type pypi:${parts[1]}@1.2.3`);
  }
  if (["mvnrepository.com", "central.sonatype.com", "search.maven.org"].includes(host) && parts[0] === "artifact") {
    const [, group, artifact, version] = parts;
    if (!group || !artifact) return null;
    return version && /^\d/.test(version) ? packageResult(ctx, "maven", `${group}:${artifact}`, version)
      : needVersion("a Maven", `${group}:${artifact}`, `type maven:${group}:${artifact}@1.2.3`);
  }
  if (host === "hub.docker.com") {
    let name = null;
    let tag = null;
    if (parts[0] === "_") name = parts[1];
    else if (parts[0] === "r") name = `${parts[1]}/${parts[2]}`;
    else if (parts[0] === "layers") { name = parts[1] === "library" ? parts[2] : `${parts[1]}/${parts[2]}`; tag = parts[3]; }
    if (!name) return null;
    const search = url.searchParams.get("name");
    if (!tag && search) {
      return no(`a Docker Hub tag search for ${name}. Paste the image with the exact tag you run, such as ${name}:${search}.`);
    }
    return tag ? imageResult(`${name}:${tag}`, ctx.rules)
      : no(`a Docker Hub image, ${name}, but with no tag. Add the tag you run, such as ${name}:1.2.3, and paste that: `
        + "an image without a tag changes under you, so it is not checked.");
  }
  if (host === "ghcr.io" || host === "quay.io") {
    const ref = `${host}/${(parts[0] === "repository" ? parts.slice(1) : parts).join("/")}`;
    return /:/.test(parts.at(-1) ?? "") ? imageResult(ref, ctx.rules)
      : no(`a container image, ${ref}, but with no tag. Paste it as ${ref}:1.2.3, with the tag you run.`);
  }
  if (host === "marketplace.visualstudio.com" || host === "open-vsx.org") {
    return no("a VS Code extension. oss-intake cannot check an installed extension yet: find its source on GitHub "
      + "(the extension's page links to it) and check its package-lock.json.");
  }
  if (["chromewebstore.google.com", "chrome.google.com", "addons.mozilla.org", "microsoftedge.microsoft.com"].includes(host)) {
    return no("a browser extension. oss-intake does not check browser extensions.");
  }
  return null;
}

// ---------------------------------------------------------------- commands

/** Words of a command line, with quotes removed. Enough for install and pull commands, not a full shell. */
function words(text) {
  const out = [];
  for (const m of text.matchAll(/(?:"[^"]*"|'[^']*'|[^\s"'])+/g)) {
    const w = m[0];
    // The command ends at a shell operator: what follows is another command.
    if (/^(&&|\|\||[;|&]|\d?>.*|<.*)$/.test(w)) break;
    out.push(w.replace(/"([^"]*)"|'([^']*)'/g, "$1$2"));
  }
  return out;
}

const DOCKER_VALUE_FLAGS = new Set(["-p", "-e", "-v", "-w", "-u", "-l", "-h", "-m", "--publish", "--env", "--volume",
  "--name", "--network", "--net", "--workdir", "--entrypoint", "--platform", "--user", "--mount", "--label",
  "--hostname", "--add-host", "--env-file", "--cpus", "--memory", "--link", "--security-opt", "--restart",
  "--log-opt", "--log-driver", "--cap-add", "--cap-drop", "--device", "--tmpfs", "--dns", "--ulimit", "--ip",
  "--gpus", "--pid", "--ipc", "--expose", "--shm-size", "--cidfile", "--stop-signal", "--runtime", "--pull",
  "--cpu-shares", "--memory-swap", "--group-add", "--health-cmd", "--volumes-from", "--uts", "--userns", "-c", "-a",
  "--attach", "--cpuset-cpus", "--cpuset-mems", "--memory-reservation", "--stop-timeout", "--sysctl", "--annotation",
  "--health-interval", "--health-timeout", "--health-retries", "--health-start-period", "--kernel-memory",
  "--blkio-weight", "--oom-score-adj", "--isolation", "--cgroup-parent", "--cgroupns", "--mac-address", "--ip6",
  "--network-alias", "--dns-search", "--dns-option", "--label-file", "--env", "--detach-keys", "--storage-opt",
  "--device-cgroup-rule", "--pids-limit", "--cpu-period", "--cpu-quota", "--cpus", "--log-opt"]);
const NPM_VALUE_FLAGS = new Set(["--registry", "--prefix", "--tag", "-w", "--workspace", "--cache", "--userconfig",
  "--omit", "--include", "--install-strategy"]);
const PIP_VALUE_FLAGS = new Set(["-i", "--index-url", "--extra-index-url", "-c", "--constraint", "-t", "--target",
  "--platform", "--python-version", "--implementation", "--abi", "--root", "--prefix", "-f", "--find-links",
  "--trusted-host", "--cache-dir", "--src", "--proxy", "--timeout", "--retries"]);

/** The arguments that are not flags (or flag values). */
function operands(ws, valueFlags) {
  const out = [];
  for (let i = 0; i < ws.length; i += 1) {
    const w = ws[i];
    if (w.startsWith("-")) {
      if (!w.includes("=") && valueFlags.has(w)) i += 1;
      continue;
    }
    out.push(w);
  }
  return out;
}

const PRIVATE_NOTE = ". The command names its own registry: this checks the public package of that name, which "
  + "may not be the one it installs";

function withNote(result, ws, flags) {
  if (result.status === "ok" && ws.some((w) => flags.some((f) => w === f || w.startsWith(`${f}=`)))) result.says += PRIVATE_NOTE;
  return result;
}

function npmSpec(ctx, spec) {
  if (/^(\.|\/|~|file:|git|github:|https?:)/.test(spec) || spec.includes("@npm:")) {
    return no(`${spec} is a local, git or aliased package: check the project's package-lock.json instead.`);
  }
  const at = spec.lastIndexOf("@");
  if (at <= 0) return needVersion("an npm", spec, `type ${spec}@1.2.3`);
  return packageResult(ctx, "npm", spec.slice(0, at), spec.slice(at + 1));
}

function pipSpec(ctx, spec) {
  if (/\.(whl|tar\.gz|zip)$/i.test(spec)) {
    return no(`${spec} is a downloaded package file. Check the package by name instead, such as pypi:name@1.2.3.`);
  }
  if (/^(\.|\/|~|git\+|https?:|file:)/.test(spec)) {
    return no(`${spec} is a local or git package: check the project's requirements.txt or lockfile instead.`);
  }
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(===?)([^\s;]+)$/.exec(spec);
  if (m) return packageResult(ctx, "pypi", m[1], m[3]);
  const name = spec.split(/[<>=!~[;]/)[0];
  return needVersion("a PyPI", name, `pin it, such as ${name}==1.2.3`);
}

function fromCommand(text, ctx) {
  const ws = words(text);
  const head = ws.map((w) => w.toLowerCase());
  if (["npm", "pnpm", "yarn"].includes(head[0])) {
    const everything = no("this installs everything in package-lock.json: paste that file's name to check it.");
    if (head[1] === "ci") return everything;
    if (!["install", "i", "add"].includes(head[1])) return null;
    const specs = operands(ws.slice(2), NPM_VALUE_FLAGS);
    return specs.length ? withNote(packagesResult(specs.map((s) => npmSpec(ctx, s))), ws, ["--registry"]) : everything;
  }
  let rest = null;
  if (/^pip3?$/.test(head[0]) || head[0] === "pipx") rest = head[1] === "install" ? ws.slice(2) : null;
  else if (/^(python3?|py)$/.test(head[0]) && head[1] === "-m" && head[2] === "pip" && head[3] === "install") rest = ws.slice(4);
  else if (head[0] === "uv" && head[1] === "pip" && head[2] === "install") rest = ws.slice(3);
  else if (head[0] === "uv" && head[1] === "add") rest = ws.slice(2);
  if (rest) {
    const r = rest.findIndex((w) => w === "-r" || w === "--requirement");
    if (r >= 0 && rest[r + 1]) {
      const file = rest[r + 1];
      if (/^[a-z]+:\/\//i.test(file)) return no(`${file} is a link. Download the file and paste its name.`);
      const named = fileResult(file, ctx);
      if (named?.status === "ok" && named.what === "lockfile") return named;
      const base = lastPart(file).replace(/\.[^.]*$/, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "app";
      return no(`${file}: oss-intake reads a pip requirements file by its name, requirements*.txt. Copy it to a name `
        + `such as requirements-${base}.txt and paste that.`);
    }
    if (rest.includes("-e") || rest.includes("--editable")) return no("this installs a local project: check its requirements.txt or lockfile instead.");
    const specs = operands(rest, PIP_VALUE_FLAGS);
    return specs.length ? withNote(packagesResult(specs.map((s) => pipSpec(ctx, s))), rest, ["-i", "--index-url",
      "--extra-index-url"]) : null;
  }
  if (head[0] === "git" && head[1] === "clone") {
    const target = operands(ws.slice(2), new Set(["-b", "--branch", "--depth", "-o", "--origin", "-c", "--config"]))[0];
    return target ? fromRepoText(target, ctx) : null;
  }
  if (["docker", "podman", "nerdctl"].includes(head[0])) {
    const i = ["image", "container"].includes(head[1]) ? 2 : 1;
    if (!["pull", "run", "create"].includes(head[i])) return null;
    // The image is the first word after the flags; what follows it is the container's own command.
    const image = operands(ws.slice(i + 1), DOCKER_VALUE_FLAGS)[0];
    if (!image) return null;
    if (!/:[^/]*$|@/.test(image)) {
      return no(`a docker command for ${image}, with no tag. Add the tag you run, such as ${image.toLowerCase()}:1.2.3: an `
        + "image without a tag changes under you, so it is not checked.");
    }
    return imageResult(image, ctx.rules);
  }
  return null;
}

/** A git address: https://github.com/o/n(.git), git@github.com:o/n.git, or o/n.git. */
function fromRepoText(text, ctx) {
  const ssh = /^(?:ssh:\/\/)?git@github\.com[:/]([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(text);
  if (ssh) return repoResult(ssh[1], ssh[2], ctx.rules);
  if (/^https?:\/\//i.test(text)) {
    try { return fromUrl(new URL(text), ctx); } catch { return null; }
  }
  const short = /^([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9_.-]+)\.git$/.exec(text);
  return short ? repoResult(short[1], short[2], ctx.rules) : null;
}

// ---------------------------------------------------------------- everything else

/** What was pasted, as one detect() result. */
export function detect(raw, ctx) {
  let text = String(raw ?? "").slice(0, MAX).trim();
  if (!text) return { status: "unknown", says: "" };
  if (/[\u0000-\u001f\u007f]/.test(text)) return { status: "unknown", says: "Paste one thing at a time: a link, a package, an image or a file name." };
  // A copied prompt ($, >, PS C:\...>) and sudo are not part of the command; nor are quotes around it all.
  text = text.replace(/^(PS [^>]{0,200}>\s*|[$>#%]\s+)/, "").replace(/^sudo\s+/, "").trim();
  if (/^(["'`]).*\1$/.test(text)) text = text.slice(1, -1).trim();
  // The home folder written as a variable: the command quotes the path, so use ~, which it writes so it works.
  text = text.replace(/^(\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%)[\\/]/i, "~/");
  if (/^(npm|pnpm|yarn|pip3?|pipx|python3?|py|uv|docker|podman|nerdctl|git)\s/i.test(text)) {
    return fromCommand(text, ctx) ?? { status: "unknown", says: "This command was not recognised. Paste an npm "
      + "install, pip install or docker pull command, or what it installs." };
  }
  if (/^(ssh:\/\/)?git@/i.test(text) || /^[^\s/]+\/[^\s/]+\.git$/.test(text)) {
    const r = fromRepoText(text, ctx);
    if (r) return r;
  }
  if (/^(https?|file):\/\//i.test(text)) {
    let url;
    try { url = new URL(text); } catch { return { status: "unknown", says: "That link could not be read." }; }
    return fromUrl(url, ctx) ?? { status: "unknown", says: `a link to ${url.hostname}, which this page does not `
      + "recognise. Paste a GitHub, npm, PyPI, Maven or Docker Hub link, or choose below." };
  }
  if (/^[0-9a-f]{40}$/i.test(text)) return no("this looks like a git commit. Paste the project's GitHub link, or its lockfile's name.");
  if (/^pkg:/i.test(text)) {
    const m = /^pkg:([A-Za-z][A-Za-z0-9.+-]*)\/((?:@[^@?#/]+\/)?[^@?#]+)(?:@([^@?#]+))?(?:[?#].*)?$/.exec(text);
    if (!m) return no("this purl could not be read: it is pkg:type/name@version.");
    const type = m[1].toLowerCase();
    const types = [...new Set(Object.values(ctx.wiz.ecosystems))].sort();
    if (!types.includes(type)) return no(`purl type "${type}" is not one oss-intake checks: ${types.join(", ")}.`);
    if (!m[3]) return needVersion(LABELS[type] ?? "a", text, "add @1.2.3 to the purl");
    const name = decoded(m[2]);
    const problem = packageProblem(ctx, type, type === "maven" ? name.replace("/", ":") : name, m[3]);
    if (problem) return no(`${LABELS[type] ?? `a ${type}`} package, but ${problem}.`);
    return ok("package", { package: [text] }, `${LABELS[type] ?? `a ${type}`} package: ${name} ${decoded(m[3])}`);
  }
  // npm:chalk is a package with no version, or an image such as node:lts: ask, unless the tag is a number.
  const noVersion = /^(\.?[A-Za-z][A-Za-z0-9.-]*):([^\s@:/\\]+)$/.exec(text);
  if (noVersion && Object.hasOwn(ctx.wiz.ecosystems, noVersion[1].toLowerCase()) && !/^v?\d/.test(noVersion[2])) {
    const pkg = needVersion(LABELS[ctx.wiz.ecosystems[noVersion[1].toLowerCase()]] ?? "a", noVersion[2], `type ${text}@1.2.3`);
    return { status: "ask", says: `Is ${text} a container image or a package?`,
      choices: [{ ...imageResult(text, ctx.rules), label: "A container image" }, { ...pkg, label: "A package" }] };
  }
  // ecosystem:name@version (not a Windows path such as R:\Builds\x@1)
  const eco = /^(\.?[A-Za-z][A-Za-z0-9.-]*):([^\\\s]+)@([^@\s]+)$/.exec(text);
  if (eco && Object.hasOwn(ctx.wiz.ecosystems, eco[1].toLowerCase()) && !/^[\\/]/.test(eco[2])) {
    const e = eco[1].toLowerCase();
    return packageResult(ctx, e, eco[2], ctx.wiz.ecosystems[e] === "golang" ? eco[3].replace(/^(?=\d)/, "v") : eco[3]);
  }
  const gradle = /^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):(\d[^:\s]*)$/.exec(text);
  if (gradle) return packageResult(ctx, "maven", `${gradle[1]}:${gradle[2]}`, gradle[3]);
  const pip = /^([A-Za-z0-9][A-Za-z0-9._-]*)===?([^\s;]+)$/.exec(text);
  if (pip) return packageResult(ctx, "pypi", pip[1], pip[2]);
  const go = /^([a-z0-9-]+(?:\.[a-z0-9-]+)+\/[^\s@]+)@(v?\d[^\s@]*)$/i.exec(text);
  // Go module versions start with v (go.mod writes v1.2.3); add it when it was left off.
  if (go) return packageResult(ctx, "golang", go[1], go[2].replace(/^(?=\d)/, "v"));
  const bare = /^(@?[A-Za-z0-9][A-Za-z0-9._/-]*)@(v?\d[^\s@]*)$/.exec(text);
  if (bare && !pathLike(text)) {
    // Only npm names start with @scope/. A Maven name is group:artifact, so a bare name is never Maven.
    if (/^@[^/]+\/./.test(bare[1])) return packageResult(ctx, "npm", bare[1], bare[2]);
    const choices = ASK_ECOSYSTEMS.map(([id, label]) => ({ ...packageResult(ctx, id, bare[1], bare[2]), label }));
    if (choices.every((c) => c.status !== "ok")) return { status: "no", says: choices[0].says };
    return { status: "ask", says: `Which kind of package is ${bare[1]} ${bare[2]}?`, choices };
  }
  // A file with an extension that names it (a lockfile, a package list, an SBOM, a manifest) wins over the rest.
  const named = hasExtension(lastPart(text)) || MANIFESTS[lastPart(text)] ? fileResult(text, ctx) : null;
  if (named && (named.status !== "ok" || named.what !== "artifact")) return named;
  const ghShort = /^(?:github\.com\/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9_-][A-Za-z0-9._-]{0,99})$/.exec(text);
  if (ghShort && !pathLike(text) && !named) {
    return { status: "ask", says: `Is ${text} a GitHub project or a container image?`,
      choices: [{ ...repoResult(ghShort[1], ghShort[2], ctx.rules), label: "A GitHub project" }, { status: "no", label: "A container image",
        says: `A container image needs its tag, such as ${text.toLowerCase()}:1.2.3. Paste it with the tag you run.` }] };
  }
  if (!/\s/.test(text) && !pathLike(text) && (/:[^/\\]*$/.test(text) || /@sha256:/.test(text)) && !named) {
    return imageResult(text, ctx.rules);
  }
  if (named) return named;
  if (pathLike(text)) return folderResult(text);
  if (/^([a-z0-9-]+\.[a-z0-9.-]+|localhost)(:\d+)?\/[a-z0-9._/-]+$/i.test(text)) {
    return no(`a container image, ${text}, but with no tag. Paste it as ${text.toLowerCase()}:1.2.3, with the tag you run.`);
  }
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(text)) {
    return no(`"${text}" has no version or tag. Add the one you use: a package as ${text}@1.2.3, or an image as `
      + `${text.toLowerCase()}:1.2.3.`);
  }
  return { status: "unknown", says: "This was not recognised. Choose what you are checking below." };
}
