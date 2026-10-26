#!/usr/bin/env python3
"""Write third-party notices for the Rust crates compiled into an artifact.

The crate set comes from `cargo tree` (normal edges, proc-macros excluded),
which applies Cargo's real feature resolver per target, so build-only and
feature-gated crates that never reach the binary stay out. Package details
(license expression, authors, repository, source directory) come from
`cargo metadata`. For every crate the script collects the license and notice
files the crate publishes (LICENSE*, LICENCE*, COPYING*, UNLICENSE*, NOTICE*,
COPYRIGHT*, LICENSES/ directories, also nested ones such as vendored C code)
and writes them verbatim, sorted by crate name and version.

It fails (exit 1) when a crate has no license text, when its license files
do not cover its declared SPDX expression, when a crate under a copyleft
license (MPL, LGPL, GPL, EPL, ...) has no Source Code Form pointer, when a
crate's license binds the whole binary (GPL, LGPL, AGPL, ...) and no override
records the follow-up, or when a path dependency outside the workspace is not
accounted for. Gaps are fixed with explicit entries in an overrides file
(JSON, every entry needs a "reason"), never by silent omission. It warns about
file-level copyleft (MPL, EPL, ...) in the binary, copyright placeholders left
in license files, and overrides that may have become unnecessary.

Optionally it copies the Rust standard library notices that the toolchain
ships (share/doc/rust/COPYRIGHT-library.html) and renders them as text.

Python 3.8+ standard library only; needs `cargo` (and `rustc` for
--rust-std/--target host) on PATH or in $CARGO/$RUSTC.

Examples:
  rust-notices.py --manifest-path src-tauri/Cargo.toml --target aarch64-apple-darwin \\
      --title MyApp --overrides licenses/rust-overrides.json \\
      --out src-tauri/licenses/Third-Party-Notices.txt \\
      --rust-std src-tauri/licenses/Rust-Licenses.html
  rust-notices.py -p mydaemon -p mycli --target aarch64-apple-darwin --own-license MIT --check
  rust-notices.py --rust-std Rust-Licenses.html          # standard library only
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html.parser
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

RULE = "=" * 72
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
CRATES_IO_SPARSE = "sparse+https://index.crates.io/"

# File names that hold license texts, and ones that hold notices/attributions.
LICENSE_NAME = re.compile(r"^(?:.*[-_.])?(?:licen[cs]es?|copying|unlicense)(?:[-_.0-9].*)?$", re.I)
NOTICE_NAME = re.compile(r"^(?:notice|copyright|copyrights|third[-_]?party[-_]?notices?)(?:[-_.].*)?$", re.I)
LICENSE_DIRS = {"licenses", "license", "licences", "licence"}  # compared in lower case
# Never treat code or data files as license texts, even when named license.rs.
CODE_SUFFIXES = {
    ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".js", ".ts", ".go", ".java",
    ".toml", ".json", ".yml", ".yaml", ".sh", ".ps1", ".bat", ".s", ".asm", ".pl",
    ".png", ".svg", ".jpg", ".gif", ".ico", ".bin", ".o", ".a", ".lib", ".so",
    ".dylib", ".dll", ".wasm", ".lock", ".orig", ".tmpl", ".hbs", ".in", ".cmake",
}
# Nested directories that never ship in the binary.
SKIP_DIRS = {
    ".git", ".github", "target", "node_modules", "tests", "test", "testdata",
    "test-data", "test_data", "fixtures", "examples", "example", "benches",
    "bench", "fuzz", "ci", ".cargo",
}
MAX_DEPTH = 6

# License families whose texts we can recognise. Each needs a phrase from the
# license body, so a "Licensed under the Apache License, Version 2.0" header or
# an MPL Exhibit A notice is not mistaken for the license text itself, and a
# license that merely names another (MPL-2.0 names the GNU licenses, GPL-3.0
# names the LGPL and AGPL) is not counted as that one too.
SIGNATURES = [
    ("Apache-2.0", [r"apache license", r"version 2\.0", r"grant of copyright license"]),
    ("MPL-2.0", [r"mozilla public license,? (?:version|v\.?) ?2\.0", r"covered software", r"executable form"]),
    ("LGPL", [r"this license, the (?:lesser|library) general public license, applies to some specially designated|"
              r"this version of the gnu lesser general public license incorporates the terms"]),
    ("AGPL", [r"affero general public license is (?:a free, copyleft license for software|intended to guarantee)"]),
    ("GPL", [r"(?<!affero )(?<!lesser )(?<!library )general public license is "
             r"(?:a free, copyleft license for software|intended to guarantee)"]),
    ("EPL", [r"eclipse public license", r"grant of rights"]),
    ("CDLA-Permissive", [r"community data license agreement", r"data provider"]),
    ("Unicode", [r"unicode,? inc|unicode license|unicode data files",
                 r"permission is hereby granted,? free of charge,? to any person obtaining a copy"]),
    ("BSL-1.0", [r"boost software license", r"permission is hereby granted,? free of charge,? to any person or organization"]),
    ("CC0-1.0", [r"cc0 1\.0|creative commons legal code"]),
    ("Unlicense", [r"this is free and unencumbered software released into the public domain"]),
    ("WTFPL", [r"do what the fuck you want"]),
    ("Zlib", [r"provided ['‘]?as-is['’]?", r"altered source versions must be plainly marked"]),
    ("BSD", [r"redistribution and use in source and binary forms"]),
    ("ISC", [r"permission to use, copy, modify,? and(?:/or)? distribute this software for any purpose"]),
    ("MIT", [r"permission is hereby granted,? free of charge", r"to deal in the software without restriction"]),
    ("NCSA", [r"university of illinois/ncsa", r"with the software without restriction"]),
    ("OpenSSL", [r"openssl license|openssl project", r"redistribution and use in source and binary forms"]),
    ("OFL", [r"sil open font license", r"reserved font name"]),
]
# SPDX identifier prefix -> family above.
FAMILY_OF = [
    ("Apache-", "Apache-2.0"), ("MPL-", "MPL-2.0"), ("LGPL-", "LGPL"), ("AGPL-", "AGPL"),
    ("GPL-", "GPL"), ("EPL-", "EPL"), ("CDLA-Permissive", "CDLA-Permissive"),
    ("Unicode-", "Unicode"), ("BSL-", "BSL-1.0"), ("CC0-", "CC0-1.0"), ("Unlicense", "Unlicense"),
    ("WTFPL", "WTFPL"), ("Zlib", "Zlib"), ("BSD-", "BSD"), ("0BSD", "ISC"), ("ISC", "ISC"),
    ("MIT", "MIT"), ("NCSA", "NCSA"), ("OpenSSL", "OpenSSL"), ("OFL-", "OFL"),
]
# Licenses whose Executable Form needs a pointer to the Source Code Form.
COPYLEFT = re.compile(r"^(?:MPL|LGPL|GPL|AGPL|EPL|CDDL|EUPL|OSL|CPL|MS-RL|CC-BY-SA|APSL|SSPL|GFDL|QPL|RPL|"
                      r"CECILL|LiLiQ-R|CPAL|NPL|ErlPL|Sleepycat|Watcom)(?:-|$)", re.I)
# Copyleft whose terms reach the whole statically linked binary (GPL: the combined
# work; LGPL: relinking or source duties), beyond what a notices file can meet.
STRONG_COPYLEFT = re.compile(r"^(?:GPL|AGPL|LGPL|EUPL|OSL|SSPL|QPL|RPL|Sleepycat|CECILL-[12])(?:-|$)", re.I)
# Licenses whose text must carry the copyright line (template placeholders are not enough).
NEEDS_COPYRIGHT = {"MIT", "BSD", "ISC", "Zlib"}
PLACEHOLDER = re.compile(r"<\s*(?:year|owner|copyright holders?|name of author|organization)\s*>|"
                         r"\[\s*(?:year|yyyy|fullname|name of copyright owner)\s*\]|\{\s*(?:year|yyyy)\s*\}", re.I)
# A copyright statement, not "the above copyright notice" or "COPYRIGHT HOLDERS AND CONTRIBUTORS".
REAL_COPYRIGHT = re.compile(r"^[\s#*/;>-]*(?:copyright\b|\(c\)|©)"
                            r"(?!\s+(?:notice|holders?|owners?|and|law|statement|license|permission)\b)", re.I)

OVERRIDE_KEYS = {"name", "version", "reason", "files", "spdx", "copyright", "note",
                 "source_url", "license", "skip", "accept", "accept_copyleft", "exclude_files"}
EXTRA_KEYS = {"name", "version", "reason", "files", "spdx", "copyright", "note",
              "source_url", "license", "repository", "targets"}


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, encoding="utf-8")
    if result.returncode != 0:
        fail(f"{' '.join(command)} failed:\n{result.stderr.strip()}")
    return result.stdout


def read_text(path):
    data = path.read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip("\n") + "\n"


# ---------------------------------------------------------------------------
# SPDX expressions
# ---------------------------------------------------------------------------

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:-]*$")


def tokens(expression):
    expression = expression.replace("/", " OR ")  # deprecated "MIT/Apache-2.0" form
    return re.findall(r"\(|\)|[^\s()]+", expression)


def parse(expression):
    """Parse an SPDX expression into nested ('OR'|'AND', [...]) / identifier tuples."""
    items = tokens(expression)
    position = 0

    def peek():
        return items[position] if position < len(items) else None

    def take():
        nonlocal position
        position += 1
        return items[position - 1]

    def identifier():
        token = take()
        if token.upper() in ("AND", "OR", "WITH") or not IDENTIFIER.match(token):
            raise ValueError(expression)
        return token

    def primary():
        if peek() == "(":
            take()
            node = disjunction()
            if take() != ")":
                raise ValueError(expression)
            return node
        token = identifier()
        if peek() == "WITH":
            take()
            identifier()  # the exception does not change which text is needed
        return token.rstrip("+")

    def conjunction():
        nodes = [primary()]
        while peek() in ("AND", "and"):
            take()
            nodes.append(primary())
        return nodes[0] if len(nodes) == 1 else ("AND", nodes)

    def disjunction():
        nodes = [conjunction()]
        while peek() in ("OR", "or"):
            take()
            nodes.append(conjunction())
        return nodes[0] if len(nodes) == 1 else ("OR", nodes)

    node = disjunction()
    if position != len(items):
        raise ValueError(expression)
    return node


def identifiers(node):
    if isinstance(node, str):
        return [node]
    return [identifier for child in node[1] for identifier in identifiers(child)]


def family(identifier):
    for prefix, name in FAMILY_OF:
        if identifier.startswith(prefix):
            return name
    return None


def unknown_needed(node, families):
    """Unknown identifiers that the cheapest way of meeting the expression needs.

    Returns None when a known family's text is missing. Identifiers outside the
    known families (LicenseRef-*, CC-BY-4.0, curl, ...) each need their own
    license file that matched no known family."""
    if isinstance(node, str):
        name = family(node)
        if name is None:
            return frozenset([node])
        # LGPL-3.0 is GPL-3.0 plus additional permissions: it requires both texts (LGPL-3.0 sections 3b, 4b).
        needed = {"LGPL", "GPL"} if node.upper().startswith("LGPL-3") else {name}
        return frozenset() if needed <= families else None
    options = [unknown_needed(child, families) for child in node[1]]
    if node[0] == "OR":
        options = [option for option in options if option is not None]
        return min(options, key=lambda option: (len(option), sorted(option))) if options else None
    if any(option is None for option in options):
        return None
    return frozenset().union(*options)


def satisfied(node, families, unclassified):
    """True if the detected text families (plus `unclassified` unrecognised texts) cover the expression."""
    needed = unknown_needed(node, families)
    return needed is not None and len(needed) <= unclassified


def unavoidable_copyleft(node, pattern=COPYLEFT):
    """True if every way of meeting the expression includes a license matching pattern."""
    if isinstance(node, str):
        return bool(pattern.match(node))
    results = [unavoidable_copyleft(child, pattern) for child in node[1]]
    return all(results) if node[0] == "OR" else any(results)


OTHER = "other (unrecognised text)"
COMMENT_PREFIX = re.compile(r"^\s*(?:/\*+|\*+/?|//+|#+|;+|--)[ \t]?")


def detect(text):
    """License families whose characteristic phrases appear in a text (comment markers ignored)."""
    uncommented = "\n".join(COMMENT_PREFIX.sub("", line) for line in text.splitlines())
    lowered = " ".join(uncommented.lower().split())
    found = set()
    for name, phrases in SIGNATURES:
        if all(re.search(phrase, lowered) for phrase in phrases):
            found.add(name)
    return found


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

def cargo_flags(args):
    flags = [] if args.no_locked else ["--locked"]
    for spelling in ("offline", "frozen"):
        if getattr(args, spelling):
            flags.append(f"--{spelling}")
    if args.features:
        flags += ["--features", ",".join(args.features)]
    if args.all_features:
        flags.append("--all-features")
    if args.no_default_features:
        flags.append("--no-default-features")
    return flags


def host_triple(cargo_dir, rustc):
    for line in run([rustc, "-vV"], cwd=cargo_dir).splitlines():
        if line.startswith("host: "):
            return line[len("host: "):].strip()
    fail("rustc -vV printed no host triple")


def resolve_targets(args, cargo_dir):
    requested = list(args.target)
    if not requested and os.environ.get("TAURI_ENV_TARGET_TRIPLE"):
        requested = [os.environ["TAURI_ENV_TARGET_TRIPLE"]]
    if not requested:
        fail("pass --target <triple> (or 'host') for every target the artifact ships")
    targets = []
    for target in requested:
        if target == "host":
            target = host_triple(cargo_dir, args.rustc)
        if target == "universal-apple-darwin":  # Tauri's universal macOS build
            targets += ["aarch64-apple-darwin", "x86_64-apple-darwin"]
        else:
            targets.append(target)
    return sorted(set(targets))


TREE_LINE = re.compile(r"^(\S+) v(\S+)(.*)$")


def crate_set(args, targets):
    """(name, version, source-hint) triples that cargo tree reports for the targets."""
    edges = "normal" if args.include_proc_macros else "normal,no-proc-macro"
    if args.include_build_deps:
        edges += ",build"
    found = set()
    for target in targets:
        command = [args.cargo, "tree", "--manifest-path", str(args.manifest_path), "--target", target,
                   "-e", edges, "--prefix", "none", "--format", "{p}", "--color", "never"]
        command += cargo_flags(args)
        for package in args.package:
            command += ["-p", package]
        for line in run(command).splitlines():
            match = TREE_LINE.match(line.strip())
            if not match:
                continue
            rest = match.group(3).replace("(*)", "").replace("(proc-macro)", "").strip()
            found.add((match.group(1), match.group(2), rest.strip("()")))
    return found


def metadata(args, targets):
    packages, workspace_members, nodes = {}, set(), {}
    for target in targets:
        command = [args.cargo, "metadata", "--format-version", "1", "--manifest-path",
                   str(args.manifest_path), "--filter-platform", target] + cargo_flags(args)
        document = json.loads(run(command))
        for package in document["packages"]:
            packages[package["id"]] = package
        workspace_members.update(document["workspace_members"])
        for node in document["resolve"]["nodes"]:
            merged = nodes.setdefault(node["id"], {"deps": []})
            known = {dependency["pkg"] for dependency in merged["deps"]}
            merged["deps"] += [dependency for dependency in node["deps"] if dependency["pkg"] not in known]
    return packages, workspace_members, nodes


def match_packages(found, packages):
    by_name_version = {}
    for package in packages.values():
        by_name_version.setdefault((package["name"], package["version"]), []).append(package)
    selected = {}
    for name, version, hint in sorted(found):
        candidates = by_name_version.get((name, version), [])
        if not candidates:
            fail(f"cargo tree listed {name} {version}, which cargo metadata does not know")
        if len(candidates) > 1:
            # cargo tree prints no source for crates.io packages, the URL for git
            # ones and the directory for path ones.
            if hint:
                candidates = [p for p in candidates if hint in (p["source"] or "") or
                              hint == str(Path(p["manifest_path"]).parent)]
            else:
                candidates = [p for p in candidates if p["source"] in (CRATES_IO, CRATES_IO_SPARSE)]
            if len(candidates) != 1:
                fail(f"cannot tell which {name} {version} cargo tree means ({hint or 'crates.io'}); "
                     f"candidates: {', '.join(sorted(p['id'] for p in by_name_version[(name, version)]))}")
        selected[candidates[0]["id"]] = candidates[0]
    return selected


def add_vendored_source_build_deps(selected, packages, nodes):
    """Build-dependencies named *-src compile vendored C code into the binary (openssl-src)."""
    for package_id in list(selected):
        for dependency in nodes.get(package_id, {}).get("deps", []):
            kinds = {kind["kind"] for kind in dependency["dep_kinds"]}
            target = packages.get(dependency["pkg"])
            if "build" in kinds and target and target["name"].endswith("-src"):
                selected[target["id"]] = target


# ---------------------------------------------------------------------------
# License files
# ---------------------------------------------------------------------------

def plausible_text_file(path):
    # Dotfiles (.license_template for rustfmt) and code/data files are never notices.
    return not path.name.startswith(".") and path.suffix.lower() not in CODE_SUFFIXES


def is_license_file(path):
    return plausible_text_file(path) and bool(LICENSE_NAME.match(path.name))


def is_notice_file(path):
    return plausible_text_file(path) and bool(NOTICE_NAME.match(path.name))


def scan(directory, depth=0, in_license_dir=False):
    """Yield (path, kind) for license and notice files under a crate directory."""
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.is_symlink() and not entry.exists():
            continue
        if entry.is_dir():
            if depth >= MAX_DEPTH or entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            yield from scan(entry, depth + 1, in_license_dir or entry.name.lower() in LICENSE_DIRS)
        elif entry.is_file():
            if in_license_dir and plausible_text_file(entry):
                yield entry, "license"
            elif is_license_file(entry):
                yield entry, "license"
            elif is_notice_file(entry):
                yield entry, "notice"


def git_checkout_root(path):
    parts = path.parts
    if "checkouts" in parts:
        index = parts.index("checkouts")
        return Path(*parts[: index + 3])  # .../git/checkouts/<repo>-<hash>/<rev>
    return None


def collect_files(package):
    root = Path(package["manifest_path"]).parent
    files = {}
    if package.get("license_file"):
        license_file = (root / package["license_file"]).resolve()
        if license_file.is_file():
            files[license_file] = "license"
    for path, kind in scan(root):
        files.setdefault(path.resolve(), kind)
    # Git dependencies inside a workspace often keep the license at the repository root.
    checkout = git_checkout_root(root) if (package["source"] or "").startswith("git+") else None
    if checkout and not any(kind == "license" for kind in files.values()):
        directory = root
        while directory != checkout and checkout in directory.parents:
            directory = directory.parent
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                break
            for path in entries:
                if path.is_file() and (is_license_file(path) or is_notice_file(path)):
                    files[path.resolve()] = "license" if is_license_file(path) else "notice"
            if any(kind == "license" for kind in files.values()):
                break
    return root, files


def display_path(path, root):
    try:
        return path.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name + " (from the repository root)"


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------

def as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def load_overrides(path):
    if not path:
        return {"crates": [], "extra": []}, None, None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"cannot read overrides {path}: {error}")
    if not isinstance(document, dict):
        fail(f"{path}: the top level must be an object")
    unknown = set(document) - {"comment", "spdx_dir", "crates", "extra"}
    if unknown:
        fail(f"{path}: unknown top-level keys {sorted(unknown)}")
    if not isinstance(document.get("spdx_dir", "spdx"), str):
        fail(f"{path}: spdx_dir must be a string")
    base = path.parent
    spdx_dir = base / document.get("spdx_dir", "spdx")
    for section, allowed in (("crates", OVERRIDE_KEYS), ("extra", EXTRA_KEYS)):
        entries = document.get(section, [])
        if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
            fail(f"{path}: {section} must be a list of objects")
        for entry in entries:
            label = f"{path}: {section} entry {entry.get('name')!r}"
            if not entry.get("name") or not str(entry.get("reason", "")).strip():
                fail(f"{label} needs a name and a non-empty reason")
            unknown = set(entry) - allowed
            if unknown:
                fail(f"{label} has unknown keys {sorted(unknown)}")
            for key, value in entry.items():
                if key in ("skip", "accept", "accept_copyleft"):
                    valid = isinstance(value, bool)
                elif key in ("spdx", "files", "copyright", "targets", "exclude_files"):
                    valid = isinstance(value, str) or (isinstance(value, list) and
                                                       all(isinstance(item, str) for item in value))
                else:
                    valid = isinstance(value, str)
                if not valid:
                    fail(f"{label}: {key} has the wrong type ({type(value).__name__})")
    document.setdefault("crates", [])
    document.setdefault("extra", [])
    return document, base, spdx_dir


def override_for(overrides, package):
    matches = [entry for entry in overrides["crates"] if fnmatch.fnmatchcase(package["name"], entry["name"])
               and fnmatch.fnmatchcase(package["version"], entry.get("version", "*"))]
    if len(matches) > 1:
        fail(f"several overrides match {package['name']} {package['version']}")
    if matches:
        matches[0]["_used"] = True
        return matches[0]
    return {}


def spdx_text(identifier, copyright_lines, spdx_dir):
    path = spdx_dir / f"{identifier}.txt"
    if not path.is_file():
        fail(f"canonical text {path} is missing; fetch it with fetch-spdx-texts.py {identifier}")
    text = read_text(path)
    lines = text.split("\n")
    if not copyright_lines:
        if family(identifier) in NEEDS_COPYRIGHT and any(
                PLACEHOLDER.search(line) and "copyright" in line.lower() for line in lines):
            fail(f"canonical {identifier} text has a copyright placeholder; give the override a 'copyright'")
        return text
    for index, line in enumerate(lines):
        if PLACEHOLDER.search(line) and "copyright" in line.lower():
            lines[index:index + 1] = copyright_lines
            return "\n".join(lines)
    return "\n".join(copyright_lines) + "\n\n" + text


def override_texts(entry, base, spdx_dir):
    texts = []
    copyright_lines = as_list(entry.get("copyright"))
    for identifier in as_list(entry.get("spdx")):
        texts.append((f"{identifier} (canonical SPDX text, supplied by override)", "license",
                      spdx_text(identifier, copyright_lines, spdx_dir)))
    for relative in as_list(entry.get("files")):
        path = (base / relative).resolve()
        if not path.is_file() or not path.stat().st_size:
            fail(f"override file {path} for {entry['name']} is missing or empty")
        texts.append((f"{path.name} (supplied by override)", "license", read_text(path)))
    return texts


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

def source_lines(package, override):
    """Source URL and, for copyleft crates, the Source Code Form pointer."""
    name, version, source = package["name"], package["version"], package["source"] or ""
    lines, form = [], None
    if source in (CRATES_IO, CRATES_IO_SPARSE):
        lines.append(f"Source: https://crates.io/crates/{name}/{version}")
        form = (f"https://static.crates.io/crates/{name}/{name}-{version}.crate "
                f"(unmodified crates.io release)")
    elif source.startswith("git+"):
        url, _, commit = source[len("git+"):].partition("#")
        url = url.split("?", 1)[0]
        lines.append(f"Source: {url} (git, commit {commit})")
        form = f"{url} at commit {commit}"
    elif source:
        lines.append(f"Source: {source}")
    if override.get("source_url"):
        form = override["source_url"]
        lines.append(f"Source: {form}")
    if package.get("repository"):
        lines.append(f"Repository: {package['repository']}")
    return lines, form


def build_entry(package, override, base, spdx_dir, problems, warnings):
    name, version = package["name"], package["version"]
    label = f"{name} {version}"
    expression = override.get("license") or package.get("license") or ""
    root, files = collect_files(package)
    excluded = as_list(override.get("exclude_files"))
    texts = []
    for path, kind in sorted(files.items(), key=lambda item: (display_path(item[0], root).count("/"),
                                                              display_path(item[0], root))):
        shown = display_path(path, root)
        if any(fnmatch.fnmatchcase(shown, pattern) for pattern in excluded):
            continue
        text = read_text(path)
        if kind == "notice" and detect(text):
            kind = "license"  # COPYRIGHT files that carry the license itself (musl style)
        if text.strip():
            texts.append((shown, kind, text))
    own_texts = [text for _, kind, text in texts if kind == "license"]
    supplied = override_texts(override, base, spdx_dir)
    texts += supplied

    license_texts = [text for _, kind, text in texts if kind == "license"]
    if not license_texts:
        wants_copyright = any(family(identifier) in NEEDS_COPYRIGHT
                              for identifier in re.findall(r"[A-Za-z0-9.+-]+", expression)) or not expression
        example = (f'{{"name": "{name}", "version": "{version}", "spdx": "<SPDX id>", '
                   + ('"copyright": "Copyright (c) <year> <holder>", ' if wants_copyright else "")
                   + '"reason": "..."}')
        problems.append(f"{label} ({expression or 'no license field'}) publishes no license text. "
                        f"Authors: {', '.join(package['authors']) or 'none listed'}. Repository: "
                        f"{package.get('repository') or 'none'}. Add an override, e.g. {example}")
        return None
    if not expression:
        problems.append(f"{label} declares no license expression; add an override with \"license\"")
        return None
    try:
        tree = parse(expression)
    except (ValueError, IndexError):
        problems.append(f"{label}: cannot parse license expression {expression!r}; override \"license\"")
        return None

    def coverage(candidates):
        families = set()
        for text in candidates:
            families |= detect(text) or {OTHER}
        return families, sum(1 for text in candidates if not detect(text))

    families, unclassified = coverage(license_texts)
    if not satisfied(tree, families, unclassified) and not override.get("accept"):
        lgpl3 = " (LGPL-3.0 also needs the GPL-3.0 text)" if "LGPL-3" in expression.upper() else ""
        problems.append(f"{label}: license files ({', '.join(sorted(families)) or 'unrecognised'}) do not "
                        f"cover {expression!r}{lgpl3}; supply the missing text by override, or set "
                        f"\"accept\": true with a reason after checking the files by hand")
    if supplied and own_texts and satisfied(tree, *coverage(own_texts)):
        warnings.append(f"{label}: its own license files now cover {expression!r}; "
                        f"check whether its override is still needed")
    # A lone MIT/BSD/ISC/Zlib license whose files keep the template's placeholder
    # instead of a copyright statement: ship it verbatim, but flag it for review.
    # (Many crates' LICENSE-MIT has no copyright line at all; the Authors line
    # below carries the attribution, so that alone is not flagged.)
    if isinstance(tree, str) and family(tree) in NEEDS_COPYRIGHT and not override.get("copyright"):
        lines_ = [line for _, _, text in texts for line in text.splitlines()]
        if (any(PLACEHOLDER.search(line) and "copyright" in line.lower() for line in lines_) and
                not any(REAL_COPYRIGHT.search(line) and not PLACEHOLDER.search(line) for line in lines_)):
            warnings.append(f"{label}: license file keeps a copyright placeholder; consider an override "
                            f"with \"copyright\" from the authors ({', '.join(package['authors']) or 'none'})")

    lines, form = source_lines(package, override)
    copyleft = any(COPYLEFT.match(identifier) for identifier in identifiers(tree))
    header = [RULE, label, f"License: {expression}"] + lines
    if copyleft:
        if not form:
            problems.append(f"{label} is under {expression} but has no Source Code Form location; "
                            f"add \"source_url\" in its override")
        else:
            header.append(f"Source Code Form: {form}")
        if unavoidable_copyleft(tree, STRONG_COPYLEFT):
            # Notices cannot meet these terms: the combined work's license, relinking or
            # source offers. Fail until a human records the follow-up in the overrides.
            if override.get("accept_copyleft"):
                warnings.append(f"{label}: {expression} binds the shipped binary; accepted by override: "
                                f"{override['reason']}")
            else:
                problems.append(f"{label}: {expression} binds the whole shipped binary (combined-work, "
                                f"relinking or source duties beyond notices); report it as a follow-up and "
                                f"record that with \"accept_copyleft\": true and a reason in its override")
        elif unavoidable_copyleft(tree):
            warnings.append(f"{label}: {expression} (file-level copyleft) applies to the shipped binary; the "
                            f"Source Code Form line covers unmodified use, changes to its files must be published")
    if package["authors"]:
        header.append(f"Authors: {', '.join(package['authors'])}")
    if override.get("copyright") and not override.get("spdx"):
        header += [f"Copyright: {line}" for line in as_list(override["copyright"])]
    if override.get("note"):
        header.append(f"Note: {override['note']}")
    body = []
    for shown, _, text in texts:
        body.append(f"\n----- {shown} -----\n\n{text}")
    return "\n".join(header) + "\n" + "".join(body)


def build_extra(entry, base, spdx_dir):
    label = f"{entry['name']} {entry.get('version', '')}".strip()
    texts = override_texts(entry, base, spdx_dir)
    if not texts:
        fail(f"extra component {label} needs 'spdx' or 'files'")
    header = [RULE, label, f"License: {entry.get('license', 'see below')}"]
    try:
        copyleft = entry.get("license") and any(COPYLEFT.match(i) for i in identifiers(parse(entry["license"])))
    except (ValueError, IndexError):
        fail(f"extra component {label}: cannot parse license expression {entry['license']!r}")
    if copyleft and not entry.get("source_url"):
        fail(f"extra component {label} is under {entry['license']} and needs a 'source_url'")
    if entry.get("source_url"):
        header.append(f"Source: {entry['source_url']}")
        if copyleft:
            header.append(f"Source Code Form: {entry['source_url']}")
    if entry.get("repository"):
        header.append(f"Repository: {entry['repository']}")
    if entry.get("copyright") and not entry.get("spdx"):
        header += [f"Copyright: {line}" for line in as_list(entry["copyright"])]
    if entry.get("note"):
        header.append(f"Note: {entry['note']}")
    body = "".join(f"\n----- {shown} -----\n\n{text}" for shown, _, text in texts)
    return label, "\n".join(header) + "\n" + body


# ---------------------------------------------------------------------------
# Rust standard library
# ---------------------------------------------------------------------------

class HtmlToText(html.parser.HTMLParser):
    BLOCKS = {"p", "div", "h1", "h2", "h3", "h4", "li", "ul", "details", "summary", "tr", "br", "pre"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.pre, self.skip = [], 0, 0

    def handle_starttag(self, tag, attrs):
        if tag in ("head", "style", "script"):
            self.skip += 1
        if tag in self.BLOCKS:
            self.parts.append("\n\n" if tag in ("h1", "h2", "h3", "p", "pre", "details") else "\n")
        if tag == "pre":
            self.pre += 1

    def handle_endtag(self, tag):
        if tag in ("head", "style", "script"):
            self.skip -= 1
        if tag == "pre":
            self.pre -= 1
        if tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip:
            return
        if not self.pre:
            data = re.sub(r"\s+", " ", data)
            if not self.parts or self.parts[-1].endswith("\n"):
                data = data.lstrip()
        self.parts.append(data)

    def text(self):
        joined = "".join(self.parts)
        joined = "\n".join(line.rstrip() for line in joined.split("\n"))
        return re.sub(r"\n{3,}", "\n\n", joined).strip() + "\n"


def rust_std(args, cargo_dir):
    sysroot = run([args.rustc, "--print", "sysroot"], cwd=cargo_dir).strip()
    source = Path(sysroot) / "share" / "doc" / "rust" / "COPYRIGHT-library.html"
    if not source.is_file() or not source.stat().st_size:
        fail(f"missing Rust standard library notices: {source}")
    version = run([args.rustc, "-V"], cwd=cargo_dir).strip()
    if args.check:
        print(f"ok: Rust standard library notices present: {source} ({version})", file=sys.stderr)
        return
    if args.rust_std:
        args.rust_std.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, args.rust_std)
    if args.rust_std_text:
        parser = HtmlToText()
        parser.feed(source.read_text(encoding="utf-8"))
        args.rust_std_text.parent.mkdir(parents=True, exist_ok=True)
        args.rust_std_text.write_text(f"Rust standard library notices ({version})\n"
                                      f"Converted from COPYRIGHT-library.html.\n\n" + parser.text(),
                                      encoding="utf-8")
    print(f"Rust standard library notices: {source} ({version})", file=sys.stderr)


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="Examples:" + __doc__.split("Examples:")[1])
    parser.add_argument("--manifest-path", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("-p", "--package", action="append", default=[],
                        help="shipped workspace package (repeat); required in multi-member workspaces")
    parser.add_argument("--target", action="append", default=[],
                        help="target triple the artifact ships (repeat; 'host'; "
                             "default $TAURI_ENV_TARGET_TRIPLE)")
    parser.add_argument("--features", action="append", default=[])
    parser.add_argument("--all-features", action="store_true")
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--no-locked", action="store_true",
                        help="only for sources without Cargo.lock (some sdists); crate versions may then "
                             "differ from the shipped binary")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--frozen", action="store_true")
    parser.add_argument("--overrides", type=Path, help="JSON overrides file")
    parser.add_argument("--title", default="this software", help="product name for the header")
    parser.add_argument("--out", help="notices file to write ('-' for stdout)")
    parser.add_argument("--append", action="append", type=Path, default=[],
                        help="notices file of another ecosystem to append verbatim (repeat)")
    parser.add_argument("--check", action="store_true", help="collect and validate, write nothing")
    parser.add_argument("--rust-std", type=Path, help="copy COPYRIGHT-library.html here")
    parser.add_argument("--rust-std-text", type=Path, help="write a plain-text rendering here")
    parser.add_argument("--std-name", default="Rust-Licenses.html",
                        help="file name the header cites for the standard library notices")
    parser.add_argument("--own-license", metavar="SPDX",
                        help="fail unless every shipped workspace package declares this license")
    parser.add_argument("--musl-dynamic", action="store_true",
                        help="musl targets link the system musl dynamically (no musl notice needed)")
    parser.add_argument("--include-build-deps", action="store_true")
    parser.add_argument("--include-proc-macros", action="store_true")
    parser.add_argument("--list", action="store_true", help="print the crate list to stderr")
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    args = parser.parse_args()

    if not (args.out or args.check or args.rust_std or args.rust_std_text):
        parser.error("nothing to do: pass --out, --check, --rust-std or --rust-std-text")
    args.manifest_path = args.manifest_path.resolve()
    crates_wanted = bool(args.out or args.check)
    # Standard-library-only runs need no Cargo.toml, only the directory whose
    # rust-toolchain.toml selects the toolchain.
    if not args.manifest_path.is_file() and (crates_wanted or not args.manifest_path.parent.is_dir()):
        parser.error(f"no Cargo.toml at {args.manifest_path}")
    cargo_dir = args.manifest_path.parent

    if args.rust_std or args.rust_std_text:
        rust_std(args, cargo_dir)
    if not crates_wanted:
        return

    if args.no_locked:
        print("warning: --no-locked: crate versions come from a fresh resolution", file=sys.stderr)
    overrides, base, spdx_dir = load_overrides(args.overrides)
    targets = resolve_targets(args, cargo_dir)
    packages, members, nodes = metadata(args, targets)
    if len(members) > 1 and not args.package:
        names = sorted(packages[m]["name"] for m in members)
        fail(f"workspace has {len(members)} members ({', '.join(names)}); "
             f"pass -p for each package the artifact ships")
    selected = match_packages(crate_set(args, targets), packages)
    add_vendored_source_build_deps(selected, packages, nodes)

    problems, warnings, entries, skipped, own = [], [], [], [], []
    for package in sorted(selected.values(), key=lambda p: (p["name"], p["version"], p["id"])):
        if package["id"] in members:
            own.append((package["name"], package.get("license")))
            # The project's own crates must state the root LICENSE's terms, so
            # upstream license files nearby are not read as covering them.
            if args.own_license and package.get("license") != args.own_license:
                problems.append(f"workspace package {package['name']} declares "
                                f"{package.get('license') or 'no license'}, expected {args.own_license} "
                                f"(the root LICENSE); set `license` in its Cargo.toml")
            continue
        override = override_for(overrides, package)
        if override.get("skip"):
            skipped.append(f"{package['name']} {package['version']}: {override['reason']}")
            continue
        if package["source"] is None and not override:
            problems.append(f"{package['name']} {package['version']} is a path dependency outside the "
                            f"workspace ({Path(package['manifest_path']).parent}); add an override: "
                            f"\"skip\" for own code, or license texts for vendored code")
            continue
        entry = build_entry(package, override, base, spdx_dir, problems, warnings)
        if entry:
            entries.append(entry)
            if args.list:
                print(f"  {package['name']} {package['version']}  {package.get('license')}", file=sys.stderr)
    # Workspace members are own code and not listed. Without --own-license nothing
    # checks that, so surface members that look like vendored third-party code.
    if own and not args.own_license:
        print("note: workspace members treated as own code (not listed): "
              + ", ".join(f"{name} ({license or 'no license field'})" for name, license in own), file=sys.stderr)
        declared = sorted({license for _, license in own if license})
        hint = "vendored third-party code needs its texts in an \"extra\" entry"
        if len(declared) > 1:
            warnings.append(f"workspace members declare different licenses ({'; '.join(declared)}); {hint}")
        for name, license in own:
            try:
                copyleft = bool(license) and unavoidable_copyleft(parse(license))
            except (ValueError, IndexError):
                copyleft = False
            if copyleft:
                warnings.append(f"workspace member {name} declares {license}; {hint}")
    # Extras with "targets" (glob patterns) apply only when one of them matches.
    applicable = []
    for entry in overrides["extra"]:
        if not entry.get("targets") or any(fnmatch.fnmatchcase(target, pattern) for target in targets
                                           for pattern in as_list(entry["targets"])):
            applicable.append(entry)
        else:
            print(f"note: extra {entry['name']} applies to {', '.join(as_list(entry['targets']))}, "
                  f"which matches none of {', '.join(targets)}", file=sys.stderr)
    extras = sorted(build_extra(entry, base, spdx_dir) for entry in applicable)
    # musl targets statically link the toolchain's self-contained musl libc (MIT),
    # whose notice is in neither Cargo metadata nor COPYRIGHT-library.html.
    musl = [target for target in targets if "-musl" in target]
    if musl and not args.musl_dynamic and not any(entry["name"].lower().startswith("musl")
                                                  for entry in applicable):
        problems.append(f"{', '.join(musl)} statically links musl libc from the Rust toolchain; add an "
                        f"\"extra\" entry named \"musl libc <version>\" with musl's COPYRIGHT file for the "
                        f"version that rustc ships (src/ci/docker/scripts/musl.sh at the rustc release tag), "
                        f"or pass --musl-dynamic if the binary links the system's musl dynamically")

    for entry in overrides["crates"]:
        if not entry.pop("_used", False):
            print(f"note: override {entry['name']} {entry.get('version', '*')} matched no crate "
                  f"for {', '.join(targets)}", file=sys.stderr)
    for message in skipped:
        print(f"skipped by override: {message}", file=sys.stderr)
    for message in warnings:
        print(f"warning: {message}", file=sys.stderr)
    if problems:
        for message in problems:
            print(f"error: {message}", file=sys.stderr)
        fail(f"{len(problems)} problem(s); see the messages above")

    intro = (f"Third-party notices: Rust crates in {args.title}\n\n"
             f"{args.title} statically links the Rust crates below (targets: {', '.join(targets)}).\n"
             f"Each keeps its own license. Every entry lists the crate, version, SPDX license\n"
             f"expression and source, then the license and notice files the crate publishes.\n"
             f"The Rust standard library's notices ship separately as {args.std_name}.\n")
    document = intro + "".join(f"\n{entry}" for entry in entries) + "".join(f"\n{text}" for _, text in extras)
    for path in args.append:
        if not path.is_file() or not path.stat().st_size:
            fail(f"--append file {path} is missing or empty")
        document += f"\n{RULE}\n{RULE}\n\n" + read_text(path)
    count = len(entries) + len(extras)
    encoded = document.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:12]
    if args.check:
        print(f"ok: {count} components, {len(encoded)} bytes, sha256 {digest}", file=sys.stderr)
        return
    if args.out == "-":
        sys.stdout.write(document)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(encoded)
    print(f"wrote {args.out}: {count} components, {len(encoded)} bytes, sha256 {digest}", file=sys.stderr)


if __name__ == "__main__":
    main()
