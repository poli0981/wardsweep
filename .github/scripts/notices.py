#!/usr/bin/env python3
"""Generate, or check, the third-party licence notices.

    python .github/scripts/notices.py                 # regenerate both files
    python .github/scripts/notices.py --check         # fail if either is stale
    python .github/scripts/notices.py --check rust    # one half only

`licenses/rust.md` comes from cargo-about over `Cargo.lock` (see `about.toml`
and `about.hbs`). `licenses/dotnet.md` is built here, from the WPF interface's
`packages.lock.json` and the packages as restored: each package's nuspec gives
its licence and copyright, and the package carries its own licence file and any
third-party notices. Velopack is included from `.config/dotnet-tools.json`,
because `vpk pack` writes its installer and updater into every release.

Nothing is fetched from the network, so the same lock files always produce the
same bytes, which is what lets CI compare. Restore first: `cargo fetch --locked`
for the Rust half, and `dotnet restore WardSweep.sln --locked-mode` plus
`dotnet tool restore` for the .NET half.
"""

from __future__ import annotations

import argparse
import difflib
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST_OUT = ROOT / "licenses" / "rust.md"
DOTNET_OUT = ROOT / "licenses" / "dotnet.md"

# The interface is the only .NET project that ships; its tests do not.
SHIPPED_LOCKS = [ROOT / "ui" / "WardSweep.UI" / "packages.lock.json"]
TOOL_MANIFEST = ROOT / ".config" / "dotnet-tools.json"
# Tools whose own binaries end up inside a release, and what they are called.
EMBEDDED_TOOLS = {"vpk": "Velopack, whose installer and updater `vpk pack` writes into the package"}

LICENCE_FILE = re.compile(r"^licen[cs]e(\.(md|txt))?$", re.IGNORECASE)
NOTICES_FILE = re.compile(r"^third[-_ ]?party[-_ ]?notices?(\.(md|txt))?$", re.IGNORECASE)

# The SPDX `MIT` text, for a package that names the licence by expression and
# carries no file of its own. Its copyright line is the package's.
MIT_TEXT = """\
MIT License

{copyright}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

SYNTHESISED = {"MIT": MIT_TEXT}


def fail(message: str) -> None:
    print(f"::error::{message}")
    sys.exit(1)


def normalise(text: str) -> str:
    """One newline style, no byte-order mark, no trailing whitespace.

    Licence texts arrive with every combination of the three, and the file has
    to come out byte for byte the same on every runner.
    """
    text = text.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def fenced(text: str) -> str:
    """A code block no licence text can close early."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(4, longest + 1)
    return f"{fence}text\n{normalise(text)}{fence}"


def cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|") or "—"


# --- Rust --------------------------------------------------------------------


def check_licence_lists() -> None:
    """about.toml must accept exactly what deny.toml allows.

    WardSweep's own GPL identifiers are allowed by deny.toml for its own crates,
    which about.toml leaves out of the third-party list entirely.
    """
    deny = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
    about = tomllib.loads((ROOT / "about.toml").read_text(encoding="utf-8"))
    allowed = {licence for licence in deny["licenses"]["allow"] if not licence.startswith("GPL-")}
    accepted = set(about["accepted"])
    if allowed != accepted:
        fail(
            "about.toml `accepted` and deny.toml `[licenses] allow` disagree: "
            f"only in deny.toml {sorted(allowed - accepted)}, "
            f"only in about.toml {sorted(accepted - allowed)}"
        )


def rust_notices() -> str:
    # Written to a file rather than read from stdout: cargo-about refuses to
    # write to a redirected stdout when PowerShell is anywhere up the process
    # tree, because PowerShell would re-encode it.
    with tempfile.TemporaryDirectory() as scratch:
        output = Path(scratch) / "rust.md"
        result = subprocess.run(
            [
                "cargo", "about", "generate", "--workspace", "--offline", "--locked", "--fail",
                "about.hbs", "--output-file", str(output),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if result.returncode != 0 or not output.exists():
            print(result.stderr)
            fail("cargo about generate failed; is cargo-about installed, and were the crates fetched?")
        return normalise(output.read_text(encoding="utf-8"))


# --- .NET --------------------------------------------------------------------


@dataclass
class Package:
    id: str
    version: str
    licence: str
    copyright: str
    note: str = ""
    licence_text: str | None = None
    licence_name: str = ""
    notices: list[tuple[str, str]] = field(default_factory=list)


def nuget_root() -> Path:
    configured = os.environ.get("NUGET_PACKAGES")
    return Path(configured) if configured else Path.home() / ".nuget" / "packages"


def read_package(root: Path, name: str, version: str, note: str = "") -> tuple[Package, bool]:
    """A restored package, and whether it is left out as development-only.

    A tool listed in EMBEDDED_TOOLS (it has a `note`) is never left out: its
    nuspec calls it a development dependency, and it is one, but `vpk pack`
    writes its own binaries into every release all the same.
    """
    directory = root / name.lower() / version.lower()
    nuspec = next(directory.glob("*.nuspec"), None) if directory.is_dir() else None
    if nuspec is None:
        fail(
            f"{name} {version} is not restored under {root}; run "
            "`dotnet restore WardSweep.sln --locked-mode` and `dotnet tool restore` first"
        )
    metadata = ET.parse(nuspec).getroot().find("{*}metadata")

    def text(tag: str) -> str:
        element = metadata.find("{*}" + tag)
        return (element.text or "").strip() if element is not None else ""

    licence = metadata.find("{*}license")
    expression = (licence.text or "").strip() if licence is not None else ""
    kind = licence.get("type", "") if licence is not None else ""
    package = Package(
        id=text("id") or name,
        version=version,
        licence=expression if kind == "expression" else (f"see `{expression}`" if expression else text("licenseUrl")),
        copyright=text("copyright") or (f"Copyright (c) {text('authors')}" if text("authors") else ""),
        note=note,
    )

    if text("developmentDependency").lower() == "true" and not note:
        # Left out of the notices, so its texts are not needed.
        return package, True

    files = sorted(entry for entry in directory.iterdir() if entry.is_file())
    own = directory / expression if kind == "file" else next((f for f in files if LICENCE_FILE.match(f.name)), None)
    if own is not None and own.is_file():
        package.licence_text = own.read_text(encoding="utf-8", errors="replace")
        package.licence_name = own.name
    elif kind == "expression" and expression in SYNTHESISED:
        package.licence_text = SYNTHESISED[expression].format(copyright=package.copyright)
        package.licence_name = ""
    else:
        fail(
            f"{name} {version} is under `{package.licence}` and carries no licence file; "
            "add that licence's text to SYNTHESISED in .github/scripts/notices.py"
        )
    package.notices = [
        (entry.name, entry.read_text(encoding="utf-8", errors="replace"))
        for entry in files
        if NOTICES_FILE.match(entry.name)
    ]
    return package, False


def dotnet_notices() -> str:
    root = nuget_root()
    wanted: dict[tuple[str, str], tuple[str, str, str]] = {}
    for lock in SHIPPED_LOCKS:
        data = json.loads(lock.read_text(encoding="utf-8"))
        for framework in data["dependencies"].values():
            for name, entry in framework.items():
                if entry.get("type") == "Project":
                    continue
                wanted[(name.lower(), entry["resolved"])] = (name, entry["resolved"], "")
    tools = json.loads(TOOL_MANIFEST.read_text(encoding="utf-8"))["tools"]
    for tool, note in EMBEDDED_TOOLS.items():
        version = tools[tool]["version"]
        wanted[(tool, version)] = (tool, version, note)

    shipped: list[Package] = []
    left_out: list[Package] = []
    for name, version, note in sorted(wanted.values(), key=lambda item: (item[0].lower(), item[1])):
        package, development = read_package(root, name, version, note)
        (left_out if development else shipped).append(package)

    out = [
        "<!-- Generated by .github/scripts/notices.py from ui/WardSweep.UI/packages.lock.json, "
        ".config/dotnet-tools.json and the packages as restored. Do not edit: CI regenerates "
        "this file and fails if it differs. -->",
        "# .NET components",
        "",
        "Every NuGet package the WPF interface ships with, and the tool whose own",
        "binaries every release carries, with the licence, copyright and texts each",
        "package was published with.",
        "",
    ]
    if left_out:
        out += [
            "Left out as development-only, run by the compiler and never shipped: "
            + ", ".join(f"`{package.id}` {package.version}" for package in left_out)
            + ".",
            "",
        ]
    out += ["| Package | Version | Licence | Copyright |", "| --- | --- | --- | --- |"]
    for package in shipped:
        label = f"`{package.id}`" + (f" ({package.note})" if package.note else "")
        out.append(f"| {label} | {package.version} | {cell(package.licence)} | {cell(package.copyright)} |")

    def grouped(pairs: list[tuple[str, Package]]) -> list[tuple[str, list[Package]]]:
        groups: dict[str, list[Package]] = {}
        for text, package in pairs:
            groups.setdefault(normalise(text), []).append(package)
        return sorted(groups.items(), key=lambda item: (item[1][0].id.lower(), item[1][0].version))

    def users(packages: list[Package]) -> str:
        return ", ".join(f"`{package.id}` {package.version}" for package in packages)

    out += ["", "## Licence texts", ""]
    for text, packages in grouped([(package.licence_text or "", package) for package in shipped]):
        first = packages[0]
        source = (
            f"`{first.licence_name}` in the package"
            if first.licence_name
            else "the SPDX text, with the copyright the package declares"
        )
        out += [f"### {first.licence} — {source}", "", f"Used by {users(packages)}.", "", fenced(text), ""]

    notices = [(text, package) for package in shipped for _, text in package.notices]
    if notices:
        out += ["## Third-party notices carried by the packages", ""]
        for text, packages in grouped(notices):
            names = sorted({name for package in packages for name, other in package.notices if normalise(other) == text})
            out += [f"### {', '.join(f'`{name}`' for name in names)}", "", f"Carried by {users(packages)}.", "", fenced(text), ""]

    return normalise("\n".join(out))


# --- Entry point -------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("which", nargs="?", choices=["all", "rust", "dotnet"], default="all")
    parser.add_argument("--check", action="store_true", help="compare with the committed files instead of writing them")
    args = parser.parse_args()

    check_licence_lists()
    halves = []
    if args.which in ("all", "rust"):
        halves.append((RUST_OUT, rust_notices))
    if args.which in ("all", "dotnet"):
        halves.append((DOTNET_OUT, dotnet_notices))

    stale = []
    for path, generate in halves:
        generated = generate()
        name = path.relative_to(ROOT).as_posix()
        if not args.check:
            path.parent.mkdir(exist_ok=True)
            path.write_text(generated, encoding="utf-8", newline="\n")
            print(f"wrote {name}")
            continue
        committed = normalise(path.read_text(encoding="utf-8")) if path.exists() else ""
        if committed == generated:
            print(f"{name} is current")
            continue
        stale.append(name)
        diff = difflib.unified_diff(
            committed.splitlines(), generated.splitlines(), f"{name} (committed)", f"{name} (generated)", lineterm="", n=1
        )
        for line in itertools.islice(diff, 80):
            print(line)

    if stale:
        fail(f"{', '.join(stale)} is out of date; run `python .github/scripts/notices.py` and commit the result")


if __name__ == "__main__":
    main()
