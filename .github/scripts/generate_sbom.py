#!/usr/bin/env python3
"""Generate CycloneDX SBOMs for this repository.

Each Python dependency manifest is resolved in an isolated virtualenv so the
resulting SBOM carries *pinned, transitive* versions rather than the unpinned
ranges declared in the requirements files. Per-component SBOMs are written
alongside a merged, repository-level SBOM.

Usage:
    python3 .github/scripts/generate_sbom.py [--output-dir sbom] [--spec-version 1.6]

Stdlib only; the CycloneDX tooling is installed into a throwaway venv.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Dependency manifests to inventory, mapped to the logical component they build.
COMPONENTS = [
    {"name": "phantom", "manifest": "phantom/requirements.txt",
     "description": "Phantom offensive-security agent"},
    {"name": "mcp-servers", "manifest": "mcp/requirements-http.txt",
     "description": "MCP server suite (HTTP transport)"},
]

ROOT_COMPONENT = {
    "type": "application",
    "name": "cybersecurity-skills",
    "description": "Library of cybersecurity skills for AI agents",
    "license": "Apache-2.0",
}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Run a command, surfacing stderr on failure."""
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        sys.stderr.write(f"command failed: {' '.join(cmd)}\n{proc.stderr}\n")
        proc.check_returncode()
    return proc


def make_venv(path: Path) -> Path:
    """Create a venv and return the path to its interpreter."""
    run([sys.executable, "-m", "venv", str(path)])
    python = path / ("Scripts" if os.name == "nt" else "bin") / "python"
    run([str(python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    return python


def build_tool_venv(workdir: Path) -> Path:
    """Install cyclonedx-bom into its own venv.

    Kept separate from the component venvs on purpose: installing the SBOM
    tool next to the dependencies would list the tool's own dependency tree
    as part of the component being inventoried.
    """
    python = make_venv(workdir / "_toolenv")
    run([str(python), "-m", "pip", "install", "--quiet", "cyclonedx-bom"])
    return python


def sbom_for_manifest(tool_python: Path, manifest: Path, workdir: Path,
                      name: str, spec_version: str) -> dict:
    """Resolve a manifest in a clean venv and return its CycloneDX document."""
    print(f"  resolving {manifest.relative_to(REPO_ROOT)} ...", flush=True)
    target = make_venv(workdir / f"env_{name}")
    run([str(target), "-m", "pip", "install", "--quiet", "-r", str(manifest)])

    out = workdir / f"{name}.cdx.json"
    run([str(tool_python.parent / "cyclonedx-py"), "environment", str(target),
         "--sv", spec_version, "--of", "JSON", "--output-reproducible",
         "-o", str(out)])
    return json.loads(out.read_text())


def new_bom(spec_version: str, timestamp: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{
                "type": "application",
                "name": "generate_sbom.py",
                "group": "cybersecurity-skills",
            }]},
            "component": {
                "bom-ref": "root",
                "type": ROOT_COMPONENT["type"],
                "name": ROOT_COMPONENT["name"],
                "description": ROOT_COMPONENT["description"],
                "licenses": [{"license": {"id": ROOT_COMPONENT["license"]}}],
            },
        },
        "components": [],
        "dependencies": [],
    }


def merge(boms: list[tuple[dict, dict]], spec_version: str, timestamp: str) -> dict:
    """Merge per-component BOMs into one repository-level document.

    Packages shared between components are emitted once and depended on by
    each component that uses them, so the merged BOM has no duplicate purls.
    """
    merged = new_bom(spec_version, timestamp)
    by_purl: dict[str, str] = {}   # purl -> bom-ref of the deduped component
    root_depends: list[str] = []

    for meta, bom in boms:
        app_ref = f"component:{meta['name']}"
        merged["components"].append({
            "bom-ref": app_ref,
            "type": "application",
            "name": meta["name"],
            "description": meta["description"],
            "properties": [{
                "name": "cybersecurity-skills:manifest",
                "value": meta["manifest"],
            }],
        })
        root_depends.append(app_ref)

        app_depends: list[str] = []
        for comp in bom.get("components", []):
            purl = comp.get("purl")
            key = purl or f"{comp.get('group','')}/{comp['name']}@{comp.get('version','')}"
            if key not in by_purl:
                ref = f"pkg:{key}"
                entry = {k: v for k, v in comp.items() if k != "bom-ref"}
                entry["bom-ref"] = ref
                merged["components"].append(entry)
                by_purl[key] = ref
            app_depends.append(by_purl[key])

        merged["dependencies"].append({
            "ref": app_ref,
            "dependsOn": sorted(set(app_depends)),
        })

    merged["dependencies"].insert(0, {"ref": "root", "dependsOn": sorted(root_depends)})
    # Every referenced component needs a dependency entry for a well-formed graph.
    declared = {d["ref"] for d in merged["dependencies"]}
    for ref in sorted(by_purl.values()):
        if ref not in declared:
            merged["dependencies"].append({"ref": ref, "dependsOn": []})

    merged["components"].sort(key=lambda c: (c.get("type", ""), c["name"].lower()))
    return merged


def validate(tool_python: Path, path: Path, spec_version: str) -> None:
    """Validate a document against the CycloneDX JSON schema."""
    code = (
        "import sys, json\n"
        "from cyclonedx.validation.json import JsonStrictValidator\n"
        "from cyclonedx.schema import SchemaVersion\n"
        f"v = JsonStrictValidator(SchemaVersion.from_version('{spec_version}'))\n"
        f"err = v.validate_str(open({str(path)!r}).read())\n"
        "sys.exit(0) if err is None else sys.exit(f'schema violation: {err}')\n"
    )
    run([str(tool_python), "-c", code])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", default="sbom")
    ap.add_argument("--spec-version", default="1.6")
    args = ap.parse_args()

    out_dir = REPO_ROOT / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    # Reproducible builds set SOURCE_DATE_EPOCH; honour it so reruns diff cleanly.
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    ts = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc)
    timestamp = ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    workdir = Path(tempfile.mkdtemp(prefix="sbom-"))
    try:
        print("installing CycloneDX tooling ...", flush=True)
        tool_python = build_tool_venv(workdir)

        boms = []
        for meta in COMPONENTS:
            manifest = REPO_ROOT / meta["manifest"]
            if not manifest.is_file():
                sys.stderr.write(f"warning: {meta['manifest']} not found, skipping\n")
                continue
            bom = sbom_for_manifest(tool_python, manifest, workdir,
                                    meta["name"], args.spec_version)
            bom["metadata"]["timestamp"] = timestamp
            part = out_dir / f"{meta['name']}.cdx.json"
            part.write_text(json.dumps(bom, indent=2) + "\n")
            validate(tool_python, part, args.spec_version)
            print(f"  wrote {part.relative_to(REPO_ROOT)} "
                  f"({len(bom.get('components', []))} components)", flush=True)
            boms.append((meta, bom))

        if not boms:
            sys.stderr.write("error: no manifests resolved, nothing to do\n")
            return 1

        merged = merge(boms, args.spec_version, timestamp)
        target = out_dir / "cyclonedx.json"
        target.write_text(json.dumps(merged, indent=2) + "\n")
        validate(tool_python, target, args.spec_version)
        print(f"wrote {target.relative_to(REPO_ROOT)} "
              f"({len(merged['components'])} components)", flush=True)
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
