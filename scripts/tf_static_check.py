"""Static check of a project's Terraform directory before `terraform init` runs in CI.

The pipeline runs Terraform on project code with Azure credentials. This check parses
every file with a real HCL parser (python-hcl2, pinned in requirements-hcl.txt) and
allows only a narrow, fixed shape; anything it cannot parse is rejected (fail closed):

- top-level blocks: terraform, provider, resource, data, locals, variable, output,
  moved, import, removed (no module, check, ephemeral, action, ...)
- resource and data types: azurerm_* only; no provisioner or connection blocks anywhere
- provider: only "azurerm", body exactly `features {}` (auth comes from ARM_* env)
- terraform: required_version, required_providers (only azurerm = hashicorp/azurerm)
  and an empty `backend "azurerm" {}` (the pipeline passes -backend-config)
- files: .tf only at the top level; no .tf.json, override files, auto-loaded tfvars,
  CLI config, plugin or cache directories, or symlinks
- .terraform.lock.hcl: present, parseable, only hashicorp/azurerm

The second, independent barrier is the governance CLI configuration
(terraform/cli.tfrc), which lets `terraform init` install nothing but azurerm.

Usage: python tf_static_check.py [--json] <terraform dir>     (exit 1 on findings)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import hcl2

ALLOWED_PROVIDER_SOURCES = {"hashicorp/azurerm", "registry.terraform.io/hashicorp/azurerm"}
ALLOWED_TYPE_PREFIX = "azurerm_"
ALLOWED_TOP_BLOCKS = {
    "terraform",
    "provider",
    "resource",
    "data",
    "locals",
    "variable",
    "output",
    "moved",
    "import",
    "removed",
}
ALLOWED_TERRAFORM_KEYS = {"required_version", "required_providers", "backend"}
FORBIDDEN_NESTED = {"provisioner", "connection"}
FORBIDDEN_DIRS = {".terraform", "terraform.d"}
CLI_CONFIG_FILES = {".terraformrc", "terraform.rc"}
LOCK_FILE = ".terraform.lock.hcl"


def _finding(where: str, problem: str, fix: str) -> str:
    return f"[terraform-static] {where}: {problem} Required change: {fix}"


def _unquote(label: str) -> str:
    if len(label) >= 2 and label[0] == label[-1] == '"':
        return label[1:-1]
    return label


def _is_meta(key: str) -> bool:
    return key.startswith("__") and key.endswith("__")


def _keys(body: Any) -> list[str]:
    return [k for k in body if not _is_meta(k)] if isinstance(body, dict) else []


def _blocks(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return [value] if isinstance(value, dict) else []


def _labelled(value: Any) -> list[tuple[str, Any]]:
    """Entries of a block with one label: [(label, body), ...]."""
    out = []
    for entry in _blocks(value):
        for label in _keys(entry):
            out.append((_unquote(label), entry[label]))
    return out


def _find_nested(node: Any, names: set[str]) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in names:
                found.add(key)
            found |= _find_nested(value, names)
    elif isinstance(node, list):
        for item in node:
            found |= _find_nested(item, names)
    return found


def _check_terraform_block(rel: str, body: dict) -> list[str]:
    out = []
    for key in _keys(body):
        if key not in ALLOWED_TERRAFORM_KEYS:
            out.append(
                _finding(
                    rel,
                    f"`{_unquote(key)}` is not allowed in the terraform block.",
                    "keep only required_version, required_providers and an empty "
                    '`backend "azurerm" {}`.',
                )
            )
    for name, cfg in [
        (k, v)
        for e in _blocks(body.get("required_providers"))
        for k, v in ((k, e[k]) for k in _keys(e))
    ]:
        source = _unquote(cfg.get("source", "")) if isinstance(cfg, dict) else ""
        if _unquote(name) != "azurerm" or source not in ALLOWED_PROVIDER_SOURCES:
            out.append(
                _finding(
                    rel,
                    f'required provider "{_unquote(name)}" (source "{source}") is not allowed.',
                    'require only azurerm = { source = "hashicorp/azurerm" }.',
                )
            )
    for name, cfg in _labelled(body.get("backend")):
        if name != "azurerm" or _keys(cfg):
            out.append(
                _finding(
                    rel,
                    f'backend "{name}" with settings {_keys(cfg)} is not allowed.',
                    'keep an empty `backend "azurerm" {}`; the pipeline passes the settings.',
                )
            )
    return out


def check_config(rel: str, doc: dict) -> list[str]:
    out: list[str] = []
    for key in _keys(doc):
        if key not in ALLOWED_TOP_BLOCKS:
            out.append(
                _finding(
                    rel,
                    f"`{_unquote(key)}` blocks are not allowed in the pipeline.",
                    f"use only {sorted(ALLOWED_TOP_BLOCKS)} blocks.",
                )
            )
    kinds = {"resource": "resource type", "data": "data source type"}
    for kind, word in kinds.items():
        for type_name, _ in _labelled(doc.get(kind)):
            if not type_name.startswith(ALLOWED_TYPE_PREFIX):
                out.append(
                    _finding(
                        rel,
                        f'{word} "{type_name}" is not allowed in the pipeline.',
                        f"use only {ALLOWED_TYPE_PREFIX}* types of the azurerm provider.",
                    )
                )
    for name, body in _labelled(doc.get("provider")):
        if name != "azurerm":
            out.append(_finding(rel, f'provider "{name}" is not allowed.', 'use only "azurerm".'))
            continue
        extra = [k for k in _keys(body) if k != "features"]
        if extra:
            out.append(
                _finding(
                    rel,
                    f'provider "azurerm" sets {extra}; authentication and options come from '
                    "the pipeline.",
                    'write the provider block as `provider "azurerm" { features {} }`.',
                )
            )
        if any(_keys(f) for f in _blocks(body.get("features"))):
            out.append(
                _finding(
                    rel,
                    'provider "azurerm" features must be empty.',
                    "write `features {}`.",
                )
            )
    for body in _blocks(doc.get("terraform")):
        out.extend(_check_terraform_block(rel, body))
    for name in sorted(_find_nested(doc, FORBIDDEN_NESTED)):
        out.append(
            _finding(
                rel,
                f"`{name}` blocks (provisioners) are not allowed.",
                "remove them; the pipeline does not run local or remote commands.",
            )
        )
    return out


def _parse(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    if not isinstance(doc, dict):
        raise ValueError("unexpected document structure")
    return doc


def check_lockfile(path: Path) -> list[str]:
    if not path.is_file():
        return [
            _finding(
                LOCK_FILE,
                "the dependency lock file is missing.",
                "run `terraform -chdir=infra init -backend=false` and commit .terraform.lock.hcl.",
            )
        ]
    try:
        doc = _parse(path)
    except Exception as exc:  # noqa: BLE001 - any parser error means reject
        return [
            _finding(
                LOCK_FILE,
                f"the file cannot be parsed ({type(exc).__name__}).",
                "regenerate it with terraform init.",
            )
        ]
    out = [
        _finding(LOCK_FILE, f"`{k}` entries are not allowed.", "regenerate it with terraform init.")
        for k in _keys(doc)
        if k != "provider"
    ]
    providers = [name for name, _ in _labelled(doc.get("provider"))]
    if not providers:
        out.append(
            _finding(
                LOCK_FILE,
                "the dependency lock file lists no provider.",
                "run `terraform -chdir=infra init -backend=false` and commit .terraform.lock.hcl.",
            )
        )
    out += [
        _finding(
            LOCK_FILE,
            f'provider "{p}" is not allowed.',
            "remove it; only registry.terraform.io/hashicorp/azurerm may be locked.",
        )
        for p in providers
        if p not in ALLOWED_PROVIDER_SOURCES
    ]
    return out


def _file_finding(rel: str, name: str, top_level: bool) -> str | None:
    if name in CLI_CONFIG_FILES:
        return _finding(rel, "Terraform CLI configuration files are not allowed.", f"delete {rel}.")
    if name.endswith(".tf.json"):
        return _finding(rel, "JSON Terraform configuration is not allowed.", "write .tf (HCL).")
    if name == "override.tf" or name.endswith("_override.tf"):
        return _finding(
            rel, "override files are not allowed.", f"merge {rel} into a normal .tf file."
        )
    if name in ("terraform.tfvars", "terraform.tfvars.json") or name.endswith(
        (".auto.tfvars", ".auto.tfvars.json")
    ):
        return _finding(
            rel,
            "automatically loaded variable files are not allowed.",
            "put environment values into env/<environment>.tfvars.",
        )
    if name.endswith(".tf") and not top_level:
        return _finding(
            rel,
            "Terraform files outside the root module (local modules) are not allowed.",
            "move the resources into the root module.",
        )
    return None


def check_dir(root: Path) -> list[str]:
    root = Path(root)
    out: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return [
            _finding(str(root), "the Terraform directory is missing or a symlink.", "use infra/.")
        ]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        for d in sorted(dirnames):
            rel = (here / d).relative_to(root).as_posix()
            if (here / d).is_symlink():
                out.append(
                    _finding(rel, "symlinks are not allowed.", f"replace {rel} by real files.")
                )
            elif d in FORBIDDEN_DIRS:
                out.append(
                    _finding(
                        rel,
                        "Terraform plugin or cache directories are not allowed.",
                        f"delete {rel} from the repository.",
                    )
                )
        dirnames[:] = sorted(
            d for d in dirnames if d not in FORBIDDEN_DIRS and not (here / d).is_symlink()
        )
        for name in sorted(filenames):
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                out.append(
                    _finding(rel, "symlinks are not allowed.", f"replace {rel} by a real file.")
                )
                continue
            finding = _file_finding(rel, name, here == root)
            if finding:
                out.append(finding)
            elif here == root and name.endswith(".tf"):
                try:
                    doc = _parse(path)
                except Exception as exc:  # noqa: BLE001 - any parser error means reject
                    out.append(
                        _finding(
                            rel,
                            f"the file cannot be parsed as HCL ({type(exc).__name__}).",
                            "fix the syntax; run `terraform fmt` and `terraform validate`.",
                        )
                    )
                    continue
                out.extend(check_config(rel, doc))
    out.extend(check_lockfile(root / LOCK_FILE))
    return out


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if len(args) != 1:
        print("usage: tf_static_check.py [--json] <terraform dir>")
        return 2
    findings = check_dir(Path(args[0]))
    if as_json:
        print(json.dumps(findings))
    else:
        for f in findings:
            print(f)
        if not findings:
            print(f"terraform-static: ok ({args[0]})")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
