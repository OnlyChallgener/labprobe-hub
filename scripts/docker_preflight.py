#!/usr/bin/env python3
"""Fail the image build when a module the Hub needs is missing.

Why this exists
---------------
The Dockerfile used to copy modules from a hand-written allowlist.  A new
module (child_guard_service.py) was added to the repository and imported by
hub.py, but nobody added it to the allowlist.  The build still succeeded --
its import smoke test did not name the new module either -- so the image
shipped without the file, and every container start died on `import hub`.
Docker then restarted the container forever.

Compiling everything is not enough, because a missing file is not a syntax
error.  This script instead resolves every top-level import found in the real
entry points, which is exactly the failure that got through.

Usage
-----
    python scripts/docker_preflight.py [app_dir]

`app_dir` defaults to /app.  Exits non-zero with a readable report on failure.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import sys

# Entry points that actually boot the service.  These are what the container
# runs, so a missing module referenced here is fatal.
ENTRY_POINTS = ("hub_entry.py", "hub.py")


class ImportSite:
    """One import statement found in a source file."""

    def __init__(self, module: str, path: pathlib.Path, lineno: int, optional: bool):
        self.module = module
        self.path = path
        self.lineno = lineno
        self.optional = optional


def _top_level(name: str) -> str:
    return name.split(".", 1)[0]


def _collect_imports(path: pathlib.Path) -> list[ImportSite]:
    """Walk the AST and collect absolute imports.

    Imports guarded by `try: ... except ImportError` are marked optional,
    because the module is explicitly designed to work without them.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:  # caught earlier by compileall, reported plainly
        raise SystemExit(f"{path}: syntax error: {exc}") from exc

    # Line numbers that sit inside a try block whose handler catches ImportError.
    optional_lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        catches_import_error = any(
            (isinstance(h.type, ast.Name) and h.type.id in {"ImportError", "ModuleNotFoundError"})
            or (isinstance(h.type, ast.Tuple) and any(
                isinstance(e, ast.Name) and e.id in {"ImportError", "ModuleNotFoundError"}
                for e in h.type.elts
            ))
            for h in node.handlers
        )
        if not catches_import_error:
            continue
        for child in node.body:
            for sub in ast.walk(child):
                if hasattr(sub, "lineno"):
                    optional_lines.add(sub.lineno)

    found: list[ImportSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append(ImportSite(alias.name, path, node.lineno, node.lineno in optional_lines))
        elif isinstance(node, ast.ImportFrom):
            # level > 0 is a relative import: intra-package, not our concern here.
            if node.level or not node.module:
                continue
            found.append(ImportSite(node.module, path, node.lineno, node.lineno in optional_lines))
    return found


def _resolvable(module: str, app_dir: pathlib.Path) -> bool:
    """True when the module can be located, without executing it.

    Checks the app directory first so a local file is preferred over any
    same-named package, matching how Python resolves these at runtime with
    /app as the working directory.
    """
    top = _top_level(module)
    if (app_dir / f"{top}.py").is_file() or (app_dir / top / "__init__.py").is_file():
        return True
    try:
        return importlib.util.find_spec(top) is not None
    except (ImportError, ValueError):
        return False


def main(argv: list[str]) -> int:
    app_dir = pathlib.Path(argv[1] if len(argv) > 1 else "/app").resolve()
    if not app_dir.is_dir():
        print(f"preflight: {app_dir} is not a directory", file=sys.stderr)
        return 2

    missing_entries = [name for name in ENTRY_POINTS if not (app_dir / name).is_file()]
    if missing_entries:
        print("preflight: entry point(s) missing from image: " + ", ".join(missing_entries), file=sys.stderr)
        return 2

    local_modules = sorted(p.stem for p in app_dir.glob("*.py"))
    fatal: list[ImportSite] = []
    optional_missing: list[ImportSite] = []
    seen: set[tuple[str, str]] = set()

    for entry in ENTRY_POINTS:
        for site in _collect_imports(app_dir / entry):
            key = (site.module, str(site.path))
            if key in seen:
                continue
            seen.add(key)
            if _resolvable(site.module, app_dir):
                continue
            (optional_missing if site.optional else fatal).append(site)

    if fatal:
        print("preflight FAILED: unresolvable imports in the entry point chain", file=sys.stderr)
        for site in fatal:
            print(f"  {site.path.name}:{site.lineno}  ->  {site.module}", file=sys.stderr)
        print(
            "\nAdd the file to the image (the Dockerfile copies *.py) or to requirements.txt.",
            file=sys.stderr,
        )
        return 1

    for site in optional_missing:
        print(f"preflight note: optional import not installed: {site.module} ({site.path.name}:{site.lineno})")

    print(f"preflight OK: {len(local_modules)} root modules, {len(seen)} imports resolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
