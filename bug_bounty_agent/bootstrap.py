"""Runtime dependency bootstrap for smoother cross-platform execution."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class BootstrapResult:
    ok: bool
    installed: list[str]
    missing_after_install: list[str]
    notes: list[str]


CORE_REQUIREMENTS = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
}

OPTIONAL_REQUIREMENTS = {
    "selenium": "selenium",
}


def ensure_runtime_dependencies(
    include_optional: bool = False,
    auto_install: bool = True,
) -> BootstrapResult:
    requirements = dict(CORE_REQUIREMENTS)
    if include_optional:
        requirements.update(OPTIONAL_REQUIREMENTS)

    missing = [pkg for mod, pkg in requirements.items() if importlib.util.find_spec(mod) is None]
    notes: list[str] = []
    installed: list[str] = []
    if not missing:
        return BootstrapResult(ok=True, installed=[], missing_after_install=[], notes=["Runtime dependencies already satisfied."])

    if not auto_install:
        return BootstrapResult(ok=False, installed=[], missing_after_install=missing, notes=["Auto-install disabled."])

    _ensure_pip(notes)

    for pkg in missing:
        if _pip_install(pkg):
            installed.append(pkg)
            continue
        notes.append(f"Auto-install failed for {pkg}.")

    still_missing = [pkg for mod, pkg in requirements.items() if importlib.util.find_spec(mod) is None]
    ok = len(still_missing) == 0
    if installed:
        notes.append(f"Installed: {', '.join(installed)}")
    if still_missing:
        notes.append(f"Still missing: {', '.join(still_missing)}")
    return BootstrapResult(ok=ok, installed=installed, missing_after_install=still_missing, notes=notes)


def _ensure_pip(notes: list[str]) -> None:
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode == 0:
            return
    except Exception:
        pass

    try:
        bootstrap = subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            text=True,
            check=False,
        )
        if bootstrap.returncode == 0:
            notes.append("Initialized pip via ensurepip.")
    except Exception:
        notes.append("Unable to initialize pip via ensurepip.")


def _pip_install(package: str) -> bool:
    commands = [
        [sys.executable, "-m", "pip", "install", "--user", package],
        [sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", package],
    ]
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception:
            continue
        if result.returncode == 0:
            return True
    return False

