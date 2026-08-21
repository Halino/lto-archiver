"""Import seams for the repository's hyphenated command-line tools."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _register_script(alias: str, filename: str) -> None:
    qualified_name = f"{__name__}.{alias}"
    script = Path(__file__).with_name(filename)
    if qualified_name in sys.modules or not script.is_file():
        return
    spec = importlib.util.spec_from_file_location(qualified_name, script)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(qualified_name, None)
        raise


_register_script("build_public_snapshot", "build-public-snapshot.py")
_register_script("audit_public_content", "audit-public-content.py")
