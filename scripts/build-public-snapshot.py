"""Derive a history-free, content-audited Git snapshot from one source commit."""

from __future__ import annotations

import ast
import argparse
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")

_REVIEWED_PUBLIC_LITERAL_SHA256 = {
    ("src/ltobackup/operational_log.py", "_SECRET_NAME"):
        "ff7cd0cfc64de3da74f5a0b6348c23c46683b1ec95aedfe8e57b714d45769ac2",
    ("src/ltobackup/operational_log.py", "_QUOTED_SECRET_VALUE"):
        "1f17d012fd75287cbdb51c4e06044dae9d169c203d28b2ecad263e2c0b74d893",
    ("src/ltobackup/daemon/service.py", "PEER_CREDENTIAL_SCOPE_KEY"):
        "970979fa139f8b9e16c2a975b6d2040c550533ce83debc188f6616c69ff8fc33",
    ("src/ltobackup/broker/main.py", "_SERVICE_USER"):
        "eec105b1ce9e5072a351b74b12a0553d29c3be2ddbe03d5502f275fd89aa71ae",
    ("src/ltobackup/web/app.py", "password"):
        "05e5cdbae9437afc2dc248302223a0499bba03fcf240a36792784c6d03ef87c7",
    # Disposable guest account name, never a password or operator credential.
    ("packaging/rpm/public_fresh_guest.py", "username"):
        "da04a31e9a531c2ddda4d89b46863ff9700eb96c3407a976b92e435fbd1a29b6",
}



# Only these manually reviewed synthetic WebUI test files bypass the generic
# literal-name heuristic. Any byte change revokes this exception; the independent
# media-identity, private-network and key scanners still run over both files.
_REVIEWED_WEB_TEST_SHA256 = {
    "tests/web/test_management_views.py": "054b900bae95a9c896fcfa2d123b77457f6354d1a540e7b1165fbfcbe9871f20",
    "tests/web/test_layout_chromium.py": "c4eb2a28e97bdef34718eba4fce6e52210e5c5c1bcbaa88c691bb8e994c815dc",
}


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input,
        capture_output=True,
        check=True,
    ).stdout


def _safe_path(raw: str) -> PurePosixPath:
    if not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw:
        raise ValueError("unsafe public manifest path")
    path = PurePosixPath(raw)
    if any(part in (".", "..") for part in raw.split("/")) or path.parts[0] == ".git":
        raise ValueError("unsafe public manifest path")
    return path


def _manifest_paths(manifest: Path) -> tuple[str, ...]:
    lines = manifest.read_text(encoding="utf-8").splitlines()
    if not lines or any(not line or line != line.strip() for line in lines):
        raise ValueError("public manifest must contain exact nonempty paths")
    paths = tuple(_safe_path(line).as_posix() for line in lines)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("public manifest must be sorted with unique paths")
    return paths


def _tree_entries(source_root: Path, commit: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for record in _git(source_root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\x00"):
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, kind, _oid = header.decode("ascii").split(" ", 2)
        if kind != "blob":
            continue
        entries[raw_path.decode("utf-8")] = mode
    return entries


def _auditor():
    script = Path(__file__).with_name("audit-release-content.py")
    spec = importlib.util.spec_from_file_location("lto_public_content_audit", script)
    if spec is None or spec.loader is None:
        raise ValueError("public content auditor unavailable")
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _source_audit_findings(stage: Path, auditor) -> tuple:
    """Keep release-auditor findings except provably ordinary source syntax."""

    findings = auditor.audit_directory(stage)
    accepted: list = []
    for path in stage.rglob("*.py"):
        if path.is_file() and not _safe_python_literals(
            path.read_text(encoding="utf-8", errors="replace"), auditor,
            path.relative_to(stage).as_posix(),
        ):
            accepted.append(
                auditor.AuditFinding(
                    path=path.relative_to(stage).as_posix(),
                    rule="literal-credential",
                    detail="literal credential assigned in Python source",
                )
            )
    for finding in findings:
        path = stage / finding.path
        if not path.is_file():
            accepted.append(finding)
            continue
        suffix = path.suffix.casefold()
        text = path.read_text(encoding="utf-8", errors="replace")
        if finding.rule == "private-network" and _safe_policy_networks(text, auditor):
            continue
        if finding.rule == "internal-host" and _safe_local_config_name(text, auditor):
            continue
        if finding.rule == "private-operation-identifier" and _safe_public_build_input(text):
            continue
        if suffix not in {".py", ".js", ".sh", ".service"}:
            accepted.append(finding)
            continue
        if finding.rule == "credential-assignment" and _safe_code_assignments(
            text, suffix, auditor, finding.path
        ):
            continue
        accepted.append(finding)
    operation_id = re.compile(
        r"\b(?:IR[0-9]{4}|AUTO-[0-9]{8}-[0-9]{6}-[0-9]{6})\b",
        re.IGNORECASE,
    )
    for path in stage.rglob("*"):
        if path.is_file() and operation_id.search(
            path.read_text(encoding="utf-8", errors="replace")
        ):
            accepted.append(
                auditor.AuditFinding(
                    path=path.relative_to(stage).as_posix(),
                    rule="private-operation-identity",
                    detail="media label or job identity detected; value redacted",
                )
            )
    return tuple(accepted)


def _safe_public_build_input(text: str) -> bool:
    residual = text.replace("packaging/scripts/deploy-rhel9.py", "")
    private_markers = (
        ".gitlab-ci.yml",
        "scripts/deploy-",
        "scripts/field-tools/archive/",
        "scripts/field-tools/controlled/",
    )
    return not any(marker.casefold() in residual.casefold() for marker in private_markers)



def _safe_code_assignments(text: str, suffix: str, auditor, relative_path: str) -> bool:
    if suffix == ".py":
        return _safe_python_literals(text, auditor, relative_path)
    matches = tuple(auditor._CREDENTIAL_RE.finditer(text))
    if not matches:
        return False
    for match in matches:
        key = match.group("key").casefold()
        value = match.group("value")
        if auditor._is_synthetic_credential(value):
            continue
        if suffix == ".js":
            if value in {"==", "==="}:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\[[0-9]+\]", value):
                continue
            if value in {'dialog.querySelector("', 'document.querySelector("'} and (
                "#" in auditor._line_for_match(text, match)
            ):
                continue
        if suffix == ".service":
            if key in {"user", "group"} and value in {
                "root", "lto-archiver", "lto-web"
            }:
                continue
            if key in {"credential", "token"} and value.startswith("/"):
                directive = auditor._line_for_match(text, match).strip()
                if re.fullmatch(
                    r"LoadCredential=[A-Za-z0-9_-]+:/etc/lto-archiver/credentials/[A-Za-z0-9_-]+",
                    directive,
                ):
                    continue
            return False
        if suffix == ".sh":
            if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value):
                continue
            return False
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*(?:\([^\"\x27`]*\))?", value):
            continue
        return False
    return True


def _safe_python_literals(text: str, auditor, relative_path: str) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    if _REVIEWED_WEB_TEST_SHA256.get(relative_path) == hashlib.sha256(text.encode("utf-8")).hexdigest():
        return True


    def sensitive(name: str) -> bool:
        return bool(re.search(
            r"(?i)(?:^|_)(?:password|passwd|pwd|secret|token|credential|username|user|account|api_key|access_key|client_secret)(?:$|_)",
            name,
        ))

    def target_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            return node.slice.value if isinstance(node.slice.value, str) else None
        return None

    def sensitive_literal(name: str, value: ast.AST) -> bool:
        if not sensitive(name) or not isinstance(value, ast.Constant):
            return False
        if not isinstance(value.value, str) or auditor._is_synthetic_credential(value.value):
            return False
        digest = hashlib.sha256(value.value.encode("utf-8")).hexdigest()
        return _REVIEWED_PUBLIC_LITERAL_SHA256.get((relative_path, name)) != digest

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(
                sensitive_literal(target_name(target) or "", node.value)
                for target in node.targets
            ):
                return False
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None and sensitive_literal(
                target_name(node.target) or "", node.value
            ):
                return False
        elif isinstance(node, ast.NamedExpr):
            if sensitive_literal(target_name(node.target) or "", node.value):
                return False
        elif isinstance(node, ast.keyword):
            if node.arg and sensitive_literal(node.arg, node.value):
                return False
        elif isinstance(node, ast.Dict):
            if any(
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and sensitive_literal(key.value, value)
                for key, value in zip(node.keys, node.values)
            ):
                return False
    return True



def _safe_policy_networks(text: str, auditor) -> bool:
    cidrs = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
    allowed_hosts = {"0.0.0.0", "127.0.0.1"}
    matches = tuple(
        match for match in auditor._IPV4_RE.finditer(text)
        if auditor._is_private_address(match.group(0))
    )
    return bool(matches) and all(
        match.group(0) in allowed_hosts
        or any(text.startswith(cidr, match.start()) for cidr in cidrs)
        for match in matches
    )


def _safe_local_config_name(text: str, auditor) -> bool:
    matches = tuple(auditor._INTERNAL_HOST_RE.finditer(text))
    return bool(matches) and all(
        match.group(0).casefold() == "ltfs.conf.local" for match in matches
    )



def build_public_snapshot(
    source_root: Path,
    commit: str,
    manifest: Path,
    output_root: Path,
) -> Path:
    """Export only allowlisted files from *commit* into a new one-commit repo."""

    source_root = Path(source_root).resolve(strict=True)
    manifest = Path(manifest).resolve(strict=True)
    output_root = Path(output_root).absolute()
    if output_root.exists() or not output_root.parent.is_dir():
        raise ValueError("public output must be a fresh path under an existing directory")
    if Path(_git(source_root, "rev-parse", "--show-toplevel").decode().strip()) != source_root:
        raise ValueError("source must be the root of its Git repository")
    if not _COMMIT_RE.fullmatch(commit):
        raise ValueError("source commit must be a full SHA-1 identifier")
    resolved = _git(source_root, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if resolved != commit:
        raise ValueError("source commit identity changed")

    paths = _manifest_paths(manifest)
    tree = _tree_entries(source_root, commit)
    if any(tree.get(path) not in ("100644", "100755") for path in paths):
        raise ValueError("manifest contains missing, untracked or non-regular source")

    archive = _git(source_root, "archive", "--format=tar", commit, *paths)
    allowed = set(paths)
    with tempfile.TemporaryDirectory(prefix="lto-public-stage-", dir=output_root.parent) as temp:
        stage = Path(temp) / "snapshot"
        stage.mkdir()
        seen: set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as members:
            for member in members:
                name = _safe_path(member.name.rstrip("/"))
                relative = name.as_posix()
                if member.isdir():
                    if not any(path.startswith(relative + "/") for path in allowed):
                        raise ValueError("unexpected directory in source archive")
                    continue
                if not member.isfile() or relative not in allowed or relative in seen:
                    raise ValueError("unsafe or unexpected source archive member")
                seen.add(relative)
                destination = stage.joinpath(*name.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = members.extractfile(member)
                if stream is None:
                    raise ValueError("unreadable source archive member")
                with stream, destination.open("wb") as target:
                    shutil.copyfileobj(stream, target)
                destination.chmod(0o755 if tree[relative] == "100755" else 0o644)
        if seen != allowed:
            raise ValueError("source archive omitted manifest files")

        auditor = _auditor()
        if _source_audit_findings(stage, auditor):
            raise ValueError("public source content audit rejected the snapshot")
        _git(stage, "init", "-q", "-b", "main")
        _git(stage, "config", "core.hooksPath", "/dev/null")
        _git(stage, "add", "--all")
        _git(
            stage,
            "-c", "user.name=Public Source Export",
            "-c", "user.email=export@example.invalid",
            "commit", "-qm", "Audited public source snapshot",
        )
        # This repository is freshly initialized; the audited tree is its sole commit.
        if _git(stage, "rev-list", "--count", "--all").strip() != b"1":
            raise ValueError("public source history is not a single new root")
        if _git(stage, "log", "-1", "--format=%B").strip() != b"Audited public source snapshot":
            raise ValueError("public source commit message changed")
        if _git(stage, "status", "--porcelain"):
            raise ValueError("public source tree changed after audit")
        head = _git(stage, "rev-parse", "HEAD").decode().strip()
        history_findings = auditor.audit_git_history(stage)
        for finding in history_findings:
            identity, separator, relative = finding.path.partition(":")
            if (
                separator != ":"
                or identity != head
                or relative not in allowed
                or not (stage / relative).is_file()
            ):
                raise ValueError("public source history audit rejected the snapshot")
        os.rename(stage, output_root)
    return output_root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build_public_snapshot(args.source, args.commit, args.manifest, args.output))


if __name__ == "__main__":
    main()
