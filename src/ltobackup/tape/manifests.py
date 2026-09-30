from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Self

from ..catalog import Catalog
from ..errors import ValidationError
from ..util import ltfs_tape_relative_path, validate_source_relative_path
from .copier import CopyRequest, SourceChanged, copy_frozen_file

_COPY_BUFFER_BYTES = 1024 * 1024
_MAX_BLOCK_STRING_BYTES = 256
_MAX_BLOCK_JSON_BYTES = 64 * 1024
_PORTABLE_FIELDS = frozenset(
    {"library_id", "relative_path", "tape_relative_path", "size", "mtime_ns", "sha256"}
)
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{n}" for n in range(1, 10)),
        *(f"LPT{n}" for n in range(1, 10)),
    }
)


def _portable_relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValidationError(f"{field} deve essere un percorso POSIX relativo sicuro")
    path, windows = PurePosixPath(value), PureWindowsPath(value)
    if (
        path.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or windows.root
        or not path.parts
        or path.as_posix() != value
        or any(
            part in {"", ".", ".."}
            or ":" in part
            or part.rstrip(". ") != part
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
            for part in path.parts
        )
    ):
        raise ValidationError(f"{field} deve essere un percorso POSIX relativo sicuro")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{field} deve essere un intero non negativo")
    return value


def _sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValidationError("sha256 deve essere un digest esadecimale minuscolo")
    return value


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


@dataclass(frozen=True)
class FileManifestRecord:
    library_id: str
    relative_path: str
    tape_relative_path: str
    size: int
    mtime_ns: int
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.library_id, str) or not self.library_id:
            raise ValidationError("library_id è obbligatorio")
        object.__setattr__(
            self,
            "relative_path",
            validate_source_relative_path(self.relative_path, "relative_path"),
        )
        object.__setattr__(
            self,
            "tape_relative_path",
            _portable_relative_path(self.tape_relative_path, "tape_relative_path"),
        )
        _nonnegative_integer(self.size, "size")
        _nonnegative_integer(self.mtime_ns, "mtime_ns")
        object.__setattr__(self, "sha256", _sha256(self.sha256))


@dataclass(frozen=True)
class BlockManifest:
    block_id: str
    library_id: str
    tape_id: str
    completed_at: str
    file_count: int
    total_bytes: int
    format: str = "lto-library-backup-block-v1"
    copy_mode: str = "direct-files-no-tar"
    sha256_recorded_during_source_stream: bool = True

    def __post_init__(self) -> None:
        if any(
            not isinstance(v, str) or not v
            for v in (self.block_id, self.library_id, self.tape_id, self.completed_at)
        ):
            raise ValidationError("identificativo block.json non valido")
        _nonnegative_integer(self.file_count, "file_count")
        _nonnegative_integer(self.total_bytes, "total_bytes")
        if (
            any(
                len(value.encode("utf-8")) > _MAX_BLOCK_STRING_BYTES
                for value in (
                    self.block_id,
                    self.library_id,
                    self.tape_id,
                    self.completed_at,
                )
            )
            or self.file_count > 2**63 - 1
            or self.total_bytes > 2**63 - 1
        ):
            raise ValidationError("block.json supera i limiti portabili")
        if (
            self.format != "lto-library-backup-block-v1"
            or self.copy_mode != "direct-files-no-tar"
            or self.sha256_recorded_during_source_stream is not True
        ):
            raise ValidationError("block.json non compatibile")


def copy_single_file_to_tape(
    source: Path, destination: Path, *, buffer_bytes: int = _COPY_BUFFER_BYTES
) -> None:
    """Compatibility helper; ManifestWriter itself uses descriptor-anchored publication."""
    source = Path(source)
    destination = Path(destination)
    details = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode):
        raise SourceChanged("source is not a regular file")
    copy_frozen_file(
        CopyRequest(
            source=source,
            destination=destination,
            expected_size=details.st_size,
            expected_mtime_ns=details.st_mtime_ns,
            buffer_bytes=buffer_bytes,
        )
    )


class ManifestWriter:
    def __init__(
        self,
        catalog: Catalog,
        host_staging_path: Path,
        tape_manifest_path: Path,
        block_path: Path,
        snapshot_path: Path,
        *,
        tape_root: Path | None = None,
        buffer_bytes: int = _COPY_BUFFER_BYTES,
    ) -> None:
        if tape_root is None or buffer_bytes <= 0:
            raise ValidationError("tape_root e buffer_bytes validi sono obbligatori")
        self.catalog, self.host_staging_path, self.tape_root, self.buffer_bytes = (
            catalog,
            Path(host_staging_path),
            Path(tape_root),
            buffer_bytes,
        )
        if self.host_staging_path.name in {"", ".", ".."}:
            raise ValidationError("staging host non valido")
        self._host_fd: int | None = None
        self._tape_fd: int | None = None
        self._closed = False
        try:
            self._host_fd = os.open(self.host_staging_path.parent, _directory_flags())
            self._tape_fd = os.open(self.tape_root, _directory_flags())
        except OSError as exc:
            try:
                self.close()
            except OSError as cleanup_error:
                exc.add_note(
                    f"secondary ManifestWriter init close failure: {cleanup_error}"
                )
            error = ValidationError("radice host o LTFS non sicura")
            for note in getattr(exc, "__notes__", []):
                error.add_note(note)
            raise error from exc
        try:
            self._host_identity, self._tape_identity = (
                os.fstat(self._host_fd),
                os.fstat(self._tape_fd),
            )
            if self.host_staging_path.resolve(strict=False).is_relative_to(
                self.tape_root.resolve(strict=True)
            ):
                raise ValidationError("lo staging JSONL deve risiedere fuori da LTFS")
            self._manifest_relative = self._relative(tape_manifest_path)
            self._block_relative = self._relative(block_path)
            self._snapshot_relative = self._relative(snapshot_path)
            if (
                len(
                    {
                        self._manifest_relative,
                        self._block_relative,
                        self._snapshot_relative,
                    }
                )
                != 3
            ):
                raise ValidationError("destinazioni LTFS non distinte")
        except BaseException as exc:
            try:
                self.close()
            except OSError as cleanup_error:
                exc.add_note(
                    f"secondary ManifestWriter init close failure: {cleanup_error}"
                )
            raise
        self._staging_identity: tuple[int, int] | None = None

    def _relative(self, path: Path) -> str:
        try:
            return _portable_relative_path(
                Path(path).relative_to(self.tape_root).as_posix(),
                "percorso artefatto LTFS",
            )
        except ValueError as exc:
            raise ValidationError(
                "gli artefatti portabili devono risiedere su LTFS"
            ) from exc

    @staticmethod
    def _same_identity(
        actual: os.stat_result, expected: os.stat_result | tuple[int, int]
    ) -> bool:
        expected_pair = (
            (expected.st_dev, expected.st_ino)
            if isinstance(expected, os.stat_result)
            else expected
        )
        return (actual.st_dev, actual.st_ino) == expected_pair

    def _assert_roots(self) -> None:
        if self._closed or self._host_fd is None or self._tape_fd is None:
            raise ValidationError("ManifestWriter chiuso")
        if not self._same_identity(
            os.fstat(self._host_fd), self._host_identity
        ) or not self._same_identity(os.fstat(self._tape_fd), self._tape_identity):
            raise ValidationError("identità della radice cambiata")

    def _parent(self, relative: str, create: bool) -> tuple[int, str, tuple[int, int]]:
        self._assert_roots()
        parent_fd = os.dup(self._tape_fd)
        try:
            parts = PurePosixPath(relative).parts
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent_fd)
                    except FileExistsError:
                        pass
                child = os.open(part, _directory_flags(), dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = child
            current = os.fstat(parent_fd)
            return parent_fd, parts[-1], (current.st_dev, current.st_ino)
        except BaseException:
            os.close(parent_fd)
            raise

    def _recheck_parent(self, relative: str, expected: tuple[int, int]) -> None:
        fd, _, identity = self._parent(relative, False)
        try:
            if identity != expected:
                raise ValidationError(
                    "directory LTFS cambiata durante la pubblicazione"
                )
        finally:
            os.close(fd)

    def _preflight_absent(self) -> None:
        for relative in (
            self._manifest_relative,
            self._block_relative,
            self._snapshot_relative,
        ):
            fd, name, _ = self._parent(relative, True)
            try:
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise FileExistsError(f"artefatto LTFS già esistente: {relative}")
            finally:
                os.close(fd)

    def append(self, record: FileManifestRecord) -> None:
        if not isinstance(record, FileManifestRecord):
            raise TypeError("record deve essere FileManifestRecord")
        self._assert_roots()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
        if self._staging_identity is None:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(self.host_staging_path.name, flags, 0o600, dir_fd=self._host_fd)
        try:
            current = os.fstat(fd)
            identity = (current.st_dev, current.st_ino)
            if not stat.S_ISREG(current.st_mode) or (
                self._staging_identity is not None
                and identity != self._staging_identity
            ):
                raise ValidationError("identità staging host non attendibile")
            payload = (
                json.dumps(
                    asdict(record),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            os.write(fd, payload)
            self._staging_identity = identity
        finally:
            os.close(fd)

    def _read_staging(
        self, block: BlockManifest
    ) -> tuple[list[FileManifestRecord], bytes]:
        if self._staging_identity is None:
            raise ValidationError("staging host non creato da questo writer")
        self._assert_roots()
        fd = os.open(
            self.host_staging_path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self._host_fd,
        )
        try:
            current = os.fstat(fd)
            if not stat.S_ISREG(current.st_mode) or not self._same_identity(
                current, self._staging_identity
            ):
                raise ValidationError("staging host è stato sostituito")
            chunks = []
            while chunk := os.read(fd, self.buffer_bytes):
                chunks.append(chunk)
            payload = b"".join(chunks)
            if not payload or not payload.endswith(b"\n"):
                raise ValidationError("staging JSONL incompleto")
            records = []
            for raw in payload.splitlines(keepends=True):
                try:
                    decoded = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValidationError("staging JSONL non valido") from exc
                if not isinstance(decoded, dict) or set(decoded) != _PORTABLE_FIELDS:
                    raise ValidationError("schema staging JSONL non compatibile")
                record = FileManifestRecord(**decoded)
                canonical = (
                    json.dumps(
                        asdict(record),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                if (
                    raw != canonical
                    or record.library_id.casefold() != block.library_id.casefold()
                ):
                    raise ValidationError("staging JSONL non affidabile")
                records.append(record)
            return records, payload
        finally:
            os.close(fd)

    def _validate_binding(
        self, block: BlockManifest, records: list[FileManifestRecord]
    ) -> None:
        row = self.catalog.connection.execute(
            "SELECT library_id,tape_id,tape_relative_root,status,planned_files,planned_bytes FROM blocks WHERE id=?",
            (block.block_id,),
        ).fetchone()
        if (
            row is None
            or row["status"] != "copying"
            or row["library_id"].casefold() != block.library_id.casefold()
            or row["tape_id"].casefold() != block.tape_id.casefold()
            or (block.file_count, block.total_bytes)
            != (row["planned_files"], row["planned_bytes"])
            or (len(records), sum(r.size for r in records))
            != (block.file_count, block.total_bytes)
        ):
            raise ValidationError("block.json non corrisponde al catalogo")
        expected = [
            tuple(item)
            for item in self.catalog.connection.execute(
                "SELECT library_id,relative_path,tape_relative_path,size,mtime_ns,sha256 FROM file_versions WHERE block_id=? AND visible=0 ORDER BY id",
                (block.block_id,),
            )
        ]
        actual = [
            (
                r.library_id,
                r.relative_path,
                r.tape_relative_path,
                r.size,
                r.mtime_ns,
                r.sha256,
            )
            for r in records
        ]
        if actual != expected:
            raise ValidationError("staging non corrisponde alle versioni provvisorie")
        root = _portable_relative_path(row["tape_relative_root"], "radice blocco")
        if any(
            r.tape_relative_path
            != (
                PurePosixPath(root)
                / "files"
                / ltfs_tape_relative_path(r.relative_path)
            ).as_posix()
            for r in records
        ):
            raise ValidationError("percorso staging non corrisponde al blocco")

    def _publish_from_fd(self, source_fd: int, relative: str) -> None:
        parent_fd, name, identity = self._parent(relative, True)
        temporary = f".{name}.{uuid.uuid4().hex}.partial"
        temp_fd: int | None = None
        try:
            temp_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            while chunk := os.read(source_fd, self.buffer_bytes):
                view = memoryview(chunk)
                while view:
                    written = os.write(temp_fd, view)
                    if written <= 0:
                        raise OSError("scrittura LTFS incompleta")
                    view = view[written:]
            os.close(temp_fd)
            temp_fd = None
            self._recheck_parent(relative, identity)
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(f"artefatto LTFS già esistente: {relative}")
            os.rename(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def _publish_bytes(self, payload: bytes, relative: str) -> None:
        self._assert_roots()
        temporary = (
            f".{self.host_staging_path.name}.{uuid.uuid4().hex}.publish-source"
        )
        source_fd = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._host_fd,
        )

        def cleanup(primary: BaseException | None) -> None:
            cleanup_failure: OSError | None = None
            try:
                os.close(source_fd)
            except OSError as exc:
                cleanup_failure = exc
            try:
                os.unlink(temporary, dir_fd=self._host_fd)
            except OSError as exc:
                if cleanup_failure is None:
                    cleanup_failure = exc
                else:
                    cleanup_failure.add_note(
                        "secondary manifest source unlink failure: "
                        f"{type(exc).__name__}: {exc}"
                    )
            if cleanup_failure is None:
                return
            if primary is None:
                raise cleanup_failure
            primary.add_note(
                "secondary manifest source cleanup failure: "
                f"{type(cleanup_failure).__name__}: {cleanup_failure}"
            )
            for note in getattr(cleanup_failure, "__notes__", []):
                primary.add_note(note)

        try:
            view = memoryview(payload)
            while view:
                try:
                    written = os.write(source_fd, view)
                except InterruptedError:
                    continue
                if written <= 0 or written > len(view):
                    raise OSError("scrittura staging incompleta")
                view = view[written:]
            os.lseek(source_fd, 0, os.SEEK_SET)
            self._assert_roots()
            self._publish_from_fd(source_fd, relative)
        except BaseException as exc:
            cleanup(exc)
            raise
        else:
            cleanup(None)

    def _publish_json(self, value: object, relative: str) -> None:
        payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(
            "utf-8"
        )
        if len(payload) > _MAX_BLOCK_JSON_BYTES:
            raise ValidationError("block.json supera i limiti portabili")
        self._publish_bytes(payload, relative)

    def _publish_staging_manifest(self, payload: bytes) -> None:
        self._publish_bytes(payload, self._manifest_relative)

    def _publish_snapshot(self) -> None:
        self._assert_roots()
        host_fd = self._host_fd
        if host_fd is None:
            raise ValidationError("ManifestWriter chiuso")
        name = f".{self.host_staging_path.name}.{uuid.uuid4().hex}.sqlite3"
        try:
            self.catalog.backup_to(Path(name), directory_fd=host_fd)
            fd = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=host_fd
            )
            try:
                self._publish_from_fd(fd, self._snapshot_relative)
            finally:
                os.close(fd)
        finally:
            try:
                os.unlink(name, dir_fd=host_fd)
            except FileNotFoundError:
                pass

    def finalize(self, block: BlockManifest) -> None:
        if not isinstance(block, BlockManifest):
            raise TypeError("block deve essere BlockManifest")
        records, staging_bytes = self._read_staging(block)
        self._validate_binding(block, records)
        self._preflight_absent()
        self._publish_staging_manifest(staging_bytes)
        self._publish_json(asdict(block), self._block_relative)
        self._publish_snapshot()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures: list[OSError] = []
        for attribute in ("_tape_fd", "_host_fd"):
            descriptor = getattr(self, attribute, None)
            setattr(self, attribute, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    failures.append(exc)
        if failures:
            for failure in failures[1:]:
                failures[0].add_note(
                    f"secondary ManifestWriter close failure: "
                    f"{type(failure).__name__}: {failure}"
                )
            raise failures[0]

    def __enter__(self) -> Self:
        self._assert_roots()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            self.close()
        except OSError as cleanup_error:
            if exc is None:
                raise
            exc.add_note(
                f"secondary ManifestWriter context close failure: {cleanup_error}"
            )
            for note in getattr(cleanup_error, "__notes__", []):
                exc.add_note(note)
