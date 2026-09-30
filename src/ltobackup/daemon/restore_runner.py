"""Fenced execution of one immutable, read-only LTFS restore cassette."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from ..catalog import Catalog
from ..errors import CatalogError
from ..operational_log import (
    NullOperationalEventSink,
    OperationalEventSink,
    OperationalPhaseTracker,
    closed_operational_correlation,
)
from ..tape.command_supervisor import (
    CommandFailed,
    CompletedCommand,
    LtfsFinalizationReceipt,
)
from ..tape.linux_ltfs import LinuxLtfsBackend, MediaIdentityError
from ..tape.models import (
    ExpectedMedia,
    MediaIdentity,
    MountedTape,
    UnmountResult,
    expected_media_from_catalog,
)
from .models import StaleOperationFence
from .operations import InvalidOperationAdmissionSnapshot, OperationContext
from .restore_copy import (
    RestoreCopyConflict,
    RestoreCopyError,
    RestoreCopyRequest,
    RestoreCopyResult,
    RestoreCopyVerificationError,
    RestorePathError,
    RestoreReplacementAuthorization,
    copy_selected_restore_item,
)
from .restore_destination import (
    RestoreDestinationAdmissionError,
    RestoreDestinationVerifier,
)


class _CatalogFactory(Protocol):
    def __call__(self) -> Catalog: ...


class _BackendFactory(Protocol):
    def __call__(
        self, expected: ExpectedMedia, fence: object
    ) -> LinuxLtfsBackend: ...


class _UnmountObserver:
    """The read-only restore lifecycle needs no index-finalization callbacks."""

    def finalization_started(self) -> None:
        return None

    def mount_release_started(self) -> None:
        return None


@dataclass(frozen=True)
class RestoreCassetteOutcome:
    state: Literal["succeeded", "recovery_required"]
    next_state: Literal[
        "waiting_media", "paused", "cancelled", "completed", "recovery_required"
    ]
    run_id: str
    cassette_sequence: int
    restored_files: int
    skipped_files: int
    restored_bytes: int


class RestoreCassetteRunner:
    """Restore the exact next cassette without a source rescan or tape writes."""

    def __init__(
        self,
        *,
        catalog_factory: _CatalogFactory,
        backend_factory: _BackendFactory,
        destination_verifier: RestoreDestinationVerifier,
        copy_item: Callable[[RestoreCopyRequest], RestoreCopyResult] = copy_selected_restore_item,
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        self._catalog_factory = catalog_factory
        self._backend_factory = backend_factory
        self._destination_verifier = destination_verifier
        self._copy_item = copy_item
        self._event_sink = event_sink or NullOperationalEventSink()

    def run(
        self,
        run_id: str,
        context: OperationContext,
        stop_requested: Callable[[], bool],
    ) -> RestoreCassetteOutcome:
        if not isinstance(run_id, str) or not run_id or not callable(stop_requested):
            raise ValueError("invalid restore runner request")
        if context.record.kind != "restore.cassette" or context.record.job_id != run_id:
            raise RuntimeError("restore operation is not bound to the requested run")
        if context.record.cassette_sequence is None:
            raise RuntimeError("restore operation has no cassette sequence")

        context.assert_current()
        with self._catalog_factory() as catalog:
            cassette = catalog.next_restore_cassette(run_id)
            run = catalog.restore_run(run_id)
            if cassette is None:
                raise RuntimeError("restore run has no pending cassette")
            sequence = _integer(cassette, "sequence")
            if sequence != context.record.cassette_sequence:
                raise RuntimeError("restore operation cassette is not current")
            plan = catalog.get_restore_plan(str(run["plan_id"]))

        expected = expected_media_from_catalog(
            "restore.cassette",
            run_id,
            sequence,
            _text(cassette, "physical_label"),
            _optional_text(cassette, "volume_serial"),
            _optional_text(cassette, "volume_uuid"),
        )
        frozen_ltfs_label = _text(cassette, "volume_label")
        backend = self._backend_factory(expected, context.fence)
        correlation = closed_operational_correlation(
            operation_id=context.record.id,
            job_id=run_id,
            cassette_label=expected.volume_label,
            cassette_sequence=sequence,
            daemon_generation=context.fence.owner_generation,
        )
        phases = OperationalPhaseTracker(self._event_sink, correlation)
        restored_files = 0
        skipped_files = 0
        restored_bytes = 0
        cassette_state = _text(cassette, "state")
        replacement_authorizations: dict[int, Mapping[str, Any]] = {}
        recovery_items = tuple(
            item
            for item in run["items"]
            if _integer(item, "cassette_sequence") == sequence
            and _text(item, "state") == "recovery_required"
        )
        if recovery_items:
            with self._catalog_factory() as catalog:
                for item in recovery_items:
                    item_sequence = _integer(item, "sequence")
                    authorization = catalog.authorized_restore_item_replacement(
                        run_id, item_sequence
                    )
                    if authorization is not None:
                        replacement_authorizations[item_sequence] = authorization
        mounted: MountedTape | None = None
        unmounted = False

        try:
            # This lease is held throughout every selected item.  It cannot be
            # reacquired per file because that would weaken destination fencing.
            with self._destination_verifier.admit(plan) as destination_lease:
                if cassette_state not in {"waiting_media", "restoring"} and not (
                    cassette_state == "recovery_required"
                    and replacement_authorizations
                    and len(replacement_authorizations)
                    == sum(
                        _integer(item, "cassette_sequence") == sequence
                        and _text(item, "state") == "recovery_required"
                        for item in run["items"]
                    )
                ):
                    return self._recover_cassette(
                        run_id, context, sequence, cassette_state, "restore_cassette_state_invalid",
                        restored_files, skipped_files, restored_bytes,
                    )
                backend.bind_restore_volume_label(frozen_ltfs_label)
                phases.start("identify")
                if not backend.wait_for_media(expected, stop_requested):
                    if stop_requested():
                        with self._catalog_factory() as catalog:
                            control = catalog.checkpoint_restore_control_before_mount(
                                context.fence, run_id, sequence
                            )
                        return RestoreCassetteOutcome(
                            "succeeded", control, run_id, sequence,
                            restored_files, skipped_files, restored_bytes,
                        )
                    return self._recover_cassette(
                        run_id, context, sequence, cassette_state, "media_wait_stopped",
                        restored_files, skipped_files, restored_bytes,
                    )
                context.assert_current()
                identity = backend.identify()
                if not _matches_expected_identity(identity, expected, frozen_ltfs_label):
                    return self._recover_cassette(
                        run_id, context, sequence, cassette_state, "media_identity_mismatch",
                        restored_files, skipped_files, restored_bytes,
                    )
                phases.succeed("identify")
                if cassette_state == "waiting_media" and not replacement_authorizations:
                    with self._catalog_factory() as catalog:
                        catalog.transition_restore_cassette(
                            context.fence, run_id, sequence,
                            expected_state="waiting_media", new_state="restoring",
                        )
                    cassette_state = "restoring"

                context.assert_current()
                phases.start("mount", read_only=True)
                try:
                    mounted = backend.mount(read_only=True)
                except BaseException:
                    phases.fail("mount", read_only=True)
                    raise
                if type(mounted) is not MountedTape or mounted.read_only is not True:
                    phases.fail("mount", read_only=True)
                    return self._recover_after_mount(
                        backend, mounted, run_id, context, sequence, cassette_state,
                        "writable_mount", restored_files, skipped_files, restored_bytes,
                        phases=phases,
                    )
                phases.succeed("mount", read_only=True)

                with self._catalog_factory() as catalog:
                    current = catalog.restore_run(run_id)
                phases.start("copy")
                for item in current["items"]:
                    if _integer(item, "cassette_sequence") != sequence:
                        continue
                    item_state = _text(item, "state")
                    if item_state in {"restored", "skipped_verified"}:
                        continue
                    # The coordinator deliberately keeps this false during an
                    # in-flight copy.  Observe it only here, between durable
                    # item checkpoints, so a file is never abandoned midway.
                    if stop_requested():
                        break
                    replacement_authorization = None
                    if item_state == "recovery_required":
                        pending = replacement_authorizations.get(
                            _integer(item, "sequence")
                        )
                        conflict = item.get("conflict")
                        if pending is None and conflict is not None:
                            return self._recover_after_mount(
                                backend, mounted, run_id, context, sequence,
                                cassette_state, "destination_conflict",
                                restored_files, skipped_files, restored_bytes,
                                phases=phases,
                            )
                        if pending is None:
                            with self._catalog_factory() as catalog:
                                catalog.transition_restore_item(
                                    context.fence,
                                    run_id,
                                    _integer(item, "sequence"),
                                    expected_state="recovery_required",
                                    new_state="restoring",
                                    bytes_copied=0,
                                    observed_sha256=None,
                                )
                            consumed = None
                        else:
                            with self._catalog_factory() as catalog:
                                consumed = (
                                    catalog.consume_restore_item_replacement_and_begin(
                                        context.fence,
                                        run_id,
                                        _integer(item, "sequence"),
                                        _text(pending, "id"),
                                    )
                                )
                        if consumed is not None:
                            replacement_authorization = RestoreReplacementAuthorization(
                                authorization_id=_text(consumed, "id"),
                                run_id=_text(consumed, "run_id"),
                                item_sequence=_integer(consumed, "item_sequence"),
                                file_version_id=_integer(consumed, "file_version_id"),
                                canonical_destination=_text(
                                    consumed, "canonical_destination"
                                ),
                                observed_size=_integer(consumed, "observed_size"),
                                observed_sha256=_text(consumed, "observed_sha256"),
                                library_id=_text(item["plan_item"], "library_id"),
                                relative_path=_text(
                                    item["plan_item"], "relative_path"
                                ),
                                tape_relative_path=_text(
                                    item["plan_item"], "tape_relative_path"
                                ),
                                expected_size=_integer(item["plan_item"], "size"),
                                expected_sha256=_text(item["plan_item"], "sha256"),
                                state="consumed",
                                consumed_by_operation_id=_text(
                                    consumed, "consumed_by_operation_id"
                                ),
                            )
                        item_state = "restoring"
                        cassette_state = "restoring"
                    if item_state not in {"pending", "restoring"}:
                        return self._recover_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state,
                            "restore_item_state_invalid", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    with self._catalog_factory() as catalog:
                        if item_state == "pending":
                            catalog.transition_restore_item(
                                context.fence, run_id, _integer(item, "sequence"),
                                expected_state="pending", new_state="restoring",
                                bytes_copied=0, observed_sha256=None,
                            )
                    try:
                        context.assert_current()
                        try:
                            copy_buffer_bytes = context.admitted_copy_buffer_bytes()
                        except InvalidOperationAdmissionSnapshot:
                            return self._recover_item_after_mount(
                                backend, mounted, run_id, context, sequence,
                                cassette_state, item, "restore_admission_invalid",
                                restored_files, skipped_files, restored_bytes,
                                phases=phases,
                            )
                        result = self._copy_item(
                            RestoreCopyRequest(
                                tape_root=mounted.path,
                                destination_lease=destination_lease,
                                library_id=_text(item["plan_item"], "library_id"),
                                relative_path=_text(item["plan_item"], "relative_path"),
                                tape_relative_path=_text(item["plan_item"], "tape_relative_path"),
                                expected_size=_integer(item["plan_item"], "size"),
                                expected_sha256=_text(item["plan_item"], "sha256"),
                                replacement_authorization=replacement_authorization,
                                buffer_bytes=copy_buffer_bytes,
                                stop_requested=stop_requested,
                                progress=context.record_progress,
                                fence_check=context.assert_current,
                            )
                        )
                    except RestoreCopyConflict as exc:
                        with self._catalog_factory() as catalog:
                            catalog.record_restore_item_conflict(
                                context.fence, run_id, _integer(item, "sequence"),
                                canonical_destination=exc.evidence.canonical_destination,
                                observed_size=exc.evidence.observed_size,
                                observed_sha256=exc.evidence.observed_sha256,
                            )
                        return self._recover_after_mount(
                            backend, mounted, run_id, context, sequence, "recovery_required",
                            "destination_conflict", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    except FileNotFoundError:
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            "restore_source_missing", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    except RestoreCopyVerificationError:
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            "restore_hash_mismatch", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    except RestorePathError as exc:
                        error_code = (
                            "restore_source_missing"
                            if "source" in str(exc)
                            else "restore_copy_failed"
                        )
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            error_code, restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    except StaleOperationFence:
                        raise
                    except OSError:
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            "restore_copy_io_failed", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    except RestoreCopyError:
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            "restore_copy_failed", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    expected_size = _integer(item["plan_item"], "size")
                    expected_hash = _text(item["plan_item"], "sha256")
                    if (
                        result.state not in {"restored", "skipped_verified"}
                        or result.sha256 != expected_hash
                        or (result.state == "restored" and result.bytes_copied != expected_size)
                    ):
                        return self._recover_item_after_mount(
                            backend, mounted, run_id, context, sequence, cassette_state, item,
                            "restore_hash_mismatch", restored_files, skipped_files, restored_bytes,
                            phases=phases,
                        )
                    with self._catalog_factory() as catalog:
                        catalog.transition_restore_item(
                            context.fence, run_id, _integer(item, "sequence"),
                            expected_state="restoring", new_state=result.state,
                            bytes_copied=expected_size,
                            observed_sha256=result.sha256,
                        )
                    if result.state == "restored":
                        restored_files += 1
                        restored_bytes += result.bytes_copied
                    else:
                        skipped_files += 1

                phases.succeed("copy")

                # A request that arrived during the final copy becomes visible
                # only after its durable item transition, at this last file
                # boundary before cassette commit.
                context.assert_current()
                phases.start("unmount")
                unmount = backend.unmount(mounted, _UnmountObserver())
                if not _valid_unmount_receipt(unmount, mounted):
                    return self._recover_after_mount(
                        backend, mounted, run_id, context, sequence, cassette_state,
                        "unmount_receipt_invalid", restored_files, skipped_files, restored_bytes,
                        phases=phases,
                    )
                unmounted = True
                phases.succeed("unmount")
                phases.start("eject")
                receipt = backend.unload()
                if type(receipt) is not CompletedCommand or receipt.returncode != 0:
                    return self._recover_cassette(
                        run_id, context, sequence, cassette_state, "eject_receipt_missing",
                        restored_files, skipped_files, restored_bytes,
                    )
                no_media_proven = _physical_eject_proven(backend)
                if not no_media_proven:
                    phases.fail("eject")
                    return self._recover_cassette(
                        run_id,
                        context,
                        sequence,
                        cassette_state,
                        "post_eject_unproven",
                        restored_files,
                        skipped_files,
                        restored_bytes,
                    )
                with self._catalog_factory() as catalog:
                    catalog.record_restore_post_eject_receipt(
                        context.fence,
                        run_id,
                        sequence,
                        mounted,
                        unmount,
                        no_media_proven=no_media_proven,
                    )
                    next_state = catalog.checkpoint_restore_control_or_complete(
                        context.fence, run_id, sequence
                    )
                phases.succeed("eject")
                if next_state not in {
                    "paused", "cancelled", "waiting_media", "completed"
                }:
                    return self._recover_cassette(
                        run_id, context, sequence, cassette_state,
                        "restore_control_not_durable", restored_files,
                        skipped_files, restored_bytes,
                    )
                return RestoreCassetteOutcome(
                    "succeeded", next_state, run_id, sequence,
                    restored_files, skipped_files, restored_bytes,
                )
        except StaleOperationFence:
            raise
        except (
            CatalogError,
            MediaIdentityError,
            OSError,
            RestoreDestinationAdmissionError,
            RuntimeError,
        ):
            return self._recover_after_mount(
                backend, mounted, run_id, context, sequence, cassette_state,
                "restore_cassette_failed", restored_files, skipped_files, restored_bytes,
                already_unmounted=unmounted,
                phases=phases,
            )
        finally:
            phases.fail_open()

    def _recover_item_after_mount(
        self, backend, mounted, run_id, context, sequence, cassette_state, item,
        error_code, restored_files, skipped_files, restored_bytes, *,
        phases: OperationalPhaseTracker,
    ) -> RestoreCassetteOutcome:
        try:
            with self._catalog_factory() as catalog:
                catalog.transition_restore_item(
                    context.fence, run_id, _integer(item, "sequence"),
                    expected_state="restoring", new_state="recovery_required",
                    bytes_copied=0, observed_sha256=None, error_code=error_code,
                )
        except Exception:
            pass
        return self._recover_after_mount(
            backend, mounted, run_id, context, sequence, "recovery_required", error_code,
            restored_files, skipped_files, restored_bytes,
            phases=phases,
        )

    def _recover_after_mount(
        self, backend, mounted, run_id, context, sequence, cassette_state,
        error_code, restored_files, skipped_files, restored_bytes, *,
        already_unmounted=False,
        phases: OperationalPhaseTracker,
    ) -> RestoreCassetteOutcome:
        phases.fail_open()
        if mounted is not None and not already_unmounted:
            phases.start("unmount")
            try:
                unmount = backend.unmount(mounted, _UnmountObserver())
                if _valid_unmount_receipt(unmount, mounted):
                    phases.succeed("unmount")
                    phases.start("eject")
                    receipt = backend.unload()
                    if type(receipt) is CompletedCommand and receipt.returncode == 0:
                        no_media_proven = _physical_eject_proven(backend)
                        if no_media_proven:
                            with self._catalog_factory() as catalog:
                                catalog.record_restore_post_eject_receipt(
                                    context.fence,
                                    run_id,
                                    sequence,
                                    mounted,
                                    unmount,
                                    no_media_proven=True,
                                )
                            phases.succeed("eject")
                        else:
                            phases.fail("eject")
                    else:
                        phases.fail("eject")
                else:
                    phases.fail("unmount")
            except Exception:
                phases.fail_open()
        return self._recover_cassette(
            run_id, context, sequence, cassette_state, error_code,
            restored_files, skipped_files, restored_bytes,
        )

    def _recover_cassette(
        self, run_id, context, sequence, cassette_state, error_code,
        restored_files, skipped_files, restored_bytes,
    ) -> RestoreCassetteOutcome:
        with self._catalog_factory() as catalog:
            if cassette_state != "recovery_required":
                if cassette_state == "waiting_media":
                    try:
                        catalog.record_restore_pre_mount_failure_receipt(
                            context.fence, run_id, sequence
                        )
                    except Exception:
                        pass
                try:
                    catalog.transition_restore_cassette(
                        context.fence, run_id, sequence,
                        expected_state=cassette_state, new_state="recovery_required",
                        error_code=error_code,
                    )
                except Exception:
                    # An item conflict transition already durably promoted both
                    # the cassette and run.  Do not replace that stronger
                    # evidence with a best-effort transition.
                    pass
            catalog.finish_operation(
                context.fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
        return RestoreCassetteOutcome(
            "recovery_required", "recovery_required", run_id, sequence,
            restored_files, skipped_files, restored_bytes,
        )


def _matches_expected_identity(
    identity: object, expected: ExpectedMedia, frozen_ltfs_label: str
) -> bool:
    return (
        type(identity) is MediaIdentity
        and identity.mam_barcode == expected.volume_label
        and identity.volume_label == frozen_ltfs_label
        and (
            expected.volume_serial is None
            or identity.volume_serial == expected.volume_serial
        )
        and (
            expected.volume_uuid is None
            or identity.ltfs_volume_uuid == expected.volume_uuid
        )
    )


def _valid_unmount_receipt(receipt: object, mounted: MountedTape) -> bool:
    return (
        type(receipt) is UnmountResult
        and receipt.finalization_seconds >= 0.0
        and receipt.mount_release_seconds >= 0.0
        and type(receipt.finalization_receipt) is LtfsFinalizationReceipt
        and receipt.finalization_receipt.unmounted is True
        and receipt.finalization_receipt.child_quiesced is True
        and receipt.finalization_receipt.session_receipt == mounted.session_receipt
    )


def _physical_eject_proven(backend: object) -> bool:
    """Return true only for the closed no-media probe result after unload."""

    try:
        backend.media_identity_probe.identify_unmounted()
    except BaseException as exc:  # noqa: BLE001 - observational proof only
        proven = (
            type(exc) is CommandFailed
            and exc.kind == "probe_media"
            and exc.returncode == 3
        )
        if proven and hasattr(backend, "_physical_unload_complete"):
            backend._physical_unload_complete = True
        return proven
    return False


def _text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping[key]
    if type(value) is not str or not value:
        raise RuntimeError(f"restore {key} is invalid")
    return value


def _optional_text(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping[key]
    if value is None:
        return None
    return _text(mapping, key)


def _integer(mapping: Mapping[str, Any], key: str) -> int:
    value = mapping[key]
    if type(value) is not int:
        raise RuntimeError(f"restore {key} is invalid")
    return value
