from __future__ import annotations

import contextlib
import io
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from ltobackup import gui
from ltobackup.gui import (
    NAVIGATION_ITEMS,
    ProgressTracker,
    automatic_job_label,
    build_automatic_job_view,
    choose_existing_job_action,
    explorer_library_signature,
    fitted_window_size,
    advance_write_timing,
    format_duration,
    tape_capacity_view,
    lto_capacity_rows,
    responsive_mode,
    should_reset_backup_explorer,
    smooth_live_write_bps,
    tape_activity_text,
    write_speed_chart_axes,
    write_speed_chart_geometry,
    write_speed_chart_ticks,
    write_speed_text,
    write_timing_view,
)


class GuiParserTests(unittest.TestCase):
    def test_version_flag_reports_the_package_version_without_starting_the_gui(self) -> None:
        output = io.StringIO()

        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            gui.build_parser().parse_args(["--version"])

        self.assertEqual(0, stopped.exception.code)
        self.assertEqual("LTO Archiver 0.11.26", output.getvalue().strip())

    def test_main_handles_version_before_gui_startup_and_returns_zero(self) -> None:
        output = io.StringIO()

        with contextlib.redirect_stdout(output), patch(
            "ltobackup.gui.ensure_controlled_folder_access"
        ) as startup:
            try:
                result = gui.main(["--version"])
            except SystemExit as stopped:
                result = ("SystemExit", stopped.code)

        self.assertEqual(0, result)
        self.assertEqual("LTO Archiver 0.11.26", output.getvalue().strip())
        startup.assert_not_called()

    def test_version_emitter_uses_native_writer_when_python_streams_are_absent(self) -> None:
        emitter = getattr(gui, "_emit_gui_version", None)
        self.assertIsNotNone(emitter)
        native_writer = Mock(return_value=True)

        with patch.object(gui.sys, "stdout", None), patch.object(
            gui.sys, "__stdout__", None
        ), patch.object(gui.sys, "stderr", None):
            emitted = emitter(native_writer=native_writer)

        self.assertTrue(emitted)
        native_writer.assert_called_once_with("LTO Archiver 0.11.26\n")

    def test_version_emitter_prefers_a_normal_stream_without_native_calls(self) -> None:
        emitter = getattr(gui, "_emit_gui_version", None)
        self.assertIsNotNone(emitter)
        output = io.StringIO()
        native_writer = Mock(return_value=True)

        emitted = emitter(stream=output, native_writer=native_writer)

        self.assertTrue(emitted)
        self.assertEqual("LTO Archiver 0.11.26\n", output.getvalue())
        native_writer.assert_not_called()


class ProgressTrackerTests(unittest.TestCase):
    def test_speed_chart_sampling_uses_one_second_buckets_and_keeps_cache_gaps(self) -> None:
        append_sample = getattr(gui, "append_regular_write_speed_sample", None)
        self.assertIsNotNone(append_sample)
        samples: list[tuple[float, float, float | None]] = []

        samples = append_sample(samples, 10.1, 100.0, 200.0)
        samples = append_sample(samples, 10.8, 110.0, 210.0)
        samples = append_sample(samples, 11.2, 90.0, None)
        samples = append_sample(samples, 12.4, 95.0, 205.0)

        self.assertEqual(
            [
                (10.0, 110.0, 210.0),
                (11.0, 90.0, None),
                (12.0, 95.0, 205.0),
            ],
            samples,
        )

    def test_speed_chart_axis_rises_immediately_and_decays_gradually(self) -> None:
        stabilize = getattr(gui, "stabilize_rate_ceiling", None)
        self.assertIsNotNone(stabilize)

        self.assertEqual(500.0, stabilize(200.0, 500.0, 1.0))
        self.assertAlmostEqual(400.0, stabilize(500.0, 200.0, 60.0), places=6)
        self.assertAlmostEqual(160.0, stabilize(200.0, 100.0, 60.0), places=6)

    def test_speed_chart_draws_exact_polylines_without_curve_approximation(self) -> None:
        lines: list[dict] = []
        chart = SimpleNamespace(
            _samples=[(1.0, 100.0, 200.0), (2.0, 150.0, 250.0)],
            _ceiling_bps=200_000_000.0,
            HORIZON_SECONDS=300.0,
            language="it",
            delete=Mock(),
            winfo_width=Mock(return_value=500),
            winfo_reqwidth=Mock(return_value=500),
            create_text=Mock(),
            create_line=lambda *_args, **kwargs: lines.append(kwargs),
        )

        gui.WriteSpeedChart.render(chart, now=2.0)

        traces = [
            row
            for row in lines
            if row.get("fill") in {"#5dd6c0", "#d8942f"} and "smooth" in row
        ]
        self.assertTrue(traces)
        self.assertTrue(all(row.get("smooth") is False for row in traces))

    def test_speed_chart_uses_independent_adaptive_axes_for_tape_and_cache(self) -> None:
        axes = write_speed_chart_axes(
            [
                (1.0, 40_000_000.0, 900_000_000.0),
                (2.0, 38_000_000.0, 600_000_000.0),
            ]
        )

        self.assertEqual(50_000_000.0, axes["effective"])
        self.assertEqual(1_000_000_000.0, axes["cache"])

    def test_speed_chart_ticks_show_units_for_both_independent_axes(self) -> None:
        ticks = write_speed_chart_ticks(200 * 1024**2, 1024**3)

        self.assertEqual(
            ("200.00 MiB/s", "100.00 MiB/s", "0.00 B/s"),
            ticks["effective"],
        )
        self.assertEqual(
            ("1.00 GiB/s", "512.00 MiB/s", "0.00 B/s"),
            ticks["cache"],
        )

    def test_speed_chart_renders_all_ticks_on_both_colored_axes(self) -> None:
        texts: list[dict] = []
        chart = SimpleNamespace(
            _samples=[],
            HORIZON_SECONDS=300.0,
            language="it",
            delete=Mock(),
            winfo_width=Mock(return_value=500),
            winfo_reqwidth=Mock(return_value=500),
            create_text=lambda *_args, **kwargs: texts.append(kwargs),
            create_line=Mock(),
        )

        with patch(
            "ltobackup.gui.write_speed_chart_axes",
            return_value={
                "effective": 200 * 1024**2,
                "cache": 1024**3,
            },
        ):
            gui.WriteSpeedChart.render(chart, now=2.0)

        effective = {
            row["text"] for row in texts if row.get("fill") == "#5dd6c0"
        }
        cache = {
            row["text"] for row in texts if row.get("fill") == "#d8942f"
        }
        self.assertTrue(
            {"200.00 MiB/s", "100.00 MiB/s", "0.00 B/s"}.issubset(effective)
        )
        self.assertTrue(
            {"1.00 GiB/s", "512.00 MiB/s", "0.00 B/s"}.issubset(cache)
        )

    def test_speed_chart_geometry_never_draws_outside_a_narrow_canvas(self) -> None:
        geometry = write_speed_chart_geometry(220)

        self.assertTrue(geometry["compact"])
        self.assertGreater(geometry["right"], geometry["left"])
        self.assertLessEqual(geometry["right"], 220)
        self.assertGreaterEqual(geometry["left"], 0)

    def test_create_job_forwards_registered_tape_reuse_confirmation(self) -> None:
        application = Mock()
        application.create_automatic_job.return_value = {"id": "JOB1"}
        application.automatic_job_creation_context.return_value = {
            "conflicting_jobs": [],
            "saved_on_device": [],
        }
        window = SimpleNamespace(
            _automatic_library_ids=["LIB1"],
            automatic_device=Mock(get=Mock(return_value="TAPE0")),
            automatic_mount=Mock(get=Mock(return_value="AUTO")),
            automatic_labels=Mock(get=Mock(return_value="AB1234\n")),
            automatic_confirm=Mock(get=Mock(return_value=True)),
            automatic_reuse_registered=Mock(get=Mock(return_value=True)),
            automatic_media_key=Mock(get=Mock(return_value="LTO-6")),
            application=application,
            _automatic_created=Mock(),
        )
        window._run_task = Mock(side_effect=lambda _name, operation, *_args, **_kwargs: operation())

        with patch("ltobackup.gui.messagebox.askyesno", return_value=True):
            gui.LtoBackupWindow._create_automatic_job(window)

        application.create_automatic_job.assert_called_once_with(
            ["LIB1"],
            ["AB1234"],
            device_name="TAPE0",
            mount=gui.Path("AUTO"),
            destructive_confirmed=True,
            media_key="LTO-6",
            allow_registered_reuse=True,
        )

    def test_newly_created_job_remains_saved_until_explicit_start(self) -> None:
        window = SimpleNamespace(
            _automatic_job_id="",
            automatic_confirm=Mock(),
            automatic_reuse_registered=Mock(),
            automatic_labels=Mock(),
            automatic_state=Mock(),
            refresh=Mock(),
            after=Mock(),
        )

        with patch("ltobackup.gui.messagebox.showinfo"):
            gui.LtoBackupWindow._automatic_created(window, {"id": "JOB1"})

        window.after.assert_not_called()
        self.assertIn(
            "non e ancora in esecuzione",
            window.automatic_state.set.call_args.args[0],
        )

    def test_create_job_stops_before_confirmation_when_a_library_is_already_committed(self) -> None:
        application = Mock()
        application.automatic_job_creation_context.return_value = {
            "conflicting_jobs": [
                {
                    "id": "JOB-OLD",
                    "display_name": "Archivio esistente",
                    "status": "planned",
                    "overlapping_libraries": ["LIB1"],
                }
            ],
            "saved_on_device": [],
        }
        window = SimpleNamespace(
            _automatic_library_ids=["LIB1"],
            automatic_device=Mock(get=Mock(return_value="TAPE0")),
            automatic_mount=Mock(get=Mock(return_value="AUTO")),
            automatic_labels=Mock(get=Mock(return_value="AB1234\n")),
            automatic_confirm=Mock(get=Mock(return_value=True)),
            automatic_reuse_registered=Mock(get=Mock(return_value=False)),
            automatic_media_key=Mock(get=Mock(return_value="LTO-6")),
            application=application,
            _automatic_created=Mock(),
            _run_task=Mock(),
        )

        with (
            patch("ltobackup.gui.messagebox.showinfo") as showinfo,
            patch("ltobackup.gui.messagebox.askyesno") as askyesno,
        ):
            gui.LtoBackupWindow._create_automatic_job(window)

        askyesno.assert_not_called()
        window._run_task.assert_not_called()
        self.assertIn("JOB-OLD", showinfo.call_args.args[1])

    def test_extend_job_forwards_registered_tape_reuse_confirmation(self) -> None:
        application = Mock()
        application.extend_automatic_job.return_value = {"id": "JOB1"}
        window = SimpleNamespace(
            automatic_jobs_tree=object(),
            _selected_id=Mock(return_value="JOB1"),
            _snapshot={
                "automatic_jobs": [
                    {"id": "JOB1", "status": "completed", "total_cassettes": 1,
                     "library_ids": ["LIB1"]}
                ],
                "automatic_cassettes": [],
            },
            automatic_labels=Mock(get=Mock(return_value="AB1234\n")),
            automatic_confirm=Mock(get=Mock(return_value=True)),
            automatic_reuse_registered=Mock(get=Mock(return_value=True)),
            application=application,
            _automatic_extended=Mock(),
        )
        window._run_task = Mock(side_effect=lambda _name, operation, *_args, **_kwargs: operation())

        with (
            patch("ltobackup.gui.choose_existing_job_action", return_value="extend"),
            patch("ltobackup.gui.messagebox.askyesno", return_value=True),
        ):
            gui.LtoBackupWindow._continue_automatic_job(window)

        application.extend_automatic_job.assert_called_once_with(
            "JOB1",
            ["AB1234"],
            destructive_confirmed=True,
            allow_registered_reuse=True,
        )

    def test_finalization_view_rejects_legacy_file_batch_events(self) -> None:
        with self.assertRaisesRegex(gui.ValidationError, "finalizzazione cassetta"):
            gui.finalization_view(
                {"event": "batch.finalize.progress"},
                language="it",
            )

    def test_finalization_view_does_not_invent_unmount_eta(self) -> None:
        view = gui.finalization_view(
            {
                "event": "unmount.progress",
                "stage": "index_sync",
                "status": "pending",
                "stage_number": 1,
                "stage_total": 3,
                "elapsed_seconds": 25.0,
                "eta_seconds": None,
            },
            language="it",
        )

        self.assertEqual("Sincronizzazione cache e indice LTFS", view["phase"])
        self.assertEqual("Fase 1 / 3", view["counter"])
        self.assertEqual("00:00:25", view["elapsed"])
        self.assertEqual("In apprendimento", view["eta"])
        self.assertEqual(0.0, view["percent"])

    def test_finalization_event_updates_the_dedicated_monitor(self) -> None:
        window = SimpleNamespace(
            _automatic_job_id="JOB1",
            language="it",
            automatic_finalize_phase=Mock(),
            automatic_finalize_detail=Mock(),
            automatic_finalize_counter=Mock(),
            automatic_finalize_elapsed=Mock(),
            automatic_finalize_eta=Mock(),
            automatic_finalize_progress={},
            _automatic_finalization_event=None,
            _automatic_finalization_updated_at=None,
            _set_automatic_finalization_active=Mock(),
        )
        event = {
            "event": "unmount.progress",
            "job_id": "JOB1",
            "stage": "mapping_release",
            "status": "complete",
            "stage_number": 2,
            "stage_total": 3,
            "elapsed_seconds": 12.0,
            "eta_seconds": None,
        }

        with patch("ltobackup.gui.time.monotonic", return_value=100.0):
            gui.LtoBackupWindow._apply_automatic_finalization_event(window, event)

        window.automatic_finalize_phase.set.assert_called_with("Rilascio lettera di unita")
        window.automatic_finalize_counter.set.assert_called_with("Fase 2 / 3")
        window.automatic_finalize_elapsed.set.assert_called_with("00:00:12")
        window.automatic_finalize_eta.set.assert_called_with("In apprendimento")
        self.assertAlmostEqual(
            200.0 / 3.0, window.automatic_finalize_progress["value"]
        )
        self.assertEqual(event, window._automatic_finalization_event)
        self.assertEqual(100.0, window._automatic_finalization_updated_at)

    def test_background_close_progress_does_not_replace_copy_state(self) -> None:
        window = SimpleNamespace(
            _apply_automatic_finalization_event=Mock(),
        )
        event = {
            "event": "batch.finalize.progress",
            "job_id": "JOB1",
            "status": "pending",
        }

        gui.LtoBackupWindow._handle_progress(window, event)

        window._apply_automatic_finalization_event.assert_not_called()

    def test_unmount_progress_updates_dedicated_monitor(self) -> None:
        window = SimpleNamespace(
            _apply_automatic_finalization_event=Mock(),
            _apply_automatic_unmount_timing=Mock(),
        )
        event = {
            "event": "unmount.progress",
            "job_id": "JOB1",
            "stage": "index_sync",
            "status": "pending",
        }

        gui.LtoBackupWindow._handle_progress(window, event)

        window._apply_automatic_finalization_event.assert_called_once_with(event)
        window._apply_automatic_unmount_timing.assert_called_once_with(event)

    def test_finalization_monitor_keeps_idle_phase_visible_and_expands_on_unmount(self) -> None:
        window = SimpleNamespace(
            automatic_finalize_panel=Mock(),
            automatic_finalize_detail_field=Mock(),
            automatic_finalize_progress=Mock(),
            automatic_finalize_metrics=Mock(),
        )

        gui.LtoBackupWindow._set_automatic_finalization_active(window, False)

        window.automatic_finalize_panel.configure.assert_called_with(height=64)
        window.automatic_finalize_detail_field.pack_forget.assert_called_once_with()
        window.automatic_finalize_progress.pack_forget.assert_called_once_with()
        window.automatic_finalize_metrics.pack_forget.assert_called_once_with()

        gui.LtoBackupWindow._set_automatic_finalization_active(window, True)

        window.automatic_finalize_panel.configure.assert_called_with(height=166)
        window.automatic_finalize_detail_field.pack.assert_called_once_with(fill="x")
        window.automatic_finalize_progress.pack.assert_called_once_with(
            fill="x", pady=(4, 6)
        )
        window.automatic_finalize_metrics.pack.assert_called_once_with(fill="x")

    def test_unmount_progress_keeps_the_effective_cassette_average_visible(self) -> None:
        apply_timing = getattr(
            gui.LtoBackupWindow, "_apply_automatic_unmount_timing", None
        )
        self.assertIsNotNone(apply_timing)
        chart = Mock()
        window = SimpleNamespace(
            _automatic_job_id="JOB1",
            _automatic_live_write_bps=160.0,
            _automatic_last_write_at=95.0,
            _automatic_average_write_bps=100.0,
            _automatic_timing_event=None,
            _automatic_timing_updated_at=None,
            language="it",
            automatic_write_speed=Mock(),
            automatic_elapsed_time=Mock(),
            automatic_tape_eta=Mock(),
            automatic_job_eta=Mock(),
            automatic_speed_chart=chart,
        )
        window._render_automatic_timing = lambda event: (
            gui.LtoBackupWindow._render_automatic_timing(window, event)
        )
        event = {
            "event": "unmount.progress",
            "job_id": "JOB1",
            "average_write_bps": 80.0,
            "cassette_elapsed_seconds": 20.0,
            "cassette_eta_seconds": 0.0,
            "job_eta_seconds": 0.0,
        }

        with patch("ltobackup.gui.time.monotonic", return_value=100.0):
            apply_timing(window, event)

        self.assertEqual(80.0, window._automatic_average_write_bps)
        self.assertIn(
            "Media effettiva cassetta: 80.00 B/s",
            window.automatic_write_speed.set.call_args.args[0],
        )
        chart.add_sample.assert_called_once_with(100.0, 80.0, None)

    def test_slow_copyfileex_close_is_reported_to_the_operator(self) -> None:
        window = SimpleNamespace(
            _automatic_job_id="JOB1",
            _automatic_timing_event=None,
            _automatic_timing_updated_at=None,
            _automatic_average_write_bps=0.0,
            _automatic_activity_event=None,
            _automatic_activity_started_at=None,
            _automatic_telemetry_text="",
            automatic_ltfs_activity=Mock(),
            _render_automatic_timing=Mock(),
            _append_log=Mock(),
        )
        event = {
            "event": "file.activity",
            "job_id": "JOB1",
            "phase": "timing.complete",
            "relative_path": "video/master.mxf",
            "average_write_bps": 80.0,
            "close_elapsed_seconds": 130.0,
            "data_complete_seconds": 100.0,
            "copy_return_seconds": 230.0,
            "hash_complete_seconds": 235.0,
        }

        gui.LtoBackupWindow._apply_automatic_copy_activity(window, event)

        warning = window._append_log.call_args.args[0]
        self.assertIn("Chiusura LTFS lenta", warning)
        self.assertIn("130.00s", warning)
        self.assertIn("video/master.mxf", warning)

    def test_finalization_elapsed_time_advances_while_storeopen_is_blocking(self) -> None:
        window = SimpleNamespace(
            _automatic_finalization_event={
                "event": "unmount.progress",
                "stage": "index_sync",
                "status": "pending",
                "stage_number": 1,
                "stage_total": 3,
                "elapsed_seconds": 25.0,
            },
            _automatic_finalization_updated_at=100.0,
            _automatic_activity_event=None,
            _automatic_activity_started_at=None,
            _automatic_writing=False,
            _automatic_last_write_at=None,
            language="it",
            automatic_finalize_phase=Mock(),
            automatic_finalize_detail=Mock(),
            automatic_finalize_counter=Mock(),
            automatic_finalize_elapsed=Mock(),
            automatic_finalize_eta=Mock(),
            automatic_finalize_progress={},
        )

        with patch("ltobackup.gui.time.monotonic", return_value=110.0):
            gui.LtoBackupWindow._update_automatic_speed_idle(window)

        window.automatic_finalize_elapsed.set.assert_called_with("00:00:35")
        window.automatic_finalize_eta.set.assert_called_with("In apprendimento")

    def test_speed_chart_keeps_fixed_geometry_while_trace_changes(self) -> None:
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"runtime Tcl/Tk non disponibile: {exc}")
        root.withdraw()
        try:
            chart = gui.WriteSpeedChart(root)
            chart.pack(fill="x")
            root.update_idletasks()
            before = (chart.winfo_reqwidth(), chart.winfo_reqheight())
            now = gui.time.monotonic()
            chart.add_sample(now - 1, 130_000_000, 150_000_000)
            chart.add_sample(now, 132_000_000, 170_000_000)
            root.update_idletasks()
            self.assertEqual(before, (chart.winfo_reqwidth(), chart.winfo_reqheight()))
            self.assertGreater(len(chart.find_all()), 10)
        finally:
            root.destroy()

    def test_timing_metric_does_not_request_more_space_when_eta_grows(self) -> None:
        factory = getattr(gui, "stable_metric_cell", None)
        self.assertIsNotNone(
            factory,
            "le metriche temporali devono avere una geometria indipendente dal testo",
        )
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"runtime Tcl/Tk non disponibile: {exc}")
        root.withdraw()
        try:
            value = tk.StringVar(master=root, value="-")
            cell = factory(root, "FINE CASSETTA", value, background="#263746")
            cell.pack(fill="x")
            root.update_idletasks()
            before = (cell.winfo_reqwidth(), cell.winfo_reqheight())
            value.set("123g 23:59:59")
            root.update_idletasks()
            self.assertEqual(before, (cell.winfo_reqwidth(), cell.winfo_reqheight()))
        finally:
            root.destroy()

    def test_live_phase_field_keeps_the_same_requested_geometry(self) -> None:
        factory = getattr(gui, "stable_status_field", None)
        self.assertIsNotNone(
            factory,
            "i testi di fase variabili devono vivere in un contenitore a geometria stabile",
        )
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"runtime Tcl/Tk non disponibile: {exc}")
        root.withdraw()
        try:
            parent = tk.Frame(root, width=440, height=80)
            parent.pack()
            variable = tk.StringVar(master=root, value="Scrittura")
            field = factory(
                parent,
                variable,
                height=44,
                background="#ffffff",
                foreground="#263746",
            )
            field.pack(fill="x")
            root.update_idletasks()
            short_geometry = (field.winfo_reqwidth(), field.winfo_reqheight())

            variable.set(
                "StoreOpen sta completando la scrittura fisica del file con un "
                "percorso molto lungo e una fase differente"
            )
            root.update_idletasks()

            self.assertEqual(
                short_geometry,
                (field.winfo_reqwidth(), field.winfo_reqheight()),
            )
        finally:
            root.destroy()

    def test_copy_activity_heartbeat_explains_a_pending_ltfs_write(self) -> None:
        formatter = getattr(gui, "copy_activity_text", None)
        self.assertIsNotNone(formatter, "manca il testo heartbeat delle chiamate LTFS bloccanti")

        text = formatter(
            {
                "phase": "write.pending",
                "relative_path": "video/master.mxf",
                "pending_bytes": 67_108_864,
            },
            elapsed_seconds=12,
        )

        self.assertEqual(
            "StoreOpen sta completando la scrittura: video/master.mxf  |  "
            "blocco 64.00 MiB  |  12s",
            text,
        )
        self.assertEqual(
            "StoreOpen sta completando la scrittura fisica e il flush LTFS: "
            "video/master.mxf  |  12s",
            formatter(
                {
                    "phase": "flush.pending",
                    "relative_path": "video/master.mxf",
                    "pending_bytes": 0,
                },
                elapsed_seconds=12,
            ),
        )
        self.assertEqual(
            "StoreOpen sta chiudendo il file LTFS: video/master.mxf  |  12s",
            formatter(
                {
                    "phase": "close.pending",
                    "relative_path": "video/master.mxf",
                    "pending_bytes": 0,
                },
                elapsed_seconds=12,
            ),
        )
        self.assertEqual(
            "Lettura SMB in corso: video/master.mxf  |  12s",
            formatter(
                {
                    "phase": "read.pending",
                    "relative_path": "video/master.mxf",
                    "pending_bytes": 0,
                },
                elapsed_seconds=12,
            ),
        )
        self.assertEqual(
            "Attesa disponibilita pipeline di chiusura LTFS: "
            "video/master.mxf  |  12s",
            formatter(
                {
                    "phase": "close_queue.pending",
                    "relative_path": "video/master.mxf",
                    "pending_bytes": 0,
                },
                elapsed_seconds=12,
            ),
        )

    def test_pending_copy_activity_remains_live_until_storeopen_returns(self) -> None:
        window = SimpleNamespace(
            _automatic_job_id="JOB1",
            _automatic_activity_event=None,
            _automatic_activity_started_at=None,
            _automatic_writing=True,
            language="it",
            automatic_state=Mock(),
            automatic_selected_job_action=Mock(),
            automatic_ltfs_activity=Mock(),
            automatic_write_speed=Mock(),
            automatic_elapsed_time=Mock(),
            automatic_tape_eta=Mock(),
            automatic_job_eta=Mock(),
            _automatic_timing_event=None,
            _automatic_timing_updated_at=None,
            _automatic_last_write_at=None,
            _automatic_average_write_bps=0.0,
        )
        window._render_automatic_timing = lambda event: (
            gui.LtoBackupWindow._render_automatic_timing(window, event)
        )
        pending = {
            "event": "file.activity",
            "job_id": "JOB1",
            "phase": "write.pending",
            "relative_path": "video/master.mxf",
            "pending_bytes": 67_108_864,
        }

        with patch("ltobackup.gui.time.monotonic", return_value=100.0):
            gui.LtoBackupWindow._apply_automatic_copy_activity(window, pending)
        with patch("ltobackup.gui.time.monotonic", return_value=112.0):
            gui.LtoBackupWindow._update_automatic_speed_idle(window)

        expected = (
            "StoreOpen sta completando la scrittura: video/master.mxf  |  "
            "blocco 64.00 MiB  |  12s"
        )
        window.automatic_state.set.assert_called_with(expected)
        window.automatic_selected_job_action.set.assert_called_with(expected)
        window.automatic_ltfs_activity.set.assert_called_with(expected)

        gui.LtoBackupWindow._apply_automatic_copy_activity(
            window,
            {**pending, "phase": "write.complete", "pending_bytes": 0},
        )
        self.assertIsNone(window._automatic_activity_event)
        self.assertIsNone(window._automatic_activity_started_at)

    def test_pending_ltfs_close_refreshes_the_timing_strip_and_effective_rate(self) -> None:
        pending = {
            "event": "file.activity",
            "job_id": "JOB1",
            "phase": "close.pending",
            "relative_path": "video/master.mxf",
            "cassette_copied_bytes": 1_000,
            "cassette_planned_bytes": 2_000,
            "job_copied_bytes": 1_500,
            "job_planned_bytes": 4_000,
            "cassette_elapsed_seconds": 10.0,
            "average_write_bps": 100.0,
        }
        window = SimpleNamespace(
            _automatic_job_id="JOB1",
            _automatic_activity_event=pending,
            _automatic_activity_started_at=100.0,
            _automatic_writing=True,
            _automatic_last_write_at=100.0,
            _automatic_average_write_bps=100.0,
            _automatic_timing_event=pending,
            _automatic_timing_updated_at=100.0,
            language="it",
            automatic_state=Mock(),
            automatic_selected_job_action=Mock(),
            automatic_ltfs_activity=Mock(),
            automatic_write_speed=Mock(),
            automatic_elapsed_time=Mock(),
            automatic_tape_eta=Mock(),
            automatic_job_eta=Mock(),
        )
        window._render_automatic_timing = lambda event: (
            gui.LtoBackupWindow._render_automatic_timing(window, event)
        )

        with patch("ltobackup.gui.time.monotonic", return_value=110.0):
            gui.LtoBackupWindow._update_automatic_speed_idle(window)

        window.automatic_elapsed_time.set.assert_called_with("00:00:20")
        window.automatic_tape_eta.set.assert_called_with("00:00:20")
        window.automatic_job_eta.set.assert_called_with("00:00:50")
        self.assertEqual(50.0, window._automatic_average_write_bps)
        self.assertIn(
            "Media effettiva cassetta: 50.00 B/s",
            window.automatic_write_speed.set.call_args.args[0],
        )
        self.assertIn(
            "Invio alla cache LTFS: in attesa di conferma LTFS",
            window.automatic_write_speed.set.call_args.args[0],
        )
        self.assertNotIn("Velocita nastro", window.automatic_write_speed.set.call_args.args[0])

    def test_gui_startup_checks_the_narrow_cfa_permission_before_initialization(self) -> None:
        application = Mock()
        window = Mock()
        window.mainloop.return_value = None
        timeline = Mock()
        application.ensure_initialized.side_effect = timeline.initialize
        with (
            patch(
                "ltobackup.gui.ensure_controlled_folder_access",
                side_effect=timeline.cfa,
            ) as ensure_cfa,
            patch("ltobackup.gui.LtoApplication", return_value=application),
            patch("ltobackup.gui.LtoBackupWindow", return_value=window),
        ):
            self.assertEqual(0, gui.main([]))

        ensure_cfa.assert_called_once_with()
        application.ensure_initialized.assert_called_once_with()
        self.assertEqual([call.cfa(), call.initialize()], timeline.mock_calls[:2])

    def test_lto_capacity_rows_distinguish_native_ltfs_and_compressed_space(self) -> None:
        rows = lto_capacity_rows()

        self.assertEqual("LTO-5", rows[0]["media_key"])
        self.assertEqual("1.5 TB", rows[0]["native"])
        self.assertEqual("1.43 TB", rows[0]["ltfs"])
        self.assertEqual("2.41 TB", rows[1]["ltfs"])
        self.assertEqual("LTO-10 PA", rows[-1]["media_key"])
        self.assertEqual("37.03 TB", rows[-1]["ltfs"])

    def test_tape_capacity_view_explains_free_space_and_application_reserve(self) -> None:
        view = tape_capacity_view({
            "tape_total_bytes": 2500,
            "tape_initial_free_bytes": 2400,
            "tape_usable_bytes": 2200,
            "tape_remaining_bytes": 1900,
            "tape_reserve_bytes": 200,
            "tape_ltfs_overhead_bytes": 64,
            "tape_application_limit_bytes": 2300,
            "tape_used_percent": 13.636,
        })

        self.assertEqual(13.636, view["percent"])
        self.assertIn("1.86 KiB", view["remaining"])
        self.assertIn("2.34 KiB", view["ltfs_free"])
        self.assertIn("200.00 B", view["reserve"])
        self.assertIn("64.00 B", view["overhead"])
        self.assertIn("2.25 KiB", view["limit"])

        french = tape_capacity_view({"tape_remaining_bytes": 1024}, language="fr")
        self.assertEqual("Disponible pour l’écriture : 1.00 KiB", french["remaining"])

    def test_write_speed_text_shows_current_and_average_rate(self) -> None:
        self.assertEqual(
            "Media effettiva cassetta: 143.05 MiB/s  |  Invio alla cache LTFS: 152.59 MiB/s",
            write_speed_text(160_000_000, 150_000_000),
        )
        self.assertEqual(
            "Media effettiva cassetta: 143.05 MiB/s  |  Invio alla cache LTFS: "
            "in attesa di conferma LTFS  |  nessuna conferma dalla cache da 6s",
            write_speed_text(None, 150_000_000, stalled_seconds=6),
        )
        self.assertEqual(
            "Effective tape average: 143.05 MiB/s  |  LTFS cache admission: 152.59 MiB/s",
            write_speed_text(160_000_000, 150_000_000, language="en"),
        )
        self.assertNotIn("Velocita nastro", write_speed_text(160_000_000, 150_000_000))

    def test_live_write_speed_is_smoothed_and_survives_missing_samples(self) -> None:
        self.assertEqual(160_000_000, smooth_live_write_bps(None, 160_000_000))
        self.assertEqual(160_000_000, smooth_live_write_bps(160_000_000, None))
        self.assertEqual(160_000_000, smooth_live_write_bps(160_000_000, 0))
        self.assertEqual(
            170_000_000,
            smooth_live_write_bps(160_000_000, 200_000_000),
        )

    def test_waiting_speed_keeps_last_live_value_visible(self) -> None:
        self.assertEqual(
            "Media effettiva cassetta: 143.05 MiB/s  |  Invio alla cache LTFS: "
            "152.59 MiB/s  |  nessuna conferma dalla cache da 6s",
            write_speed_text(160_000_000, 150_000_000, stalled_seconds=6),
        )

    def test_duration_and_timing_strip_are_explicit_and_stable(self) -> None:
        self.assertEqual("1g 02:03:04", format_duration(93_784))
        self.assertEqual("01:01:01", format_duration(3_661))
        self.assertEqual("-", format_duration(None))

        view = write_timing_view({
            "cassette_elapsed_seconds": 3_661,
            "cassette_eta_seconds": 7_322,
            "job_eta_seconds": 93_784,
        })

        self.assertEqual("TEMPO TRASCORSO", view["elapsed_label"])
        self.assertEqual("01:01:01", view["elapsed"])
        self.assertEqual("FINE CASSETTA", view["tape_eta_label"])
        self.assertEqual("02:02:02", view["tape_eta"])
        self.assertEqual("FINE SET", view["job_eta_label"])
        self.assertEqual("1g 02:03:04", view["job_eta"])

    def test_timing_heartbeat_includes_ltfs_pause_in_the_effective_average(self) -> None:
        advanced = advance_write_timing(
            {
                "cassette_copied_bytes": 1_000,
                "cassette_planned_bytes": 2_000,
                "job_copied_bytes": 1_500,
                "job_planned_bytes": 4_000,
                "cassette_elapsed_seconds": 10.0,
                "average_write_bps": 100.0,
            },
            10.0,
        )

        self.assertEqual(20.0, advanced["cassette_elapsed_seconds"])
        self.assertEqual(50.0, advanced["average_write_bps"])
        self.assertEqual(20.0, advanced["cassette_eta_seconds"])
        self.assertEqual(50.0, advanced["job_eta_seconds"])

    def test_timing_strip_has_all_supported_languages(self) -> None:
        event = {
            "cassette_elapsed_seconds": 10,
            "cassette_eta_seconds": None,
            "job_eta_seconds": None,
        }

        self.assertEqual("TAPE COMPLETE", write_timing_view(event, language="en")["tape_eta_label"])
        self.assertEqual("FIN DE BANDE", write_timing_view(event, language="fr")["tape_eta_label"])
        self.assertEqual("BANDENDE", write_timing_view(event, language="de")["tape_eta_label"])
        self.assertEqual("FIN DE CINTA", write_timing_view(event, language="es")["tape_eta_label"])

    def test_tape_activity_text_distinguishes_ltfs_internal_work(self) -> None:
        buffered = tape_activity_text({
            "activity": "buffered",
            "buffered_bytes": 8_388_608,
            "buffered_objects": 2,
            "first_logical_object": 12345,
            "tape_alerts": [],
        })
        unavailable = tape_activity_text({"activity": "unavailable"})

        self.assertIn("buffer LTFS", buffered)
        self.assertIn("8.00 MiB", buffered)
        self.assertIn("posizione 12345", buffered)
        self.assertIn("monitoraggio applicativo", unavailable)

    def test_window_fits_common_small_and_large_displays(self) -> None:
        self.assertEqual((992, 688), fitted_window_size(1024, 768))
        self.assertEqual((1334, 688), fitted_window_size(1366, 768))
        self.assertEqual((1360, 840), fitted_window_size(1920, 1080))
        self.assertEqual((768, 520), fitted_window_size(800, 600))

    def test_responsive_breakpoint_keeps_narrow_panels_in_compact_mode(self) -> None:
        self.assertEqual("compact", responsive_mode(900))
        self.assertEqual("compact", responsive_mode(1199))
        self.assertEqual("compact", responsive_mode(1366))
        self.assertEqual("compact", responsive_mode(1549))
        self.assertEqual("wide", responsive_mode(1550))

    def test_catalog_refresh_preserves_search_until_libraries_change(self) -> None:
        libraries = [
            {"id": "LIB1", "name": "Library", "source_root": r"\\nas\share", "status": "active"}
        ]
        signature = explorer_library_signature(libraries)

        self.assertFalse(should_reset_backup_explorer("search", signature, signature))
        self.assertTrue(should_reset_backup_explorer("tree", signature, signature))
        changed = explorer_library_signature([
            {**libraries[0], "status": "retired"}
        ])
        self.assertTrue(should_reset_backup_explorer("search", signature, changed))

    def test_navigation_exposes_the_complete_operator_workflow(self) -> None:
        self.assertEqual(
            ["overview", "libraries", "inventory", "automatic", "backup", "restore", "search", "catalog"],
            [item.key for item in NAVIGATION_ITEMS],
        )
        self.assertEqual(
            ["01", "02", "03", "04"],
            [item.marker for item in NAVIGATION_ITEMS if item.marker],
        )
        self.assertEqual(len(NAVIGATION_ITEMS), len({item.key for item in NAVIGATION_ITEMS}))
        inventory = next(item for item in NAVIGATION_ITEMS if item.key == "inventory")
        self.assertEqual("Piano del job", inventory.title)
        self.assertIn("librerie del job", inventory.subtitle)

    def test_combines_completed_files_with_current_file_progress(self) -> None:
        tracker = ProgressTracker()
        tracker.update({"event": "plan", "files": 2, "bytes": 1000})
        first = tracker.update(
            {"event": "file.progress", "index": 1, "relative_path": "a.bin", "copied_bytes": 250}
        )
        tracker.update(
            {
                "event": "file.complete",
                "index": 1,
                "total_files": 2,
                "relative_path": "a.bin",
                "copied_bytes": 400,
                "total_bytes": 1000,
            }
        )
        second = tracker.update(
            {"event": "file.progress", "index": 2, "relative_path": "b.bin", "copied_bytes": 300}
        )

        self.assertEqual(25.0, first.percent)
        self.assertEqual(70.0, second.percent)
        self.assertIn("b.bin", second.message)

    def test_tracks_progress_across_all_libraries(self) -> None:
        tracker = ProgressTracker()

        starting_second = tracker.update(
            {"event": "library.scan.start", "library_id": "LIB_B", "index": 2, "total": 4}
        )
        completed_second = tracker.update(
            {
                "event": "library.scan.complete",
                "library_id": "LIB_B",
                "index": 2,
                "total": 4,
                "files": 12,
                "bytes": 1024,
            }
        )

        self.assertEqual(25.0, starting_second.percent)
        self.assertEqual(50.0, completed_second.percent)
        self.assertIn("LIB_B", completed_second.message)
        self.assertIn("2/4", completed_second.message)

    def test_explains_the_pre_write_scan_instead_of_reporting_a_stall(self) -> None:
        tracker = ProgressTracker()
        view = tracker.update({
            "event": "batch.scan.start", "library_id": "LIB_A", "index": 1, "total": 3
        })

        self.assertEqual(0.0, view.percent)
        self.assertIn("1/3", view.message)
        self.assertIn("LIB_A", view.message)


class AutomaticJobViewTests(unittest.TestCase):
    def test_planned_job_explains_that_explicit_start_is_required(self) -> None:
        view = build_automatic_job_view(
            {"id": "JOB-NEW", "status": "planned", "total_cassettes": 1},
            [
                {
                    "sequence": 1,
                    "physical_label": "ARC001L6",
                    "status": "pending",
                    "planned_files": 2,
                    "planned_bytes": 100,
                    "copied_files": 0,
                    "copied_bytes": 0,
                }
            ],
        )

        self.assertIn("non e in esecuzione", view["callout"])
        self.assertIn("Avvia / riprendi", view["callout"])
        self.assertIn("JOB SALVATO", view["checkpoint"])

    def test_failed_cassette_to_retry_returns_only_the_failed_step(self) -> None:
        cassettes = [
            {"sequence": 1, "status": "completed"},
            {"sequence": 2, "status": "failed", "physical_label": "FAIL02L6"},
            {"sequence": 3, "status": "pending"},
        ]

        self.assertEqual(
            cassettes[1],
            getattr(gui, "failed_cassette_to_retry", lambda *_args: None)(
                {"status": "failed"}, cassettes
            ),
        )
        self.assertIsNone(
            getattr(gui, "failed_cassette_to_retry", lambda *_args: None)(
                {"status": "paused"}, cassettes
            )
        )

    def test_job_label_prefers_editable_name_and_falls_back_to_stable_id(self) -> None:
        self.assertEqual(
            "Archivio marketing",
            automatic_job_label({"id": "AUTO-123", "display_name": "Archivio marketing"}),
        )
        self.assertEqual("AUTO-123", automatic_job_label({"id": "AUTO-123"}))

    def test_existing_job_action_resumes_or_extends_from_one_command(self) -> None:
        reserve = {
            "job_id": "JOB1",
            "status": "pending",
            "planned_files": 0,
            "planned_bytes": 0,
        }

        self.assertEqual(
            "resume",
            choose_existing_job_action({"id": "JOB1", "status": "paused"}, [], []),
        )
        self.assertEqual(
            "resume",
            choose_existing_job_action(
                {"id": "JOB1", "status": "completed"}, [reserve], []
            ),
        )
        self.assertEqual(
            "extend",
            choose_existing_job_action(
                {"id": "JOB1", "status": "completed"}, [], ["AB1234"]
            ),
        )
        self.assertEqual(
            "extend",
            choose_existing_job_action(
                {"id": "JOB1", "status": "paused"}, [], ["AB1234"]
            ),
        )

    def test_existing_job_action_explains_what_is_missing(self) -> None:
        self.assertEqual(
            "resume",
            choose_existing_job_action(
                {"id": "JOB1", "status": "completed"}, [], []
            ),
        )
        with self.assertRaisesRegex(Exception, "in errore"):
            choose_existing_job_action(
                {"id": "JOB1", "status": "failed"},
                [
                    {
                        "sequence": 2,
                        "status": "failed",
                        "planned_files": 10,
                        "planned_bytes": 100,
                    }
                ],
                ["AB1234"],
            )
        with self.assertRaisesRegex(Exception, "cassetta 2"):
            choose_existing_job_action(
                {"id": "JOB1", "status": "failed"},
                [
                    {
                        "sequence": 2,
                        "status": "failed",
                        "planned_files": 10,
                        "planned_bytes": 100,
                    }
                ],
                [],
            )

    def test_marks_completed_current_and_upcoming_cassettes(self) -> None:
        job = {
            "id": "JOB-42",
            "status": "waiting_media",
            "current_sequence": 2,
            "total_cassettes": 3,
        }
        cassettes = [
            {
                "sequence": 1,
                "physical_label": "ARC001L6",
                "status": "completed",
                "planned_files": 2,
                "planned_bytes": 100,
                "copied_files": 2,
                "copied_bytes": 100,
            },
            {
                "sequence": 2,
                "physical_label": "ARC002L6",
                "status": "pending",
                "planned_files": 3,
                "planned_bytes": 200,
                "copied_files": 0,
                "copied_bytes": 0,
            },
            {
                "sequence": 3,
                "physical_label": "ARC003L6",
                "status": "pending",
                "planned_files": 1,
                "planned_bytes": 50,
                "copied_files": 0,
                "copied_bytes": 0,
            },
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertEqual(1, view["completed_cassettes"])
        self.assertEqual(3, view["total_cassettes"])
        self.assertAlmostEqual(100 / 350 * 100, view["progress_percent"])
        self.assertEqual("ARC002L6", view["next_label"])
        self.assertEqual("Inserire ora: ARC002L6", view["callout"])
        self.assertEqual(
            "CHECKPOINT SALVATO  |  1 / 3 cassette completate  |  Ripartenza: 2 / 3 ARC002L6",
            view["checkpoint"],
        )
        self.assertEqual(["[OK]", "[ORA]", "[ ]"], [row["marker"] for row in view["cassettes"]])
        self.assertEqual(
            ["queue_done", "queue_current", "queue_pending"],
            [row["tag"] for row in view["cassettes"]],
        )

    def test_append_step_is_clearly_marked_as_non_destructive(self) -> None:
        job = {
            "id": "JOB-APPEND", "status": "waiting_media",
            "current_sequence": 1, "total_cassettes": 2,
        }
        cassettes = [
            {
                "sequence": 1, "physical_label": "ARC001L6", "status": "waiting_media",
                "operation": "append", "planned_files": 2, "planned_bytes": 200,
                "copied_files": 0, "copied_bytes": 0,
            },
            {
                "sequence": 2, "physical_label": "ARC002L6", "status": "pending",
                "operation": "format", "planned_files": 1, "planned_bytes": 100,
                "copied_files": 0, "copied_bytes": 0,
            },
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertIn("APPEND", view["callout"])
        self.assertIn("nessuna formattazione", view["callout"])
        self.assertEqual("APPEND - conserva i dati", view["cassettes"][0]["operation_label"])
        self.assertEqual("NUOVA - formatta LTFS", view["cassettes"][1]["operation_label"])

    def test_completed_job_without_reserves_can_attempt_append_without_new_labels(self) -> None:
        action = choose_existing_job_action(
            {"id": "JOB-APPEND", "status": "completed"},
            [{
                "sequence": 1, "status": "completed", "operation": "format",
                "planned_files": 1, "planned_bytes": 10,
            }],
            [],
        )

        self.assertEqual("resume", action)

    def test_uses_cassette_progress_and_exposes_failure(self) -> None:
        job = {
            "id": "JOB-FAIL",
            "status": "failed",
            "current_sequence": 1,
            "total_cassettes": 1,
            "last_error": "Drive non disponibile",
        }
        cassettes = [
            {
                "sequence": 1,
                "physical_label": "BAD001L6",
                "status": "failed",
                "planned_files": 10,
                "planned_bytes": 1000,
                "copied_files": 4,
                "copied_bytes": 400,
            }
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertEqual(40.0, view["progress_percent"])
        self.assertEqual("Job fermo: Drive non disponibile", view["callout"])
        self.assertIn("ultimo checkpoint sicuro: 0 / 1", view["checkpoint"])
        self.assertIn("Verificare l'errore", view["checkpoint"])
        self.assertEqual("[!]", view["cassettes"][0]["marker"])
        self.assertEqual("queue_failed", view["cassettes"][0]["tag"])
        self.assertEqual(1, view.get("retry_sequence"))
        self.assertEqual("BAD001L6", view.get("retry_label"))

    def test_completed_job_has_a_terminal_summary(self) -> None:
        job = {"id": "JOB-DONE", "status": "completed", "total_cassettes": 1}
        cassettes = [
            {
                "sequence": 1,
                "physical_label": "DONE01L6",
                "status": "completed",
                "planned_files": 2,
                "planned_bytes": 200,
                "copied_files": 2,
                "copied_bytes": 200,
            }
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertEqual(100.0, view["progress_percent"])
        self.assertEqual("Job completato: tutte le cassette sono state scritte ed espulse.", view["callout"])
        self.assertEqual(
            "CHECKPOINT FINALE  |  1 / 1 cassette completate  |  Job concluso",
            view["checkpoint"],
        )
        self.assertEqual("-", view["next_label"])

    def test_completed_job_displays_unused_cassettes_as_future_reserve(self) -> None:
        job = {"id": "JOB-RESERVE", "status": "completed", "total_cassettes": 3}
        cassettes = [
            {
                "sequence": 1,
                "physical_label": "DONE01L6",
                "status": "completed",
                "planned_files": 2,
                "planned_bytes": 200,
                "copied_files": 2,
                "copied_bytes": 200,
            },
            {
                "sequence": 2,
                "physical_label": "KEEP02L6",
                "status": "pending",
                "planned_files": 0,
                "planned_bytes": 0,
                "copied_files": 0,
                "copied_bytes": 0,
            },
            {
                "sequence": 3,
                "physical_label": "KEEP03L6",
                "status": "pending",
                "planned_files": 0,
                "planned_bytes": 0,
                "copied_files": 0,
                "copied_bytes": 0,
            },
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertEqual(2, view["reserved_cassettes"])
        self.assertEqual(1, view["active_cassettes"])
        self.assertIn("2 cassette in riserva futura", view["callout"])
        self.assertEqual(["[OK]", "[R]", "[R]"], [row["marker"] for row in view["cassettes"]])
        self.assertEqual(
            ["queue_done", "queue_reserved", "queue_reserved"],
            [row["tag"] for row in view["cassettes"]],
        )

    def test_active_cassette_does_not_claim_mid_tape_resume(self) -> None:
        job = {"id": "JOB-WRITE", "status": "writing", "total_cassettes": 2}
        cassettes = [
            {"sequence": 1, "physical_label": "DONE01L6", "status": "completed"},
            {"sequence": 2, "physical_label": "LIVE02L6", "status": "writing"},
        ]

        view = build_automatic_job_view(job, cassettes)

        self.assertIn("checkpoint sicuro: 1 / 2 cassette", view["checkpoint"])
        self.assertIn("Cassetta corrente 2 / 2: LIVE02L6", view["checkpoint"])


if __name__ == "__main__":
    unittest.main()
