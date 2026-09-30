from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_NODE = shutil.which("node")


@unittest.skipUnless(_NODE, "Node.js is required for the live refresh gate")
class LiveRefreshNodeTests(unittest.TestCase):
    def test_job_fragments_preserve_inputs_and_replace_obsolete_actions(self):
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
class Element {
  constructor(tag, attrs = {}, children = []) {
    this.tagName = tag.toUpperCase(); this.nodeType = 1;
    this.attrs = { ...attrs }; this.childNodes = [];
    this.value = attrs.value || ""; this.parentNode = null;
    children.forEach(child => this.insertBefore(child, null));
  }
  get attributes() { return Object.entries(this.attrs).map(([name,value]) => ({name,value})); }
  getAttribute(name) { return this.attrs[name] ?? null; }
  setAttribute(name, value) { this.attrs[name] = value; }
  removeAttribute(name) { delete this.attrs[name]; }
  insertBefore(child, ref) {
    if (child.parentNode) child.remove();
    let at = ref ? this.childNodes.indexOf(ref) : this.childNodes.length;
    this.childNodes.splice(at, 0, child); child.parentNode = this;
  }
  remove() {
    this.parentNode.childNodes = this.parentNode.childNodes.filter(child => child !== this);
    this.parentNode = null;
  }
}
global.document = {readyState: "loading", addEventListener() {}};
global.window = {setTimeout() {}, clearTimeout() {}};
require(process.argv[2]); const hooks = global.__ltoLiveTestHooks;
const input = new Element("input", {name: "format_confirmation_label", value: ""});
input.value = "AB1234";
const revision = new Element("input", {type: "hidden", name: "expected_revision", value: "1"});
const token = new Element("input", {type: "hidden", name: "idempotency_key", value: "original"});
const resume = new Element("form", {action: "/jobs/JOB1/resume"}, [input, revision, token]);
const current = new Element("section", {}, [resume]);
const next = new Element("section", {}, [new Element("form", {action: "/jobs/JOB1/resume"}, [
  new Element("input", {name: "format_confirmation_label", value: ""}),
  new Element("input", {type: "hidden", name: "expected_revision", value: "2"}),
  new Element("input", {type: "hidden", name: "idempotency_key", value: "new"})
])]);
document.activeElement = input;
hooks.patchJobFragment(current, next);
assert.equal(current.childNodes[0], resume, "retained action keeps DOM identity");
assert.equal(resume.childNodes[0], input, "input and focus survive refresh");
assert.equal(input.value, "AB1234", "entered label survives refresh");
assert.equal(revision.getAttribute("value"), "2", "revision refreshes");
assert.equal(token.getAttribute("value"), "original", "in-flight command token is stable");
const pause = new Element("form", {action: "/jobs/JOB1/pause"});
hooks.patchJobFragment(current, new Element("section", {}, [pause]));
assert.equal(current.childNodes[0], pause, "state transition replaces unavailable action");
assert.equal(resume.parentNode, null, "obsolete Resume cannot remain active");
const header = new Element("header", {"data-revision": "1"});
const summary = new Element("section", {"data-checkpoint": "writing"});
const sourceCheck = new Element("div", {"data-source-state": "blocked"});
const runtime = {dataset: {runtimeUrl: "/partials/jobs/JOB1/runtime?cassette_cursor=page2"}, replaceWith() {}};
const selectors = new Map([
  ['[data-job-runtime][data-job-id="JOB1"]', runtime],
  ['[data-job-fragment="header"]', header],
  ['[data-job-fragment="summary"]', summary],
  ['[data-job-fragment="source-check"]', sourceCheck],
  ['[data-job-fragment="actions"]', current],
]);
document.querySelector = selector => selectors.get(selector) || null;
global.DOMParser = class { parseFromString() { return {querySelector(selector) {
  if (selector.includes("data-job-runtime")) return runtime;
  if (selector.includes('"header"')) return new Element("header", {"data-revision": "2"});
  if (selector.includes('"summary"')) return new Element("section", {"data-checkpoint": "paused"});
  if (selector.includes('"source-check"')) return new Element("div", {"data-source-state": "ready"});
  if (selector.includes('"actions"')) return new Element("section", {}, [new Element("form", {action: "/jobs/JOB1/resume"})]);
  return null;
}}; }};
global.fetch = async url => {
  assert.equal(url, "/partials/jobs/JOB1/runtime?cassette_cursor=page2");
  return {ok: true, text: async () => "authoritative fragments"};
};
(async () => {
  assert.equal(await hooks.refreshJobRuntime("JOB1"), true);
  assert.equal(header.getAttribute("data-revision"), "2");
  assert.equal(summary.getAttribute("data-checkpoint"), "paused");
  assert.equal(sourceCheck.getAttribute("data-source-state"), "ready");
  assert.equal(current.childNodes[0].getAttribute("action"), "/jobs/JOB1/resume");
  process.stdout.write("ok");
})().catch(error => { console.error(error); process.exitCode = 1; });''', "job-fragments.js")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def _run_node_harness(self, source: str, name: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="lto-web-task7-node-") as raw:
            harness = Path(raw) / name
            harness.write_text(source, encoding="utf-8")
            return subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

    def test_log_reconciliation_accepts_journal_cursors_and_preserves_rows(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let insertions = 0;
class Node {
  constructor(key, marker = key) {
    this.dataset = key ? { liveKey: key } : {};
    this.marker = marker;
    this.children = [];
    this.parentNode = null;
    this.scrollTop = 72;
    this.detailsOpen = false;
  }
  appendChild(node) { return this.insertBefore(node, null); }
  insertBefore(node, reference) {
    if (node.parentNode) node.parentNode.children = node.parentNode.children.filter(item => item !== node);
    const at = reference ? this.children.indexOf(reference) : -1;
    if (at < 0) this.children.push(node); else this.children.splice(at, 0, node);
    node.parentNode = this;
    insertions += 1;
    return node;
  }
  remove() {
    if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(item => item !== this);
    this.parentNode = null;
  }
}
global.document = { readyState: "loading", visibilityState: "hidden", addEventListener() {} };
global.window = { setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
assert.ok(hooks);
const current = new Node();
const cursor2 = "s=5f8ab;i=2;b=" + "A".repeat(180);
const old2 = new Node(cursor2, "old-2"); old2.detailsOpen = true;
const old1 = new Node("s=5f8ab;i=1", "old-1");
current.appendChild(old2); current.appendChild(old1);
insertions = 0;
const replacement = new Node();
const cursor3 = "s=5f8ab;i=3;b=boot id/with punctuation!?";
replacement.appendChild(new Node(cursor3, "new-3"));
replacement.appendChild(new Node(cursor2, "updated-2"));
insertions = 0;
hooks.patchImmutableLogContainer(current, replacement);
assert.deepEqual(current.children.map(node => node.dataset.liveKey), [cursor3, cursor2]);
assert.equal(current.children[1], old2, "an immutable journal row keeps its DOM identity");
assert.equal(current.children[1].detailsOpen, true, "expanded event details survive refresh");
assert.equal(current.scrollTop, 72, "the log viewport does not jump");
assert.equal(insertions, 1, "only the new journal row is inserted");
assert.equal(old1.parentNode, null, "rows outside the authoritative page are removed");
process.stdout.write("ok");''',
            "log-immutable-reconciliation.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_log_follow_pause_hidden_tab_and_inflight_fence(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let hidden = true, fetches = 0, replacements = 0, resolveFetch;
const banner = { hidden: true };
const button = {
  disabled: false,
  textContent: "Pause live updates",
  attrs: { "aria-pressed": "true" },
  getAttribute(name) { return this.attrs[name]; },
  setAttribute(name, value) { this.attrs[name] = String(value); },
};
const current = {
  id: "logs-live-status",
  dataset: { logLiveStatus: "", liveFragmentUrl: "/logs/status-fragment?source=all" },
  replaceWith() { replacements += 1; },
  querySelector() { return null; },
};
global.document = {
  readyState: "loading",
  get visibilityState() { return hidden ? "hidden" : "visible"; },
  querySelector(selector) {
    if (selector === "#logs-live-status" || selector === "[data-log-live-status]") return current;
    if (selector === "#connection-banner") return banner;
    if (selector === "[data-log-follow]") return button;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString() { return { querySelector() { return {
    id: "logs-live-status", dataset: { logLiveStatus: "" },
    querySelector() { return null; }, replaceWith() {},
  }; } }; }
};
global.fetch = () => {
  fetches += 1;
  return new Promise(resolve => { resolveFetch = resolve; });
};
global.window = { setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
const settle = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  await hooks.refreshLogStatus();
  assert.equal(fetches, 0, "a hidden tab never starts a journal query");
  hidden = false;
  const stale = hooks.refreshLogStatus(); await settle();
  assert.equal(fetches, 1);
  hooks.setLogFollowing(false);
  assert.equal(button.attrs["aria-pressed"], "false");
  assert.equal(banner.hidden, true, "pausing never exposes a connection warning");
  resolveFetch({ ok: true, text: async () => "fragment" });
  await stale;
  assert.equal(replacements, 0, "a response started before pause is fenced out");
  await hooks.refreshLogStatus();
  assert.equal(fetches, 1, "pause suppresses subsequent journal queries");
  process.stdout.write("ok");
})().catch(error => { console.error(error); process.exitCode = 1; });''',
            "log-follow-fence.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_temporarily_unavailable_log_fragment_recovers_without_full_page_reload(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let hidden = false, fetches = 0, statusReplacements = 0, pageReplacements = 0;
const banner = { hidden: true };
const button = {
  disabled: false,
  textContent: "Pause live updates",
  attrs: { "aria-pressed": "true" },
  getAttribute(name) { return this.attrs[name]; },
  setAttribute(name, value) { this.attrs[name] = String(value); },
};
const page = { replaceWith() { pageReplacements += 1; } };
const unavailable = {
  id: "logs-live-status",
  dataset: {
    logLiveStatus: "",
    liveFragmentUrl: "/logs/status-fragment?source=all",
    liveRefreshMode: "active",
  },
  querySelector() { return null; },
  replaceWith() { statusReplacements += 1; },
};
const healthy = {
  id: "logs-live-status",
  dataset: { logLiveStatus: "", liveRefreshMode: "active" },
  querySelector() { return null; },
  querySelectorAll() { return []; },
};
global.document = {
  readyState: "loading",
  get visibilityState() { return hidden ? "hidden" : "visible"; },
  querySelector(selector) {
    if (selector === "#logs-live-status" || selector === "[data-log-live-status]") return unavailable;
    if (selector === "[data-log-browser]") return page;
    if (selector === "#connection-banner") return banner;
    if (selector === "[data-log-follow]") return button;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString() { return { querySelector(selector) {
    return selector === "#logs-live-status" ? healthy : null;
  } }; }
};
global.fetch = async () => {
  fetches += 1;
  return { ok: true, text: async () => "healthy fragment" };
};
global.window = {
  scrollX: 0, scrollY: 0, scrollTo() {},
  setTimeout() { return 1; }, clearTimeout() {},
};
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
(async () => {
  await hooks.refreshLogStatus();
  assert.equal(fetches, 1, "recovery keeps querying the bounded fragment");
  assert.equal(statusReplacements, 1, "the unavailable status is replaced by healthy logs");
  assert.equal(pageReplacements, 0, "the complete page is never reloaded");
  assert.equal(banner.hidden, true, "source recovery does not flash a transport warning");

  hidden = true;
  await hooks.refreshLogStatus();
  assert.equal(fetches, 1, "a hidden recovery page does not query the journal");
  hidden = false;
  hooks.setLogFollowing(false);
  await hooks.refreshLogStatus();
  assert.equal(fetches, 1, "an intentional pause stops recovery queries");
  assert.equal(banner.hidden, true);
  process.stdout.write("ok");
})().catch(error => { console.error(error); process.exitCode = 1; });''',
            "log-unavailable-recovery.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_log_sse_reconnect_coalesces_replayed_invalidation_burst(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let fetches = 0;
const timers = [];
const banner = { hidden: true };
const button = {
  disabled: false,
  getAttribute(name) { return name === "aria-pressed" ? "true" : null; },
  addEventListener() {},
};
const status = {
  id: "logs-live-status",
  dataset: { logLiveStatus: "", liveFragmentUrl: "/logs/status-fragment" },
  querySelector() { return null; },
  replaceWith() {},
};
global.document = {
  readyState: "complete",
  visibilityState: "visible",
  documentElement: { classList: { add() {} } },
  querySelector(selector) {
    if (selector === "[data-nav-toggle]" || selector === "[data-library-form]") return null;
    if (selector === "[data-log-browser]") return {};
    if (selector === "[data-live-fragment-url]" || selector === "#logs-live-status" || selector === "[data-log-live-status]") return status;
    if (selector === "[data-log-follow]") return button;
    if (selector === "#connection-banner") return banner;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString() { return { querySelector() { return {
    id: "logs-live-status", dataset: { logLiveStatus: "" },
    querySelector() { return null; }, querySelectorAll() { return []; }, replaceWith() {},
  }; } }; }
};
global.fetch = async () => {
  fetches += 1;
  return { ok: true, text: async () => "fragment" };
};
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  scrollX: 0, scrollY: 0, scrollTo() {},
  setTimeout(callback, delay) { timers.push({ callback, delay }); return timers.length; },
  clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cleared = true; },
};
require(process.argv[2]);
assert.equal(stream.url, "/logs/events", "the browser reconnects to the cursor-aware route");
stream.listeners["logs.changed"]({ lastEventId: "42" });
stream.listeners["logs.changed"]({ lastEventId: "43" });
assert.equal(fetches, 0, "a replay burst is deferred and coalesced");
const coalesced = timers.find(timer => timer.delay === 100 && !timer.cleared);
assert.ok(coalesced, "a bounded coalescing refresh is scheduled");
coalesced.callback();
setImmediate(() => {
  assert.equal(fetches, 1, "one fragment request covers the replay burst");
  stream.onerror();
  assert.equal(fetches, 1, "finite SSE reconnect does not force another request");
  assert.equal(banner.hidden, true, "normal reconnect grace does not flicker a warning");
  assert.ok(timers.some(timer => timer.delay === 15000 && !timer.cleared));
  process.stdout.write("ok");
});''',
            "log-sse-replay-coalescing.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_new_log_rows_receive_local_time_without_losing_exact_datetime(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
const exact = "2026-08-21T12:00:00Z";
const time = {
  textContent: exact,
  getAttribute(name) { return name === "datetime" ? exact : null; },
};
const root = { querySelectorAll(selector) {
  assert.equal(selector, "time[data-local-time]"); return [time];
} };
global.document = { readyState: "loading", visibilityState: "hidden", addEventListener() {} };
global.window = { setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
hooks.formatLocalTimes(root);
assert.equal(time.getAttribute("datetime"), exact, "the exact RFC3339 value remains available");
assert.notEqual(time.textContent, exact, "visible time is converted for the operator locale");
process.stdout.write("ok");''',
            "log-local-time.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_keyed_reconciliation_removes_orders_and_defers_focused_nodes(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
class Node {
  constructor(key, marker = key) { this.dataset = key ? { liveKey: key } : {}; this.marker = marker; this.children = []; this.parentNode = null; this.classList = { add() {}, remove() {} }; }
  appendChild(node) { return this.insertBefore(node, null); }
  insertBefore(node, reference) { if (node.parentNode) node.parentNode.children = node.parentNode.children.filter(item => item !== node); const at = reference ? this.children.indexOf(reference) : -1; if (at < 0) this.children.push(node); else this.children.splice(at, 0, node); node.parentNode = this; return node; }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(item => item !== this); this.parentNode = null; }
  replaceWith(node) { this.parentNode.insertBefore(node, this); this.remove(); }
  contains(node) { return node === this || node?.owner === this; }
  querySelectorAll() { return []; }
}
const listeners = {};
global.document = { readyState: "loading", visibilityState: "hidden", activeElement: null, addEventListener(name, fn) { listeners[name] = fn; } };
global.window = { setTimeout(fn) { fn(); return 1; }, clearTimeout() {} };
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
assert.ok(hooks, "deterministic live-refresh hooks are available");
const current = new Node(); current.dataset.livePatch = "keyed";
const a = new Node("a", "old-a"), b = new Node("b", "old-b"), c = new Node("c", "old-c");
current.appendChild(a); current.appendChild(b); current.appendChild(c);
const replacement = new Node(); replacement.dataset.livePatch = "keyed";
replacement.appendChild(new Node("c", "new-c")); replacement.appendChild(new Node("b", "new-b")); replacement.appendChild(new Node("d", "new-d"));
document.activeElement = { owner: b };
hooks.patchKeyedContainer(current, replacement);
assert.deepEqual(current.children.map(node => node.dataset.liveKey), ["c", "b", "d"]);
assert.equal(current.children[1].marker, "old-b", "focused form is preserved temporarily");
assert.equal(a.parentNode, null, "absent keyed nodes are removed");
document.activeElement = null;
listeners.focusout({});
assert.equal(current.children[1].marker, "new-b", "focusout reconciles deferred authoritative state");
process.stdout.write("ok");''',
            "keyed-reconciliation.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_fragment_replacement_never_dims_the_replacement_root(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
const added = [], removed = [];
const current = {
  querySelectorAll() { return []; },
  replaceWith(next) { assert.equal(next, replacement); },
};
const replacement = {
  classList: {
    add(name) { added.push(name); },
    remove(name) { removed.push(name); },
  },
  querySelectorAll() { return []; },
};
global.document = {
  readyState: "loading",
  visibilityState: "visible",
  addEventListener() {},
};
global.window = {
  matchMedia() { return { matches: false }; },
  requestAnimationFrame(callback) { callback(1000); return 1; },
  setTimeout() { return 1; },
  clearTimeout() {},
};
require(process.argv[2]);
const hooks = global.__ltoLiveTestHooks;
assert.ok(hooks);
hooks.replaceLiveNode(current, replacement);
assert.deepEqual(added, [], "a refresh must not dim an entire keyed section");
assert.deepEqual(removed, [], "no root-level fade class needs cleanup");
process.stdout.write("ok");''',
            "no-fragment-dimming.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_stale_success_is_suppressed_and_job_runtime_is_patched_in_place(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let rootReplacements = 0, childReplacements = 0, resolveFetch;
const child = { dataset: { liveKey: "metrics" }, parentNode: null, classList: { add() {}, remove() {} }, contains() { return false; }, querySelectorAll() { return []; }, replaceWith(next) { childReplacements += 1; runtime.children[0] = next; next.parentNode = runtime; } };
const runtime = { dataset: { jobId: "JOB.1", livePatch: "keyed" }, children: [child], querySelectorAll() { return []; }, replaceWith() { rootReplacements += 1; }, insertBefore() {}, appendChild() {} }; child.parentNode = runtime;
const operations = { dataset: {}, replaceWith() { rootReplacements += 1; } };
global.document = { readyState: "loading", visibilityState: "visible", activeElement: null,
  querySelector(selector) { if (selector === "#operations") return operations; if (selector.includes("data-job-runtime")) return runtime; return null; }, querySelectorAll(selector) { return selector === "[data-job-runtime]" ? [runtime] : []; }, addEventListener() {} };
global.DOMParser = class { parseFromString(value) { return { querySelector(selector) { if (selector === "#operations") return { dataset: {}, replaceWith() {} }; const nextChild = { dataset: { liveKey: "metrics" }, classList: { add() {}, remove() {} }, querySelectorAll() { return []; } }; return { dataset: { jobId: "JOB.1", livePatch: "keyed" }, children: [nextChild], querySelectorAll() { return []; } }; } }; } };
global.fetch = () => new Promise(resolve => { resolveFetch = resolve; });
global.window = { setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]); const hooks = global.__ltoLiveTestHooks; assert.ok(hooks);
const settle = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  hooks.startStatusPolling(); const stale = hooks.refreshStatusFragment(); await settle(); hooks.stopStatusPolling(); resolveFetch({ ok: true, text: async () => "stale" }); await stale;
  assert.equal(rootReplacements, 0, "a stale successful Dashboard response cannot mutate DOM");
  global.fetch = () => Promise.resolve({ ok: true, text: async () => "fresh" });
  await hooks.refreshJobRuntime("JOB.1");
  assert.equal(rootReplacements, 0, "active runtime root remains stable");
  assert.equal(childReplacements, 1, "runtime keyed child is updated in place");
  process.stdout.write("ok");
})().catch(error => { console.error(error); process.exitCode = 1; });''',
            "stale-and-runtime.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_geometry_animation_finishes_authoritatively_and_skips_hidden_or_reduced(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let hidden = false, reduced = false, frames = [];
function line(points) { return { dataset: { series: "instantaneous", segmentIndex: "0", segmentEvents: "1,2" }, attrs: { points }, getAttribute(name) { return this.attrs[name]; }, setAttribute(name, value) { this.attrs[name] = value; } }; }
function root(polyline) { return { classList: { add() {}, remove() {} }, querySelectorAll(selector) { return selector.includes("polyline") ? [polyline] : []; }, replaceWith() {} }; }
global.document = { readyState: "loading", get visibilityState() { return hidden ? "hidden" : "visible"; }, addEventListener() {} };
global.window = { matchMedia() { return { matches: reduced }; }, requestAnimationFrame(fn) { frames.push(fn); return frames.length; }, setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]); const hooks = global.__ltoLiveTestHooks; assert.ok(hooks);
let oldLine = line("0,0 10,10"), newLine = line("0,10 10,20");
hooks.replaceLiveNode(root(oldLine), root(newLine));
assert.equal(newLine.attrs.points, "0.000,0.000 10.000,10.000", "geometry begins at the prior presentation state");
frames.shift()(1000);
frames.shift()(1200);
assert.equal(newLine.attrs.points, "0,10 10,20", "final server-rendered geometry is authoritative");
frames = [];
const oldMetric = { dataset: { liveNumber: "rate", value: "10" }, textContent: "10.00 MiB/s" };
const newMetric = { dataset: { liveNumber: "rate", value: "20" }, textContent: "20.00 MiB/s" };
const oldMetricRoot = { classList: { add() {}, remove() {} }, querySelectorAll(selector) { return selector.includes("data-live-number") ? [oldMetric] : []; }, replaceWith() {} };
const newMetricRoot = { classList: { add() {}, remove() {} }, querySelectorAll(selector) { return selector.includes("data-live-number") ? [newMetric] : []; }, replaceWith() {} };
hooks.replaceLiveNode(oldMetricRoot, newMetricRoot);
assert.equal(newMetric.textContent, "10.00 MiB/s", "numeric presentation begins at the prior value");
frames.shift()(2000); frames.shift()(2200);
assert.equal(newMetric.textContent, "20.00 MiB/s", "numeric presentation finishes at exact server text");
hidden = true; frames = []; oldLine = line("0,0"); newLine = line("1,1"); hooks.replaceLiveNode(root(oldLine), root(newLine)); assert.equal(frames.length, 0); assert.equal(newLine.attrs.points, "1,1");
hidden = false; reduced = true; frames = []; oldLine = line("0,0"); newLine = line("2,2"); hooks.replaceLiveNode(root(oldLine), root(newLine)); assert.equal(frames.length, 0); assert.equal(newLine.attrs.points, "2,2");
process.stdout.write("ok");''',
            "geometry-animation.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_geometry_animation_resamples_appends_and_finishes_on_midflight_policy_change(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let hidden = false, reduced = false, frames = [];
function line(points) { return { dataset: { series: "instantaneous", segmentIndex: "0", segmentEvents: "1,2" }, attrs: { points }, getAttribute(name) { return this.attrs[name]; }, setAttribute(name, value) { this.attrs[name] = value; } }; }
function root(polyline) { return { classList: { add() {}, remove() {} }, querySelectorAll(selector) { return selector.includes("polyline") ? [polyline] : []; }, replaceWith() {} }; }
global.document = { readyState: "loading", get visibilityState() { return hidden ? "hidden" : "visible"; }, addEventListener() {} };
global.window = { matchMedia() { return { matches: reduced }; }, requestAnimationFrame(fn) { frames.push(fn); return frames.length; }, setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]); const hooks = global.__ltoLiveTestHooks; assert.ok(hooks);
function begin() { const oldLine = line("0,0 10,10"); const newLine = line("0,10 10,20 20,30"); hooks.replaceLiveNode(root(oldLine), root(newLine)); return newLine; }
let animated = begin();
assert.notEqual(animated.attrs.points, "0,10 10,20 20,30", "2→3 topology starts from resampled prior geometry");
assert.equal(animated.attrs.points.split(" ").length, 3, "prior geometry is resampled to target topology");
frames.shift()(1000); frames.shift()(1200);
assert.equal(animated.attrs.points, "0,10 10,20 20,30");

frames = []; animated = begin(); frames.shift()(2000); frames.shift()(2090);
assert.equal(frames.length, 1, "midflight animation queued one continuation");
hidden = true; frames.shift()(2100);
assert.equal(animated.attrs.points, "0,10 10,20 20,30", "hidden transition finishes authoritatively");
assert.equal(frames.length, 0, "hidden transition schedules no more frames");

hidden = false; frames = []; animated = begin(); frames.shift()(3000); frames.shift()(3090);
reduced = true; frames.shift()(3100);
assert.equal(animated.attrs.points, "0,10 10,20 20,30", "reduced-motion transition finishes authoritatively");
assert.equal(frames.length, 0, "reduced-motion transition schedules no more frames");
process.stdout.write("ok");''',
            "geometry-topology-policy.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_geometry_animation_matches_real_segment_overlap_and_effective_reference(self) -> None:
        completed = self._run_node_harness(
            r'''const assert = require("node:assert/strict");
let hidden = false, reduced = false, frames = [];
function instant(points, events, index) { return { dataset: { series: "instantaneous", segmentIndex: String(index), segmentEvents: events }, attrs: { points }, getAttribute(name) { return this.attrs[name]; }, setAttribute(name, value) { this.attrs[name] = value; } }; }
function effective(y) { return { dataset: { series: "effective-reference" }, attrs: { y1: String(y), y2: String(y) }, getAttribute(name) { return this.attrs[name]; }, setAttribute(name, value) { this.attrs[name] = String(value); } }; }
function root(instants, reference = null) { return { classList: { add() {}, remove() {} }, querySelectorAll(selector) { if (selector.includes('polyline')) return instants; if (selector.includes('effective-reference')) return reference ? [reference] : []; return []; }, replaceWith() {} }; }
global.document = { readyState: "loading", get visibilityState() { return hidden ? "hidden" : "visible"; }, addEventListener() {} };
global.window = { matchMedia() { return { matches: reduced }; }, requestAnimationFrame(fn) { frames.push(fn); return frames.length; }, setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]); const hooks = global.__ltoLiveTestHooks; assert.ok(hooks);

const oldLeading = instant("0,0 10,10", "1,2", 0);
const oldRetained = instant("50,50 60,60", "10,11", 1);
const newRetained = instant("55,45 65,55 75,65", "10,11,12", 0);
hooks.replaceLiveNode(root([oldLeading, oldRetained]), root([newRetained]));
assert.equal(newRetained.attrs.points, "50.000,50.000 55.000,55.000 60.000,60.000", "rolling segment morphs only from overlapping authoritative events");
frames.shift()(1000); frames.shift()(1200);
assert.equal(newRetained.attrs.points, "55,45 65,55 75,65");

frames = [];
const unrelated = instant("80,80 90,90", "50,51", 0);
hooks.replaceLiveNode(root([oldLeading]), root([unrelated]));
assert.equal(unrelated.attrs.points, "80,80 90,90", "unrelated segments do not morph");

frames = [];
const oldReference = effective(100), newReference = effective(50);
hooks.replaceLiveNode(root([], oldReference), root([], newReference));
assert.equal(newReference.attrs.y1, "100", "effective reference starts at prior y");
frames.shift()(2000); frames.shift()(2090);
hidden = true; frames.shift()(2100);
assert.equal(newReference.attrs.y1, "50", "hidden midflight finishes effective reference authoritatively");
assert.equal(newReference.attrs.y2, "50");
assert.equal(frames.length, 0);
process.stdout.write("ok");''',
            "geometry-overlap-effective.js",
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_fallback_adapts_to_active_waiting_and_idle_fragments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-adaptive-node-") as raw:
            root = Path(raw)
            harness = root / "adaptive-timing.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let mode = "active";
let operations = {
  dataset: { liveRefreshMode: mode },
  replaceWith(next) { operations = next; mode = next.dataset.liveRefreshMode; },
};
const banner = { hidden: true };
const timers = [];
global.document = {
  readyState: "complete",
  visibilityState: "visible",
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === "#connection-banner") return banner;
    if (selector === '[data-live-refresh-mode="active"]') return mode === "active" ? operations : null;
    if (selector === '[data-live-refresh-mode="waiting"]') return mode === "waiting" ? operations : null;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString(value) {
    return { querySelector() { return {
      dataset: { liveRefreshMode: value },
      replaceWith(next) { operations = next; mode = next.dataset.liveRefreshMode; },
    }; } };
  }
};
global.fetch = () => Promise.resolve({ ok: true, text: async () => global.nextMode });
class FakeEventSource {
  constructor() { this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { timers.push({ callback, delay, cleared: false }); return timers.length; },
  clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cleared = true; },
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function fire(index) { timers[index].callback(); await settle(); await settle(); }
async function run() {
  stream.onerror();
  assert.equal(timers[0].delay, 15000, "SSE reconnect grace covers observed finite-stream reconnects");
  await fire(0);
  assert.equal(timers[1].delay, 3000, "active work polls quickly");

  global.nextMode = "waiting";
  await fire(1);
  assert.equal(mode, "waiting");
  assert.equal(timers[2].delay, 10000, "media/operator wait reduces polling");

  global.nextMode = "idle";
  await fire(2);
  assert.equal(mode, "idle");
  assert.equal(timers[3].delay, 30000, "idle or terminal work polls sparsely");
  assert.equal(banner.hidden, false);
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_fallback_failures_back_off_to_thirty_seconds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-backoff-node-") as raw:
            root = Path(raw)
            harness = root / "error-backoff.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

const operations = { dataset: { liveRefreshMode: "active" }, replaceWith() {} };
const timers = [];
global.document = {
  readyState: "complete", visibilityState: "visible",
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === '[data-live-refresh-mode="active"]') return operations;
    return null;
  },
  querySelectorAll() { return []; }, addEventListener() {},
};
global.fetch = () => Promise.reject(new Error("offline"));
class FakeEventSource { constructor() { this.listeners = {}; global.stream = this; } addEventListener(name, listener) { this.listeners[name] = listener; } }
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { timers.push({ callback, delay }); return timers.length; },
  clearTimeout() {},
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function fire(index) { timers[index].callback(); await settle(); await settle(); }
async function run() {
  stream.onerror();
  await fire(0);
  assert.equal(timers[1].delay, 3000);
  await fire(1); assert.equal(timers[2].delay, 5000);
  await fire(2); assert.equal(timers[3].delay, 10000);
  await fire(3); assert.equal(timers[4].delay, 20000);
  await fire(4); assert.equal(timers[5].delay, 30000);
  await fire(5); assert.equal(timers[6].delay, 30000);
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_hidden_tab_suspends_refresh_and_resyncs_immediately_when_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-visibility-node-") as raw:
            root = Path(raw)
            harness = root / "visibility.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let visibility = "hidden";
let operations = { dataset: { liveRefreshMode: "active" }, replaceWith(next) { operations = next; } };
const listeners = {};
const timers = [];
let fetches = 0;
global.document = {
  readyState: "complete",
  get visibilityState() { return visibility; },
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === '[data-live-refresh-mode="active"]') return operations;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener(name, listener) { listeners[name] = listener; },
};
global.DOMParser = class { parseFromString() { return { querySelector() { return { dataset: { liveRefreshMode: "active" }, replaceWith() {} }; } }; } };
global.fetch = () => { fetches += 1; return Promise.resolve({ ok: true, text: async () => "active" }); };
class FakeEventSource { constructor() { this.listeners = {}; global.stream = this; } addEventListener(name, listener) { this.listeners[name] = listener; } }
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { timers.push({ callback, delay }); return timers.length; },
  clearTimeout() {},
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.listeners["state.patch"]({ data: "{}" });
  await settle();
  assert.equal(fetches, 0, "SSE events do not fetch fragments in a hidden tab");

  stream.onerror();
  timers[0].callback();
  await settle();
  assert.equal(fetches, 0, "fallback remains suspended while hidden");
  assert.equal(timers.length, 1, "no polling timer is armed while hidden");

  visibility = "visible";
  listeners.visibilitychange();
  assert.equal(fetches, 1, "visibility restoration starts resync synchronously");
  await settle(); await settle();
  assert.equal(timers[1].delay, 3000, "adaptive fallback resumes after resync");
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_library_changed_refreshes_the_library_fragment_with_healthy_sse(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-library-node-") as raw:
            root = Path(raw)
            harness = root / "library-changed.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let libraries = {
  id: "libraries-live-status",
  dataset: { liveFragmentUrl: "/libraries/status-fragment" },
  replaceWith(next) { libraries = next; },
};
let fetches = 0;
global.document = {
  readyState: "complete", visibilityState: "visible",
  querySelector(selector) {
    if (selector === "#libraries-live-status") return libraries;
    if (selector === "[data-live-fragment-url]") return libraries;
    return null;
  },
  querySelectorAll(selector) {
    return selector === "[data-live-fragment-url]" ? [libraries] : [];
  },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString() {
    return { querySelector(selector) {
      assert.equal(selector, "#libraries-live-status");
      return { id: "libraries-live-status", dataset: libraries.dataset, replaceWith() {} };
    } };
  }
};
global.fetch = url => {
  assert.equal(url, "/libraries/status-fragment");
  fetches += 1;
  return Promise.resolve({ ok: true, text: async () => "updated" });
};
class FakeEventSource {
  constructor() { this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = { setTimeout() { return 1; }, clearTimeout() {} };
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  assert.equal(typeof stream.listeners["library.changed"], "function");
  stream.listeners["library.changed"]({ data: JSON.stringify({ id: "LIB1" }) });
  await settle(); await settle();
  assert.equal(fetches, 1, "a healthy SSE stream refreshes changed libraries");
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_healthy_sse_keeps_an_adaptive_safety_refresh_for_phase_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-safety-node-") as raw:
            root = Path(raw)
            harness = root / "healthy-safety-refresh.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let operations = { dataset: { liveRefreshMode: "active" }, replaceWith(next) { operations = next; } };
const timers = [];
let fetches = 0;
global.document = {
  readyState: "complete", visibilityState: "visible",
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === '[data-live-refresh-mode="active"]') return operations;
    return null;
  },
  querySelectorAll() { return []; }, addEventListener() {},
};
global.DOMParser = class {
  parseFromString() {
    return { querySelector() { return { dataset: { liveRefreshMode: "active" }, replaceWith() {} }; } };
  }
};
global.fetch = () => {
  fetches += 1;
  return Promise.resolve({ ok: true, text: async () => "active" });
};
class FakeEventSource {
  constructor() { this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { timers.push({ callback, delay, cleared: false }); return timers.length; },
  clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cleared = true; },
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.listeners["stream.ready"]();
  assert.equal(timers[0].delay, 3000, "healthy SSE retains an adaptive safety refresh");
  timers[0].callback();
  await settle(); await settle();
  assert.equal(fetches, 1, "phase changes without SSE events are eventually refreshed");
  assert.equal(timers[1].delay, 3000);
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_transient_safety_refresh_failure_does_not_flash_connection_banner(
        self,
    ) -> None:
        # A single failed fragment fetch while SSE remains healthy must not
        # present a connection outage that disappears with the next event.
        with tempfile.TemporaryDirectory(prefix="lto-web-safety-node-") as raw:
            root = Path(raw)
            harness = root / "transient-safety-failure.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

const operations = { dataset: { liveRefreshMode: "active" }, replaceWith() {} };
const banner = { hidden: true };
const timers = [];
global.document = {
  readyState: "complete", visibilityState: "visible",
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === "#connection-banner") return banner;
    if (selector === '[data-live-refresh-mode="active"]') return operations;
    return null;
  },
  querySelectorAll() { return []; }, addEventListener() {},
};
global.fetch = () => Promise.reject(new Error("one transient fragment failure"));
class FakeEventSource {
  constructor() { this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { timers.push({ callback, delay, cleared: false }); return timers.length; },
  clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cleared = true; },
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.listeners["stream.ready"]();
  assert.equal(timers[0].delay, 3000);
  timers[0].callback();
  await settle(); await settle();
  assert.equal(
    banner.hidden,
    true,
    "one failed safety refresh must not flash a false connection warning",
  );
  assert.equal(timers[1].delay, 5000, "the failed refresh still uses bounded retry backoff");
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_share_changed_refreshes_only_matching_status_and_coalesces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-share-node-") as raw:
            root = Path(raw)
            harness = root / "share-changed.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let status = { dataset: { shareId: "smb-media" }, replaceWith(next) { status = next; } };
const banner = { hidden: true };
const completions = [];
let fetches = 0;
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "#share-status-smb-media") return status;
    if (selector === "[data-share-id]") return status;
    if (selector === "#connection-banner") return banner;
    return null;
  },
  querySelectorAll(selector) {
    assert.equal(selector, "[data-share-id]");
    return [status];
  },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString(value) {
    return { querySelector() { return { value, dataset: { shareId: "smb-media" }, replaceWith(next) { status = next; } }; } };
  }
};
global.fetch = url => {
  assert.equal(url, "/shares/smb-media/status-fragment");
  fetches += 1;
  return new Promise(resolve => completions.push(resolve));
};
class FakeEventSource {
  constructor() { this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = { setInterval() { return 1; }, clearInterval() {} };
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  const share = {
    share_id: "smb-media",
    display_name: "SMB media",
    protocol: "smb",
    lifecycle: "active",
    desired_state: "connected",
    observed_state: "connected",
    safe_error_code: null,
    revision: 5,
    last_checked_at: "2026-08-26T10:00:00+00:00",
  };
  stream.listeners["share.changed"]({ data: JSON.stringify({ share, operation: null }) });
  stream.listeners["share.changed"]({ data: JSON.stringify({ share: {...share, revision: 6}, operation: null }) });
  await settle();
  assert.equal(fetches, 1);
  completions.shift()({ ok: true, text: async () => "first" });
  await settle(); await settle();
  assert.equal(fetches, 2);
  completions.shift()({ ok: true, text: async () => "second" });
  await settle(); await settle();
  assert.equal(status.value, "second");
  assert.equal(banner.hidden, true);
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_navigation_disclosure_closes_safely_and_restores_focus(self) -> None:
        # Removing any disclosure transition (initial close, Escape, outside
        # click, link selection, or breakpoint reset) must fail this contract.
        with tempfile.TemporaryDirectory(prefix="lto-web-nav-node-") as raw:
            root = Path(raw)
            harness = root / "navigation-disclosure.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

const listeners = {};
const mediaListeners = [];
const classNames = new Set();
const attributes = new Map();
let toggleFocusCount = 0;

const links = [
  {
    attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    removeAttribute(name) { this.attributes.delete(name); },
  },
  {
    attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    removeAttribute(name) { this.attributes.delete(name); },
  },
];
const nav = {
  hidden: false,
  querySelectorAll(selector) {
    assert.equal(selector, "a[href]");
    return links;
  },
  contains(target) { return target === links[0] || target === links[1]; },
};
const toggle = {
  hidden: false,
  setAttribute(name, value) { attributes.set(name, String(value)); },
  addEventListener(name, listener) { listeners[`toggle:${name}`] = listener; },
  contains(target) { return target === this; },
  focus() { toggleFocusCount += 1; },
};
const media = {
  matches: false,
  addEventListener(name, listener) {
    assert.equal(name, "change");
    mediaListeners.push(listener);
  },
};

global.document = {
  readyState: "complete",
  documentElement: { classList: { add(name) { classNames.add(name); } } },
  activeElement: toggle,
  querySelector(selector) {
    if (selector === "[data-nav-toggle]") return toggle;
    if (selector === "#app-navigation") return nav;
    return null;
  },
  addEventListener(name, listener) { listeners[`document:${name}`] = listener; },
};
global.window = {
  matchMedia(query) {
    assert.equal(query, "(min-width: 64rem)");
    return media;
  },
};
global.EventSource = class { constructor() { throw new Error("SSE must not start"); } };

require(process.argv[2]);

assert.equal(classNames.has("js"), true);
assert.equal(nav.hidden, true);
assert.equal(attributes.get("aria-expanded"), "false");
assert.deepEqual(links.map(link => link.attributes.get("tabindex")), ["-1", "-1"]);

listeners["toggle:click"]();
assert.equal(nav.hidden, false);
assert.equal(attributes.get("aria-expanded"), "true");
assert.deepEqual(links.map(link => link.attributes.has("tabindex")), [false, false]);

listeners["document:keydown"]({ key: "Escape", preventDefault() {} });
assert.equal(nav.hidden, true);
assert.equal(attributes.get("aria-expanded"), "false");
assert.equal(toggleFocusCount, 1);

listeners["toggle:click"]();
listeners["document:click"]({ target: {} });
assert.equal(nav.hidden, true);
assert.equal(toggleFocusCount, 2);

listeners["toggle:click"]();
listeners["document:click"]({ target: links[0] });
assert.equal(nav.hidden, true);
assert.equal(toggleFocusCount, 2);

media.matches = true;
mediaListeners[0]({ matches: true });
assert.equal(nav.hidden, false);
assert.equal(toggle.hidden, true);
assert.deepEqual(links.map(link => link.attributes.has("tabindex")), [false, false]);

media.matches = false;
mediaListeners[0]({ matches: false });
assert.equal(nav.hidden, true);
assert.equal(toggle.hidden, false);
assert.equal(attributes.get("aria-expanded"), "false");
process.stdout.write("ok");
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_short_sse_reconnect_does_not_show_false_outage_or_start_polling(
        self,
    ) -> None:
        # Finite SSE responses normally reconnect quickly, but the deployed
        # browser has shown healthy reconnect intervals up to ten seconds.
        # The UI must reserve the warning and polling fallback for a sustained
        # outage, while cancelling the grace period on the next successful open.
        with tempfile.TemporaryDirectory(prefix="lto-web-live-node-") as raw:
            root = Path(raw)
            harness = root / "live-reconnect-grace.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

const banner = { hidden: true };
let reconnectCallback = null;
const timeoutDelays = [];
const clearedTimeouts = [];
const intervalDelays = [];
const clearedIntervals = [];

global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "#operations") return {};
    if (selector === "#connection-banner") return banner;
    return null;
  },
  addEventListener() {},
};
global.fetch = () => Promise.reject(new Error("fetch must not run during grace"));
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) {
    reconnectCallback = callback;
    timeoutDelays.push(delay);
    return 22;
  },
  clearTimeout(id) { clearedTimeouts.push(id); },
  setInterval(_callback, delay) { intervalDelays.push(delay); return 77; },
  clearInterval(id) { clearedIntervals.push(id); },
};

require(process.argv[2]);

stream.onerror();
assert.equal(banner.hidden, true);
assert.deepEqual(timeoutDelays, [15000]);
assert.deepEqual(intervalDelays, []);

stream.listeners["stream.ready"]({ data: "{}" });
assert.deepEqual(clearedTimeouts, [22]);
assert.equal(banner.hidden, true);

stream.onerror();
assert.equal(typeof reconnectCallback, "function");
reconnectCallback();
assert.equal(banner.hidden, false);
assert.deepEqual(
  timeoutDelays,
  [15000, 30000, 15000, 30000],
  "healthy reconnects retain the idle safety refresh while outage polling stays delayed",
);

stream.listeners["stream.ready"]({ data: "{}" });
assert.deepEqual(clearedTimeouts, [22, 22, 22]);
assert.deepEqual(clearedIntervals, []);
assert.equal(banner.hidden, true);
process.stdout.write("ok");
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_repeated_empty_sse_open_does_not_reset_sustained_outage_grace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-live-node-") as raw:
            root = Path(raw)
            harness = root / "live-empty-sse.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

const banner = { hidden: true };
let reconnectCallback = null;
const clearedTimeouts = [];
const timeoutDelays = [];
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "#operations") return {};
    if (selector === "#connection-banner") return banner;
    return null;
  },
  addEventListener() {},
};
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback, delay) { reconnectCallback = callback; timeoutDelays.push(delay); return 22; },
  clearTimeout(id) { clearedTimeouts.push(id); },
  setInterval(_callback, delay) { intervalDelays.push(delay); return 77; },
  clearInterval() {},
};

require(process.argv[2]);
stream.onerror();
if (stream.onopen) stream.onopen();
stream.onerror();
if (stream.onopen) stream.onopen();

assert.deepEqual(clearedTimeouts, []);
assert.equal(typeof reconnectCallback, "function");
reconnectCallback();
assert.equal(banner.hidden, false);
assert.deepEqual(timeoutDelays, [15000, 30000]);
process.stdout.write("ok");
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_stale_fallback_failure_cannot_restore_banner_after_stream_ready(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-live-node-") as raw:
            root = Path(raw)
            harness = root / "live-stale-fallback.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let operations = { replaceWith(next) { operations = next; } };
const banner = { hidden: true };
const timers = [];
let rejectFetch = null;
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "#operations") return operations;
    if (selector === "#connection-banner") return banner;
    return null;
  },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString() {
    return { querySelector() { return { replaceWith() {} }; } };
  }
};
global.fetch = () => new Promise((_resolve, reject) => { rejectFetch = reject; });
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(callback) { timers.push(callback); return timers.length; },
  clearTimeout() {},
  setInterval(callback) { pollCallback = callback; return 77; },
  clearInterval() {},
};

require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.onerror();
  timers[0]();
  timers[1]();
  await settle();
  assert.equal(typeof rejectFetch, "function");
  stream.listeners["stream.ready"]({ data: "{}" });
  assert.equal(banner.hidden, true);
  rejectFetch(new Error("stale fallback failed"));
  await settle();
  await settle();
  assert.equal(banner.hidden, true);
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_overlapping_sse_patches_trigger_one_follow_up_summary_refresh(
        self,
    ) -> None:
        # Removing the pending marker loses a state patch delivered while the
        # authenticated diagnostics refresh is awaiting its response.
        with tempfile.TemporaryDirectory(prefix="lto-web-live-node-") as raw:
            root = Path(raw)
            harness = root / "live-refresh.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let summary;
const banner = { hidden: true };
function makeSummary(value) {
  return {
    value,
    replaceWith(next) { summary = next; },
  };
}
summary = makeSummary("initial");
const completions = [];
let fetches = 0;

global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "#diagnostics-runtime-summary") return summary;
    if (selector === "#connection-banner") return banner;
    return null;
  },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString(value) {
    return {
      querySelector(selector) {
        return selector === "#diagnostics-runtime-summary" ? makeSummary(value) : null;
      },
    };
  }
};
global.fetch = () => {
  fetches += 1;
  return new Promise(resolve => completions.push(resolve));
};
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; global.stream = this; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
global.EventSource = FakeEventSource;
global.window = { setInterval() { return 1; }, clearInterval() {} };

require(process.argv[2]);

const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.listeners["state.patch"]({ data: "{}" });
  await settle();
  assert.equal(fetches, 1);
  stream.listeners["state.patch"]({ data: "{}" });
  await settle();
  assert.equal(fetches, 1);

  completions.shift()({ ok: true, text: async () => "first" });
  await settle();
  await settle();
  assert.equal(fetches, 2);

  completions.shift()({ ok: true, text: async () => "second" });
  await settle();
  await settle();
  assert.equal(summary.value, "second");
  process.stdout.write(JSON.stringify({ fetches, hidden: banner.hidden }));
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_NODE),
                    str(harness),
                    str(Path("src/ltobackup/web/static/live.js").resolve()),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {"fetches": 2, "hidden": True},
            json.loads(completed.stdout),
        )

    def test_job_runtime_state_events_refresh_only_its_own_fragment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-job-runtime-node-") as raw:
            root = Path(raw)
            harness = root / "job-runtime.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let runtime = { dataset: { jobId: "JOB.1" }, replaceWith(next) { runtime = next; } };
let fetches = 0;
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "[data-job-runtime]") return runtime;
    if (selector === '[data-job-runtime][data-job-id="JOB.1"]') return runtime;
    return null;
  },
  querySelectorAll(selector) {
    if (selector === "[data-job-runtime]") return [runtime];
    return [];
  },
  addEventListener() {},
};
global.DOMParser = class { parseFromString(value) { return { querySelector() { return { value, dataset: { jobId: "JOB.1" }, replaceWith(next) { runtime = next; } }; } }; } };
global.fetch = url => { assert.equal(url, "/partials/jobs/JOB.1/runtime"); fetches += 1; return Promise.resolve({ ok: true, text: async () => "fresh" }); };
class FakeEventSource { constructor() { this.listeners = {}; global.stream = this; } addEventListener(name, listener) { this.listeners[name] = listener; } }
global.EventSource = FakeEventSource;
global.window = { setTimeout() { return 1; }, clearTimeout() {}, setInterval() { return 2; }, clearInterval() {} };
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function run() {
  stream.listeners["state.replace"]({ data: "{}" });
  await settle(); await settle();
  assert.equal(fetches, 1);
  assert.equal(runtime.value, "fresh");
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)

    def test_job_runtime_patch_coalesces_and_survives_polling_and_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lto-web-job-runtime-matrix-") as raw:
            root = Path(raw)
            harness = root / "job-runtime-matrix.js"
            harness.write_text(
                """const assert = require("node:assert/strict");

let replacementNumber = 0;
function runtimeNode(value = "initial") {
  return { dataset: { jobId: "JOB.1" }, value, replaceWith(next) { runtime = next; } };
}
let runtime = runtimeNode();
let requests = [];
let completions = [];
let eventSources = 0;
let timers = [];
let intervals = [];
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "[data-job-runtime]") return runtime;
    if (selector === '[data-job-runtime][data-job-id="JOB.1"]') return runtime;
    return null;
  },
  querySelectorAll(selector) { return selector === "[data-job-runtime]" ? [runtime] : []; },
  addEventListener() {},
};
global.DOMParser = class {
  parseFromString(value) {
    return { querySelector() { return runtimeNode(value + "-" + (++replacementNumber)); } };
  }
};
global.fetch = url => {
  assert.equal(url, "/partials/jobs/JOB.1/runtime");
  requests.push(url);
  return new Promise(resolve => completions.push(resolve));
};
class FakeEventSource {
  constructor() { this.listeners = {}; eventSources += 1; global.stream = this; }
  addEventListener(name, listener) { (this.listeners[name] ||= []).push(listener); }
}
global.EventSource = FakeEventSource;
global.window = {
  setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout() {},
  setInterval(fn) { intervals.push(fn); return intervals.length; }, clearInterval() {},
};
require(process.argv[2]);
const settle = () => new Promise(resolve => setImmediate(resolve));
async function resolveNext(text) {
  completions.shift()({ ok: true, text: async () => text });
  await settle(); await settle();
}
async function run() {
  stream.listeners["state.patch"][0]({ data: "{}" });
  stream.listeners["state.patch"][0]({ data: "{}" });
  assert.equal(requests.length, 1, "same-job patches coalesce while fetch is active");
  await resolveNext("first");
  assert.equal(requests.length, 2, "one queued job refresh follows the active request");
  await resolveNext("second");
  assert.match(runtime.value, /^second-/, "replacement becomes the live runtime node");

  timers = [];
  stream.onerror();
  assert.equal(timers.length, 1, "one reconnect grace timer is created");
  timers[0]();
  assert.equal(timers.length, 2, "fallback starts one adaptive polling timer");
  assert.equal(intervals.length, 0, "fallback does not retain a fixed interval");
  timers[1]();
  assert.equal(requests.length, 3, "polling refreshes the job runtime fragment");
  await resolveNext("poll");

  stream.listeners["state.patch"][0]({ data: "{}" });
  assert.equal(requests.length, 4, "state patch refreshes after fragment replacement");
  await resolveNext("after-replacement");
  assert.match(runtime.value, /^after-replacement-/);
  assert.equal(eventSources, 1, "runtime patches do not create duplicate EventSource objects");
  assert.equal(stream.listeners["state.patch"].length, 1, "one state listener remains installed");
  assert.equal(intervals.length, 0, "runtime patches do not add fixed intervals");
  process.stdout.write("ok");
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [str(_NODE), str(harness), str(Path("src/ltobackup/web/static/live.js").resolve())],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ok", completed.stdout)


if __name__ == "__main__":
    unittest.main()
