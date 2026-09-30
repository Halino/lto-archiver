(function () {
  "use strict";

  const POLL_INTERVALS_MS = {
    active: 3000,
    waiting: 10000,
    idle: 30000,
  };
  const ERROR_BACKOFF_MS = [5000, 10000, 20000, 30000];
  const RECONNECT_GRACE_MS = 15000;
  const LOG_EVENT_COALESCE_MS = 100;
  let pollingTimer = null;
  let safetyRefreshTimer = null;
  let reconnectTimer = null;
  let fragmentRequestInFlight = false;
  let statusRefreshPending = false;
  let diagnosticSummaryRequestInFlight = false;
  let diagnosticSummaryRefreshPending = false;
  let authoritativeState = null;
  let streamUnavailable = false;
  let recoveryGeneration = 0;
  let pollingFailures = 0;
  let visibleResyncPending = false;
  let logFollowGeneration = 0;
  let logRefreshTimer = null;
  const shareRequests = new Map();
  const pendingShareRefreshes = new Set();
  const jobRuntimeRequests = new Map();
  const pendingJobRuntimeRefreshes = new Set();
  const genericFragmentRequests = new Map();
  const pendingGenericFragmentRefreshes = new Set();
  const deferredKeyedReconciliations = new Map();

  function tabIsHidden() {
    return document.visibilityState === "hidden";
  }

  function liveRefreshDelay() {
    if (document.querySelector('[data-live-refresh-mode="active"]')) {
      return POLL_INTERVALS_MS.active;
    }
    if (document.querySelector('[data-live-refresh-mode="waiting"]')) {
      return POLL_INTERVALS_MS.waiting;
    }
    return POLL_INTERVALS_MS.idle;
  }

  function initializeNavigation() {
    const toggle = document.querySelector("[data-nav-toggle]");
    const navigation = document.querySelector("#app-navigation");
    if (!toggle || !navigation || !window.matchMedia) return;

    document.documentElement.classList.add("js");
    const desktop = window.matchMedia("(min-width: 64rem)");
    const links = Array.from(navigation.querySelectorAll("a[href]"));

    function setLinksTabbable(tabbable) {
      links.forEach((link) => {
        if (tabbable) link.removeAttribute("tabindex");
        else link.setAttribute("tabindex", "-1");
      });
    }

    function setOpen(open, { returnFocus = false } = {}) {
      navigation.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      setLinksTabbable(open);
      if (!open && returnFocus) toggle.focus();
    }

    function synchronizeBreakpoint() {
      toggle.hidden = desktop.matches;
      setOpen(desktop.matches);
    }

    toggle.addEventListener("click", () => {
      if (desktop.matches) return;
      setOpen(navigation.hidden);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || desktop.matches || navigation.hidden) return;
      event.preventDefault();
      setOpen(false, { returnFocus: true });
    });
    document.addEventListener("click", (event) => {
      if (desktop.matches || navigation.hidden || toggle.contains(event.target)) return;
      const selectedLink = links.includes(event.target) ||
        (event.target.closest && event.target.closest("#app-navigation a[href]"));
      if (selectedLink) {
        setOpen(false);
        return;
      }
      if (!navigation.contains(event.target)) {
        setOpen(false, { returnFocus: true });
      }
    });
    desktop.addEventListener("change", synchronizeBreakpoint);
    synchronizeBreakpoint();
  }

  function initializeLibraryForms() {
    if (!document.querySelector("[data-library-form]")) return;
    document.querySelectorAll("[data-library-form]").forEach((form) => {
      const sourceRadios = Array.from(
        form.querySelectorAll('input[name="source_kind"]'),
      );
      const sourcePanels = Array.from(
        form.querySelectorAll("[data-library-source-panel]"),
      );

      function synchronizeSourceFields() {
        const selected = sourceRadios.find((radio) => radio.checked)?.value;
        sourcePanels.forEach((panel) => {
          const active = panel.dataset.librarySourcePanel === selected;
          panel.hidden = !active;
          panel.setAttribute("aria-hidden", String(!active));
          panel.querySelectorAll("input, select, textarea").forEach((control) => {
            control.disabled = !active;
            if (control.hasAttribute("data-required-when-active")) {
              control.required = active;
            }
          });
        });
      }

      sourceRadios.forEach((radio) => {
        radio.addEventListener("change", synchronizeSourceFields);
      });
      synchronizeSourceFields();

      const displayName = form.querySelector('input[name="display_name"]');
      const identifier = form.querySelector("[data-library-id-suggestion]");
      if (!displayName || !identifier) return;
      const advanced = form.querySelector("[data-library-advanced]");
      if (advanced && identifier.value.length === 0) advanced.open = false;
      let identifierWasEdited = identifier.value.length > 0;
      identifier.addEventListener("input", () => {
        identifierWasEdited = true;
      });
      displayName.addEventListener("input", () => {
        if (identifierWasEdited) return;
        identifier.value = displayName.value
          .normalize("NFD")
          .replace(/[\u0300-\u036f]/g, "")
          .toUpperCase()
          .replace(/[^A-Z0-9._-]+/g, "-")
          .replace(/^[._-]+|[._-]+$/g, "")
          .slice(0, 64);
      });
    });
  }

  function setConnectionBanner(visible) {
    const element = document.querySelector("#connection-banner");
    const follow = document.querySelector("[data-log-follow]");
    const logPaused = Boolean(
      follow && follow.getAttribute("aria-pressed") !== "true",
    );
    if (element) element.hidden = !visible || logPaused;
  }

  function motionIsReduced() {
    return Boolean(
      window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    );
  }

  function parseGeometryPoints(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    const numbers = value.trim().split(/[ ,]+/).map(Number);
    return numbers.length >= 2 && numbers.length % 2 === 0 && numbers.every(Number.isFinite)
      ? numbers
      : null;
  }

  function resampleGeometryPoints(points, targetLength) {
    if (!points || points.length < 2 || targetLength < 2 || targetLength % 2 !== 0) {
      return null;
    }
    const sourceCount = points.length / 2;
    const targetCount = targetLength / 2;
    if (sourceCount === targetCount) return points.slice();
    if (sourceCount === 1) {
      return Array.from({ length: targetCount }, () => [points[0], points[1]]).flat();
    }
    return Array.from({ length: targetCount }, (_unused, index) => {
      const position = targetCount === 1
        ? 0
        : (index / (targetCount - 1)) * (sourceCount - 1);
      const lower = Math.floor(position);
      const upper = Math.min(sourceCount - 1, Math.ceil(position));
      const fraction = position - lower;
      return [
        points[lower * 2] + (points[upper * 2] - points[lower * 2]) * fraction,
        points[lower * 2 + 1] +
          (points[upper * 2 + 1] - points[lower * 2 + 1]) * fraction,
      ];
    }).flat();
  }

  function segmentEventSet(line) {
    const value = line && line.dataset ? line.dataset.segmentEvents : "";
    if (typeof value !== "string" || !/^\d+(?:,\d+)*$/.test(value)) return null;
    return new Set(value.split(","));
  }

  function animateLivePresentation(current, replacement) {
    if (
      tabIsHidden() ||
      motionIsReduced() ||
      typeof window.requestAnimationFrame !== "function" ||
      typeof current.querySelectorAll !== "function" ||
      typeof replacement.querySelectorAll !== "function"
    ) return false;
    const oldLines = Array.from(
      current.querySelectorAll(
        'polyline[data-series="instantaneous"][data-segment-events]',
      ),
      (line) => ({ line, events: segmentEventSet(line), used: false }),
    );
    const animations = [];
    Array.from(
      replacement.querySelectorAll(
        'polyline[data-series="instantaneous"][data-segment-events]',
      ),
    )
      .forEach((line) => {
        const events = segmentEventSet(line);
        if (!events) return;
        let match = null;
        let maximumOverlap = 0;
        oldLines.forEach((candidate) => {
          if (candidate.used || !candidate.events) return;
          const overlap = Array.from(events).filter((event) => candidate.events.has(event)).length;
          if (overlap > maximumOverlap) {
            match = candidate;
            maximumOverlap = overlap;
          }
        });
        if (!match || maximumOverlap === 0) return;
        match.used = true;
        let start = parseGeometryPoints(match.line.getAttribute("points"));
        const end = parseGeometryPoints(line.getAttribute("points"));
        if (!start || !end) return;
        start = resampleGeometryPoints(start, end.length);
        if (!start) return;
        const target = line.getAttribute("points");
        line.setAttribute(
          "points",
          start.reduce((pairs, value, index) => {
            if (index % 2 === 0) pairs.push(`${value.toFixed(3)},`);
            else pairs[pairs.length - 1] += value.toFixed(3);
            return pairs;
          }, []).join(" "),
        );
        animations.push({ line, start, end, target });
      });
    const effectiveAnimations = [];
    const oldEffective = Array.from(
      current.querySelectorAll('line[data-series="effective-reference"]'),
    )[0];
    const newEffective = Array.from(
      replacement.querySelectorAll('line[data-series="effective-reference"]'),
    )[0];
    if (oldEffective && newEffective) {
      const startY1 = Number(oldEffective.getAttribute("y1"));
      const startY2 = Number(oldEffective.getAttribute("y2"));
      const endY1 = Number(newEffective.getAttribute("y1"));
      const endY2 = Number(newEffective.getAttribute("y2"));
      if ([startY1, startY2, endY1, endY2].every(Number.isFinite)) {
        const targetY1 = newEffective.getAttribute("y1");
        const targetY2 = newEffective.getAttribute("y2");
        newEffective.setAttribute("y1", oldEffective.getAttribute("y1"));
        newEffective.setAttribute("y2", oldEffective.getAttribute("y2"));
        effectiveAnimations.push({
          line: newEffective,
          startY1,
          startY2,
          endY1,
          endY2,
          targetY1,
          targetY2,
        });
      }
    }
    const oldNumbers = new Map(
      Array.from(current.querySelectorAll("[data-live-number][data-value]"))
        .map((node) => [node.dataset.liveNumber, node]),
    );
    const numberAnimations = [];
    Array.from(replacement.querySelectorAll("[data-live-number][data-value]"))
      .forEach((node) => {
        const old = oldNumbers.get(node.dataset.liveNumber);
        if (!old) return;
        const start = Number(old.dataset.value);
        const end = Number(node.dataset.value);
        if (!Number.isFinite(start) || !Number.isFinite(end)) return;
        const targetText = node.textContent;
        const match = targetText.match(/^(.*?)(-?\d+(?:\.(\d+))?)([^\d]*)$/);
        if (!match) return;
        node.textContent = old.textContent;
        numberAnimations.push({
          node,
          start,
          end,
          targetText,
          prefix: match[1],
          suffix: match[4],
          decimals: (match[3] || "").length,
        });
      });
    if (!animations.length && !effectiveAnimations.length && !numberAnimations.length) {
      return false;
    }
    let startedAt = null;
    const frame = (timestamp) => {
      if (tabIsHidden() || motionIsReduced()) {
        animations.forEach(({ line, target }) => line.setAttribute("points", target));
        effectiveAnimations.forEach(({ line, targetY1, targetY2 }) => {
          line.setAttribute("y1", targetY1);
          line.setAttribute("y2", targetY2);
        });
        numberAnimations.forEach(({ node, targetText }) => {
          node.textContent = targetText;
        });
        return;
      }
      if (startedAt === null) startedAt = timestamp;
      const progress = Math.min(1, Math.max(0, (timestamp - startedAt) / 180));
      animations.forEach(({ line, start, end, target }) => {
        if (progress === 1) {
          line.setAttribute("points", target);
          return;
        }
        line.setAttribute(
          "points",
          start.map((value, index) => value + (end[index] - value) * progress)
            .reduce((pairs, value, index) => {
              if (index % 2 === 0) pairs.push(`${value.toFixed(3)},`);
              else pairs[pairs.length - 1] += value.toFixed(3);
              return pairs;
            }, []).join(" "),
        );
      });
      effectiveAnimations.forEach(
        ({ line, startY1, startY2, endY1, endY2, targetY1, targetY2 }) => {
          if (progress === 1) {
            line.setAttribute("y1", targetY1);
            line.setAttribute("y2", targetY2);
            return;
          }
          line.setAttribute("y1", startY1 + (endY1 - startY1) * progress);
          line.setAttribute("y2", startY2 + (endY2 - startY2) * progress);
        },
      );
      numberAnimations.forEach(({ node, start, end, targetText, prefix, suffix, decimals }) => {
        node.textContent = progress === 1
          ? targetText
          : `${prefix}${(start + (end - start) * progress).toFixed(decimals)}${suffix}`;
      });
      if (progress < 1) window.requestAnimationFrame(frame);
    };
    window.requestAnimationFrame(frame);
    return true;
  }

  function replaceLiveNode(current, replacement) {
    const animate =
      !tabIsHidden() &&
      !motionIsReduced() &&
      typeof window.requestAnimationFrame === "function";
    if (animate) animateLivePresentation(current, replacement);
    current.replaceWith(replacement);
  }

  function validLiveKey(node) {
    const key = node && node.dataset ? node.dataset.liveKey : "";
    return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(key) ? key : null;
  }

  function validLogLiveKey(node) {
    const key = node && node.dataset ? node.dataset.liveKey : "";
    return typeof key === "string" && key.length >= 1 && key.length <= 2048 &&
      /^[\x20-\x7e]+$/.test(key) ? key : null;
  }

  function directLogChildren(container) {
    return Array.from(container.children || []).filter((node) => validLogLiveKey(node));
  }

  function patchImmutableLogContainer(current, replacement) {
    const scrollTop = Number.isFinite(current.scrollTop) ? current.scrollTop : null;
    const currentByKey = new Map(
      directLogChildren(current).map((node) => [validLogLiveKey(node), node]),
    );
    const replacementChildren = directLogChildren(replacement);
    const desiredKeys = new Set(replacementChildren.map(validLogLiveKey));
    currentByKey.forEach((node, key) => {
      if (!desiredKeys.has(key) && typeof node.remove === "function") node.remove();
    });
    replacementChildren.forEach((candidate, index) => {
      const key = validLogLiveKey(candidate);
      const live = currentByKey.get(key) || candidate;
      const reference = (current.children || [])[index] || null;
      if (reference !== live && typeof current.insertBefore === "function") {
        current.insertBefore(live, reference);
      } else if (!reference && live.parentNode !== current && typeof current.appendChild === "function") {
        current.appendChild(live);
      }
    });
    if (scrollTop !== null) current.scrollTop = scrollTop;
  }

  function isLogStatus(element) {
    return Boolean(
      element && element.dataset && element.dataset.logLiveStatus !== undefined,
    );
  }

  function logIsFollowing() {
    const control = document.querySelector("[data-log-follow]");
    return Boolean(
      control && !control.disabled && control.getAttribute("aria-pressed") === "true",
    );
  }

  function setLogFollowing(following) {
    const control = document.querySelector("[data-log-follow]");
    if (!control || control.disabled) return;
    const enabled = Boolean(following);
    control.setAttribute("aria-pressed", String(enabled));
    control.textContent = enabled ? "Pause live updates" : "Resume live updates";
    logFollowGeneration += 1;
    if (!enabled) {
      clearLogRefreshTimer();
      setConnectionBanner(false);
    }
  }

  function clearLogRefreshTimer() {
    if (logRefreshTimer === null) return;
    window.clearTimeout(logRefreshTimer);
    logRefreshTimer = null;
  }

  function scheduleLogRefresh() {
    if (tabIsHidden()) {
      visibleResyncPending = true;
      return;
    }
    if (!logIsFollowing() || logRefreshTimer !== null) return;
    logRefreshTimer = window.setTimeout(() => {
      logRefreshTimer = null;
      if (!tabIsHidden() && logIsFollowing()) void refreshLogStatus();
    }, LOG_EVENT_COALESCE_MS);
  }

  function patchLogStatus(current, replacement) {
    const currentList = typeof current.querySelector === "function"
      ? current.querySelector("[data-log-list]")
      : null;
    const replacementList = typeof replacement.querySelector === "function"
      ? replacement.querySelector("[data-log-list]")
      : null;
    if (currentList && replacementList) {
      patchImmutableLogContainer(currentList, replacementList);
      if (typeof replacementList.replaceWith === "function") {
        replacementList.replaceWith(currentList);
      }
    }
    const scrollY = Number.isFinite(window.scrollY) ? window.scrollY : null;
    current.replaceWith(replacement);
    formatLocalTimes(replacement);
    if (scrollY !== null && typeof window.scrollTo === "function") {
      window.scrollTo(window.scrollX || 0, scrollY);
    }
  }

  function formatLocalTimes(root) {
    if (!root || typeof root.querySelectorAll !== "function") return;
    Array.from(root.querySelectorAll("time[data-local-time]")).forEach((element) => {
      const exact = element.getAttribute("datetime");
      const parsed = exact ? new Date(exact) : null;
      if (parsed && !Number.isNaN(parsed.getTime())) {
        element.textContent = parsed.toLocaleString();
      }
    });
  }

  function directKeyedChildren(container) {
    return Array.from(container.children || []).filter((node) => validLiveKey(node));
  }

  function patchKeyedContainer(current, replacement) {
    if (
      !current.dataset ||
      current.dataset.livePatch !== "keyed" ||
      typeof current.querySelectorAll !== "function" ||
      typeof replacement.querySelectorAll !== "function"
    ) {
      replaceLiveNode(current, replacement);
      return;
    }
    if (replacement.dataset && replacement.dataset.liveRefreshMode) {
      current.dataset.liveRefreshMode = replacement.dataset.liveRefreshMode;
    }
    const focused = document.activeElement;
    const currentByKey = new Map(directKeyedChildren(current).map((node) => [validLiveKey(node), node]));
    const replacementChildren = directKeyedChildren(replacement);
    const desiredKeys = new Set(replacementChildren.map(validLiveKey));
    const deferred = deferredKeyedReconciliations.get(current) || new Map();
    currentByKey.forEach((live, key) => {
      if (desiredKeys.has(key)) return;
      if (focused && typeof live.contains === "function" && live.contains(focused)) {
        deferred.set(key, { node: null, index: -1 });
      } else if (typeof live.remove === "function") live.remove();
    });
    replacementChildren.forEach((next, index) => {
      const key = validLiveKey(next);
      let live = currentByKey.get(key);
      if (live && focused && typeof live.contains === "function" && live.contains(focused)) {
        deferred.set(key, { node: next, index });
      } else if (live) {
        replaceLiveNode(live, next);
        live = next;
        deferred.delete(key);
      } else {
        live = next;
        deferred.delete(key);
      }
      const reference = (current.children || [])[index] || null;
      if (reference !== live && typeof current.insertBefore === "function") {
        current.insertBefore(live, reference);
      } else if (!reference && live.parentNode !== current && typeof current.appendChild === "function") {
        current.appendChild(live);
      }
    });
    if (deferred.size) deferredKeyedReconciliations.set(current, deferred);
    else deferredKeyedReconciliations.delete(current);
  }

  function reconcileDeferredKeyedNodes() {
    deferredKeyedReconciliations.forEach((deferred, current) => {
      const focused = document.activeElement;
      deferred.forEach((pending, key) => {
        const live = directKeyedChildren(current).find((node) => validLiveKey(node) === key);
        if (live && focused && typeof live.contains === "function" && live.contains(focused)) return;
        if (pending.node === null) {
          if (live && typeof live.remove === "function") live.remove();
        } else if (live) {
          replaceLiveNode(live, pending.node);
        } else if (typeof current.appendChild === "function") {
          current.appendChild(pending.node);
        }
        const authoritative = pending.node;
        const reference = (current.children || [])[pending.index] || null;
        if (authoritative && reference !== authoritative && typeof current.insertBefore === "function") {
          current.insertBefore(authoritative, reference);
        }
        deferred.delete(key);
      });
      if (!deferred.size) deferredKeyedReconciliations.delete(current);
    });
  }

  document.addEventListener("focusout", () => {
    window.setTimeout(reconcileDeferredKeyedNodes, 0);
  });

  async function refreshStatusFragment() {
    const current = document.querySelector("#operations");
    if (!current) return true;
    if (fragmentRequestInFlight) {
      statusRefreshPending = true;
      return true;
    }
    fragmentRequestInFlight = true;
    const requestGeneration = recoveryGeneration;
    try {
      const response = await fetch("/status-fragment", {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
        cache: "no-store",
      });
      if (!response.ok) throw new Error("status fragment unavailable");
      const documentFragment = new DOMParser().parseFromString(
        await response.text(),
        "text/html",
      );
      const replacement = documentFragment.querySelector("#operations");
      if (!replacement || !current) throw new Error("invalid status fragment");
      if (requestGeneration !== recoveryGeneration) return true;
      patchKeyedContainer(current, replacement);
      setConnectionBanner(streamUnavailable);
      return true;
    } catch (_error) {
      if (requestGeneration === recoveryGeneration) {
        setConnectionBanner(streamUnavailable);
      }
      return false;
    } finally {
      fragmentRequestInFlight = false;
      if (statusRefreshPending) {
        statusRefreshPending = false;
        void refreshStatusFragment();
      }
    }
  }

  async function refreshDiagnosticSummary() {
    const current = document.querySelector("#diagnostics-runtime-summary");
    if (!current) return true;
    if (diagnosticSummaryRequestInFlight) {
      diagnosticSummaryRefreshPending = true;
      return true;
    }
    diagnosticSummaryRequestInFlight = true;
    const requestGeneration = recoveryGeneration;
    try {
      const response = await fetch("/diagnostics/summary-fragment", {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
        cache: "no-store",
      });
      if (!response.ok) throw new Error("diagnostic summary unavailable");
      const documentFragment = new DOMParser().parseFromString(
        await response.text(),
        "text/html",
      );
      const replacement = documentFragment.querySelector(
        "#diagnostics-runtime-summary",
      );
      if (!replacement) throw new Error("invalid diagnostic summary fragment");
      if (requestGeneration !== recoveryGeneration) return true;
      current.replaceWith(replacement);
      setConnectionBanner(streamUnavailable);
      return true;
    } catch (_error) {
      if (requestGeneration === recoveryGeneration) {
        setConnectionBanner(streamUnavailable);
      }
      return false;
    } finally {
      diagnosticSummaryRequestInFlight = false;
      if (diagnosticSummaryRefreshPending) {
        diagnosticSummaryRefreshPending = false;
        void refreshDiagnosticSummary();
      }
    }
  }

  async function refreshShareStatus(shareId) {
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(shareId)) return true;
    const current = document.querySelector(`#share-status-${shareId}`);
    if (!current) return true;
    if (shareRequests.has(shareId)) {
      pendingShareRefreshes.add(shareId);
      return true;
    }
    const requestGeneration = recoveryGeneration;
    const suffix = current.dataset.shareMode === "list" ? "?view=list" : "";
    const request = fetch(`/shares/${encodeURIComponent(shareId)}/status-fragment${suffix}`, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
      cache: "no-store",
    });
    shareRequests.set(shareId, request);
    try {
      const response = await request;
      if (!response.ok) throw new Error("share status unavailable");
      const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
      const replacement = parsed.querySelector(`#share-status-${shareId}`);
      if (!replacement) throw new Error("invalid share status fragment");
      const liveCurrent = document.querySelector(`#share-status-${shareId}`);
      if (liveCurrent && requestGeneration === recoveryGeneration) liveCurrent.replaceWith(replacement);
      return true;
    } catch (_error) {
      if (requestGeneration === recoveryGeneration) {
        setConnectionBanner(streamUnavailable);
      }
      return false;
    } finally {
      shareRequests.delete(shareId);
      if (pendingShareRefreshes.delete(shareId)) void refreshShareStatus(shareId);
    }
  }

  function refreshVisibleShares() {
    if (typeof document.querySelectorAll !== "function") return Promise.resolve(true);
    return Promise.all(
      Array.from(document.querySelectorAll("[data-share-id]"), (element) =>
        refreshShareStatus(element.dataset.shareId || ""),
      ),
    ).then((results) => results.every(Boolean));
  }

  function jobNodeKey(node) {
    if (node.nodeType !== 1) return String(node.nodeType);
    return [node.tagName, node.getAttribute("data-live-key") ||
      node.getAttribute("id") || node.getAttribute("action") ||
      node.getAttribute("name") || ""].join(":");
  }

  function patchJobFragment(current, replacement) {
    if (current.nodeType !== 1) {
      if (current.nodeValue !== replacement.nodeValue) current.nodeValue = replacement.nodeValue;
      return;
    }
    // Preserve edited controls and focus, even when the operator has tabbed out.
    const editable = ["INPUT", "TEXTAREA", "SELECT"].includes(current.tagName) &&
      current.getAttribute("type") !== "hidden";
    const stableToken = current.tagName === "INPUT" &&
      ["csrf", "idempotency_key"].includes(current.getAttribute("name"));
    const preserved = (name) => (editable && ["value", "checked", "selected"].includes(name)) ||
      (stableToken && name === "value");
    for (const { name } of Array.from(current.attributes)) {
      if (!preserved(name) && replacement.getAttribute(name) === null) current.removeAttribute(name);
    }
    for (const { name, value } of Array.from(replacement.attributes)) {
      if (!preserved(name) && current.getAttribute(name) !== value) current.setAttribute(name, value);
    }
    if (editable) return;
    const retained = new Set();
    Array.from(replacement.childNodes).forEach((next, index) => {
      const live = Array.from(current.childNodes).find(
        node => !retained.has(node) && jobNodeKey(node) === jobNodeKey(next),
      );
      const selected = live || next;
      if (live) patchJobFragment(live, next);
      retained.add(selected);
      const reference = current.childNodes[index] || null;
      if (reference !== selected) current.insertBefore(selected, reference);
    });
    Array.from(current.childNodes).forEach(node => {
      if (!retained.has(node)) node.remove();
    });
  }

  async function refreshJobRuntime(jobId) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(jobId)) return true;
    const selector = `[data-job-runtime][data-job-id="${jobId}"]`;
    const current = document.querySelector(selector);
    if (!current) return true;
    if (jobRuntimeRequests.has(jobId)) {
      pendingJobRuntimeRefreshes.add(jobId);
      return true;
    }
    const requestGeneration = recoveryGeneration;
    const request = fetch(current.dataset.runtimeUrl || `/partials/jobs/${encodeURIComponent(jobId)}/runtime`, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
      cache: "no-store",
    });
    jobRuntimeRequests.set(jobId, request);
    try {
      const response = await request;
      if (!response.ok) throw new Error("job runtime unavailable");
      const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
      const replacement = parsed.querySelector(selector);
      if (!replacement) throw new Error("invalid job runtime fragment");
      const liveCurrent = document.querySelector(selector);
      if (liveCurrent && requestGeneration === recoveryGeneration) {
        patchKeyedContainer(liveCurrent, replacement);
        for (const name of ["header", "summary", "source-check", "actions", "management", "retirement"]) {
          const fragmentSelector = `[data-job-fragment="${name}"]`;
          const existing = document.querySelector(fragmentSelector);
          const incoming = parsed.querySelector(fragmentSelector);
          if (existing && incoming) patchJobFragment(existing, incoming);
        }
      }
      return true;
    } catch (_error) {
      if (requestGeneration === recoveryGeneration) {
        setConnectionBanner(streamUnavailable);
      }
      return false;
    } finally {
      jobRuntimeRequests.delete(jobId);
      if (pendingJobRuntimeRefreshes.delete(jobId)) void refreshJobRuntime(jobId);
    }
  }

  function refreshVisibleJobRuntime() {
    if (typeof document.querySelectorAll !== "function") return Promise.resolve(true);
    return Promise.all(
      Array.from(document.querySelectorAll("[data-job-runtime]"), (element) =>
        refreshJobRuntime(element.dataset.jobId || ""),
      ),
    ).then((results) => results.every(Boolean));
  }

  async function refreshGenericFragment(element) {
    const fragmentId = element.id || "";
    const url = element.dataset.liveFragmentUrl || "";
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(fragmentId) || !url.startsWith("/")) {
      return true;
    }
    const logStatus = isLogStatus(element);
    if (logStatus && (tabIsHidden() || !logIsFollowing())) return true;
    if (genericFragmentRequests.has(fragmentId)) {
      pendingGenericFragmentRefreshes.add(fragmentId);
      return true;
    }
    const requestGeneration = recoveryGeneration;
    const requestLogGeneration = logFollowGeneration;
    const request = fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
      cache: "no-store",
    });
    genericFragmentRequests.set(fragmentId, request);
    try {
      const response = await request;
      if (!response.ok) throw new Error("live fragment unavailable");
      const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
      const replacement = parsed.querySelector(`#${fragmentId}`);
      if (!replacement) throw new Error("invalid live fragment");
      const current = document.querySelector(`#${fragmentId}`);
      if (
        current &&
        requestGeneration === recoveryGeneration &&
        (!logStatus || (
          requestLogGeneration === logFollowGeneration && logIsFollowing()
        ))
      ) {
        if (logStatus) patchLogStatus(current, replacement);
        else patchKeyedContainer(current, replacement);
      }
      return true;
    } catch (_error) {
      if (requestGeneration === recoveryGeneration) {
        setConnectionBanner(streamUnavailable);
      }
      return false;
    } finally {
      genericFragmentRequests.delete(fragmentId);
      if (pendingGenericFragmentRefreshes.delete(fragmentId)) {
        const current = document.querySelector(`#${fragmentId}`);
        if (current) void refreshGenericFragment(current);
      }
    }
  }

  function refreshLogStatus() {
    const current = document.querySelector("#logs-live-status");
    if (!current) return Promise.resolve(true);
    return refreshGenericFragment(current);
  }

  function refreshGenericFragments() {
    const first = document.querySelector("[data-live-fragment-url]");
    if (!first) return Promise.resolve(true);
    const elements = typeof document.querySelectorAll === "function"
      ? Array.from(document.querySelectorAll("[data-live-fragment-url]"))
      : [first];
    return Promise.all(elements.map(refreshGenericFragment)).then(
      (results) => results.every(Boolean),
    );
  }

  async function refreshLiveFragments() {
    if (tabIsHidden()) {
      visibleResyncPending = true;
      return true;
    }
    visibleResyncPending = false;
    const results = await Promise.all([
      refreshStatusFragment(),
      refreshDiagnosticSummary(),
      refreshVisibleShares(),
      refreshVisibleJobRuntime(),
      refreshGenericFragments(),
    ]);
    return results.every(Boolean);
  }

  function replaceState(state) {
    authoritativeState = state;
    void refreshLiveFragments();
  }

  function patchState(patch) {
    if (authoritativeState && patch && typeof patch === "object") {
      authoritativeState = Object.assign({}, authoritativeState, patch);
    }
    void refreshLiveFragments();
  }

  function clearPollingTimer() {
    if (pollingTimer === null) return;
    window.clearTimeout(pollingTimer);
    pollingTimer = null;
  }

  function clearSafetyRefreshTimer() {
    if (safetyRefreshTimer === null) return;
    window.clearTimeout(safetyRefreshTimer);
    safetyRefreshTimer = null;
  }

  function scheduleSafetyRefresh(delay) {
    clearSafetyRefreshTimer();
    if (
      streamUnavailable ||
      tabIsHidden() ||
      typeof window.setTimeout !== "function"
    ) return;
    safetyRefreshTimer = window.setTimeout(async () => {
      safetyRefreshTimer = null;
      const refreshed = await refreshLiveFragments();
      if (streamUnavailable) return;
      if (refreshed) {
        pollingFailures = 0;
        scheduleSafetyRefresh(liveRefreshDelay());
        return;
      }
      const backoff = ERROR_BACKOFF_MS[
        Math.min(pollingFailures, ERROR_BACKOFF_MS.length - 1)
      ];
      pollingFailures += 1;
      scheduleSafetyRefresh(backoff);
    }, delay);
  }

  function scheduleNextPoll(delay) {
    clearPollingTimer();
    if (!streamUnavailable || tabIsHidden()) return;
    pollingTimer = window.setTimeout(() => {
      pollingTimer = null;
      void pollLiveFragments();
    }, delay);
  }

  async function pollLiveFragments() {
    if (!streamUnavailable || tabIsHidden()) {
      visibleResyncPending = tabIsHidden();
      return;
    }
    const refreshed = await refreshLiveFragments();
    if (!streamUnavailable) return;
    if (refreshed) {
      pollingFailures = 0;
      scheduleNextPoll(liveRefreshDelay());
      return;
    }
    const delay = ERROR_BACKOFF_MS[Math.min(pollingFailures, ERROR_BACKOFF_MS.length - 1)];
    pollingFailures += 1;
    scheduleNextPoll(delay);
  }

  function startStatusPolling() {
    streamUnavailable = true;
    clearSafetyRefreshTimer();
    setConnectionBanner(true);
    if (pollingTimer !== null || tabIsHidden()) return;
    scheduleNextPoll(liveRefreshDelay());
  }

  function scheduleStatusPolling() {
    if (reconnectTimer !== null || streamUnavailable) return;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      startStatusPolling();
    }, RECONNECT_GRACE_MS);
  }

  function stopStatusPolling() {
    const recovered =
      streamUnavailable || reconnectTimer !== null || pollingTimer !== null;
    if (recovered) recoveryGeneration += 1;
    streamUnavailable = false;
    pollingFailures = 0;
    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    clearPollingTimer();
    setConnectionBanner(false);
    scheduleSafetyRefresh(liveRefreshDelay());
  }

  function connect() {
    if (
      !document.querySelector("#operations") &&
      !document.querySelector("#diagnostics-runtime-summary") &&
      !document.querySelector("[data-share-id]") &&
      !document.querySelector("[data-job-runtime]") &&
      !document.querySelector("[data-live-fragment-url]")
    ) return;
    const stream = new EventSource(
      document.querySelector("[data-log-browser]") ? "/logs/events" : "/events",
    );
    stream.addEventListener("state.replace", (event) => {
      try {
        const state = JSON.parse(event.data);
        stopStatusPolling();
        replaceState(state);
      } catch (_error) {
        startStatusPolling();
      }
    });
    stream.addEventListener("state.patch", (event) => {
      try {
        const patch = JSON.parse(event.data);
        stopStatusPolling();
        patchState(patch);
      } catch (_error) {
        startStatusPolling();
      }
    });
    stream.addEventListener("stream.ready", stopStatusPolling);
    stream.addEventListener("logs.changed", () => {
      stopStatusPolling();
      scheduleLogRefresh();
    });
    stream.addEventListener("share.changed", (event) => {
      try {
        const change = JSON.parse(event.data);
        stopStatusPolling();
        if (change && change.share && typeof change.share.share_id === "string") {
          if (tabIsHidden()) visibleResyncPending = true;
          else void refreshShareStatus(change.share.share_id);
        }
      } catch (_error) {
        startStatusPolling();
      }
    });
    stream.addEventListener("library.changed", (event) => {
      try {
        const change = JSON.parse(event.data);
        stopStatusPolling();
        if (!change || typeof change.id !== "string") {
          throw new Error("invalid library change");
        }
        if (tabIsHidden()) {
          visibleResyncPending = true;
          return;
        }
        const current = document.querySelector("#libraries-live-status");
        if (current) void refreshGenericFragment(current);
      } catch (_error) {
        startStatusPolling();
      }
    });
    stream.onerror = () => {
      scheduleStatusPolling();
    };
  }

  function initialize() {
    initializeNavigation();
    initializeLibraryForms();
    const logFollow = document.querySelector("[data-log-follow]");
    if (logFollow && !logFollow.disabled) {
      logFollow.addEventListener("click", () => {
        const following = logFollow.getAttribute("aria-pressed") !== "true";
        setLogFollowing(following);
        if (following && !tabIsHidden()) void refreshLogStatus();
      });
    }
    const firstLocalTime = document.querySelector("time[data-local-time]");
    if (firstLocalTime && typeof document.querySelectorAll === "function") {
      formatLocalTimes(document);
    }
    document.addEventListener("visibilitychange", () => {
      if (tabIsHidden()) {
        clearPollingTimer();
        clearSafetyRefreshTimer();
        clearLogRefreshTimer();
        visibleResyncPending = true;
        return;
      }
      if (streamUnavailable) {
        void pollLiveFragments();
      } else if (visibleResyncPending) {
        void refreshLiveFragments().then((refreshed) => {
          pollingFailures = refreshed ? 0 : pollingFailures + 1;
          const delay = refreshed
            ? liveRefreshDelay()
            : ERROR_BACKOFF_MS[
              Math.min(pollingFailures - 1, ERROR_BACKOFF_MS.length - 1)
            ];
          scheduleSafetyRefresh(delay);
        });
      }
    });
    connect();
  }

  if (typeof globalThis !== "undefined") {
    globalThis.__ltoLiveTestHooks = Object.freeze({
      patchKeyedContainer,
      patchJobFragment,
      patchImmutableLogContainer,
      refreshLogStatus,
      setLogFollowing,
      formatLocalTimes,
      replaceLiveNode,
      refreshStatusFragment,
      refreshJobRuntime,
      startStatusPolling,
      stopStatusPolling,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
