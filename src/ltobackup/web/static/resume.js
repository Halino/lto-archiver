(function () {
  "use strict";

  const dialog = document.querySelector("#resume-confirmation");
  if (!dialog || typeof dialog.showModal !== "function") return;
  const form = document.querySelector("#resume-confirmation-form");
  const password = document.querySelector("#resume-confirmation-password");
  const error = document.querySelector("#resume-confirmation-error");
  const cancel = document.querySelector("#resume-confirmation-cancel");
  const confirm = document.querySelector("#resume-confirmation-submit");
  let source = null;
  let pending = false;
  document.documentElement.classList.add("resume-enhanced");

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
    password.focus();
  }

  document.addEventListener("submit", function (event) {
    const candidate = event.target;
    if (!candidate.matches('form[data-resume-password-required="true"]')) return;
    event.preventDefault();
    if (pending || dialog.open) return;
    source = candidate;
    password.value = "";
    const inline = source.querySelector('input[name="password"]');
    if (inline) inline.value = "";
    error.hidden = true;
    error.textContent = "";
    dialog.showModal();
    password.focus();
  });

  cancel.addEventListener("click", () => {
    if (pending) return;
    password.value = "";
    source = null;
    dialog.close();
  });
  dialog.addEventListener("cancel", event => { if (pending) event.preventDefault(); });
  dialog.addEventListener("close", () => {
    // A queued close event must not clear a newly reopened dialog.
    if (dialog.open) return;
    password.value = "";
    error.textContent = "";
    error.hidden = true;
    source = null;
  });

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (pending) return;
    if (!source || !source.isConnected || source.dataset.resumePasswordRequired !== "true") {
      password.value = "";
      showError("The job state changed. Close this window and check the current job actions.");
      return;
    }
    const target = source.getAttribute("action");
    if (!/^\/jobs\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/resume$/.test(target)) return;
    const body = new URLSearchParams(new FormData(source));
    body.set("password", password.value);
    password.value = "";
    pending = true;
    confirm.disabled = true;
    cancel.disabled = true;
    form.setAttribute("aria-busy", "true");
    error.hidden = true;
    let navigating = false;
    try {
      const response = await fetch(target, {
        method: "POST", body, credentials: "same-origin", redirect: "error",
        cache: "no-store", headers: { Accept: "application/json" },
      });
      body.delete("password");
      if (!response.headers.get("content-type")?.includes("application/json")) {
        throw new Error("unexpected response");
      }
      const result = await response.json();
      if (!response.ok) {
        showError(result.error?.message || "Resume was not accepted. Check the job status.");
        return;
      }
      const destination = target.slice(0, -"/resume".length);
      if (result.redirect !== destination) throw new Error("unexpected destination");
      navigating = true;
      window.location.assign(destination);
    } catch (_error) {
      showError("Resume could not be confirmed. Check the job status or sign in again before retrying.");
    } finally {
      body.delete("password");
      password.value = "";
      if (!navigating) {
        pending = false;
        confirm.disabled = false;
        cancel.disabled = false;
        form.removeAttribute("aria-busy");
      }
    }
  });
})();
