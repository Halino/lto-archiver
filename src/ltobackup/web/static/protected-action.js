(() => {
  "use strict";
  const dialog = document.getElementById("protected-confirmation");
  if (!dialog || typeof dialog.showModal !== "function") return;
  const password = dialog.querySelector("#protected-password");
  const confirmation = dialog.querySelector("form");
  const description = dialog.querySelector("[data-protected-action-description]");
  const forms = [...document.querySelectorAll("form[data-protected-action]")];
  let selected = null;
  let approved = null;
  let pending = false;

  const clear = () => {
    password.value = "";
    selected = null;
  };
  forms.forEach((form) => {
    if (!/^\/critical-recovery\/[A-Za-z0-9][A-Za-z0-9._:%-]{0,383}\/(reconcile|abandon|authorize-replacement)$/.test(form.getAttribute("action"))) return;
    const inline = form.querySelector('input[name="password"]');
    if (inline) {
      inline.required = false;
      form.classList.add("protected-enhanced");
    }
    form.addEventListener("submit", (event) => {
      if (pending) { event.preventDefault(); return; }
      if (inline && approved !== form) {
        event.preventDefault();
        if (dialog.open) return;
        selected = form;
        description.textContent = form.dataset.protectedAction;
        password.value = "";
        dialog.showModal();
        password.focus();
        return;
      }
      approved = null;
      pending = true;
      forms.forEach((item) => item.querySelectorAll('button[type="submit"]').forEach((button) => { button.disabled = true; }));
      // Native submission preserves CSRF, proof and idempotency. No automatic retry.
    });
  });
  confirmation.addEventListener("submit", (event) => {
    event.preventDefault();
    if (pending || !selected || !selected.isConnected || !password.value) return;
    const form = selected;
    form.querySelector('input[name="password"]').value = password.value;
    approved = form;
    clear();
    dialog.close();
    form.requestSubmit();
    form.querySelector('input[name="password"]').value = "";
  });
  dialog.querySelector("[data-protected-cancel]").addEventListener("click", () => { clear(); dialog.close(); });
  dialog.addEventListener("cancel", clear);
  dialog.addEventListener("close", clear);
  window.addEventListener("pageshow", () => {
    pending = false;
    approved = null;
    clear();
    if (dialog.open) dialog.close();
    forms.forEach((form) => {
      const inline = form.querySelector('input[name="password"]');
      if (inline) inline.value = "";
      form.querySelectorAll('button[type="submit"]').forEach((button) => { button.disabled = false; });
    });
  });
})();
