// CSP-friendly replacement for inline onsubmit confirm() handlers.
document.addEventListener("submit", function (e) {
  const form = e.target.closest("form[data-confirm]");
  if (form && !window.confirm(form.dataset.confirm)) {
    e.preventDefault();
  }
});
