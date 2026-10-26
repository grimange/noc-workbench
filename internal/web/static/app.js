// Progressive enhancement only; forms and security checks work without JavaScript.
function resetPendingForms() {
  document.querySelectorAll('form[data-pending]').forEach((form) => {
    form.removeAttribute('aria-busy');
    form.querySelectorAll('button[data-pending-label]').forEach((button) => {
      if (button.dataset.originalLabel) {
        button.textContent = button.dataset.originalLabel;
        delete button.dataset.originalLabel;
        button.disabled = false;
      }
    });
  });
}
document.addEventListener('submit', (event) => {
  const form = event.target;
  if (!form.matches('form[data-pending]') || event.defaultPrevented) return;
  if (form.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
    return;
  }
  form.setAttribute('aria-busy', 'true');
  form.querySelectorAll('button[data-pending-label]').forEach((button) => {
    button.dataset.originalLabel = button.textContent;
    button.textContent = button.dataset.pendingLabel;
    button.disabled = true;
  });
});
window.addEventListener('pageshow', resetPendingForms);
