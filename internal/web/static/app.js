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

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-copy]');
  if (!button) return;
  const input = document.getElementById(button.dataset.copy);
  const status = document.querySelector('[data-copy-status]');
  try {
    await navigator.clipboard.writeText(input.value);
    status.textContent = 'Command copied. No connection was executed.';
  } catch (_) {
    input.focus(); input.select();
    status.textContent = 'Select and copy the command manually.';
  }
});

const inventoryFile = document.querySelector('[data-inventory-file]');
if (inventoryFile) inventoryFile.addEventListener('change', async () => {
 const status = document.querySelector('[data-inventory-status]');
 const field = document.querySelector('[data-inventory-document]');
 const file = inventoryFile.files[0]; field.value = '';
 if (!file) return;
 if (file.size > 262144) { status.textContent = 'JSON file exceeds 256 KiB.'; return; }
 try { field.value = await file.text(); status.textContent = 'File loaded. Preview validates the complete graph.'; }
 catch { status.textContent = 'File could not be read.'; }
});
