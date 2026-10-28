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

// Local presentation preferences never change collection or authorization.
(() => {
  const theme = document.querySelector('[data-theme-toggle]');
  function setTheme(dark) {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    if (theme) { theme.textContent = dark ? 'Light theme' : 'Dark theme'; theme.setAttribute('aria-pressed', String(dark)); }
  }
  try { setTheme(localStorage.getItem('noc-theme') === 'dark'); } catch (_) { setTheme(false); }
  if (theme) theme.addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme !== 'dark'; setTheme(dark);
    try { localStorage.setItem('noc-theme', dark ? 'dark' : 'light'); } catch (_) {}
  });
  function sections() {
    const links = [...document.querySelectorAll('[data-tab-link]')];
    if (!links.length) return;
    const selected = links.find(a => a.hash === location.hash)?.dataset.tabLink || 'services';
    links.forEach(a => { if (a.dataset.tabLink === selected) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current'); });
    document.querySelectorAll('[data-console-tab]').forEach(p => { p.hidden = p.dataset.consoleTab !== selected; });
  }
  function filterUnits() {
    const table = document.querySelector('[data-unit-table]'); if (!table) return;
    const q = document.querySelector('[data-unit-search]').value.trim().toLowerCase();
    const state = document.querySelector('[data-unit-state]').value;
    let count = 0;
    table.querySelectorAll('tbody tr').forEach(row => {
      const cells = row.cells; if (cells.length !== 5) return;
      row.hidden = !cells[0].textContent.toLowerCase().includes(q) || !!(state && cells[2].textContent !== state && cells[3].textContent !== state);
      if (!row.hidden) count++;
    });
    document.querySelector('[data-unit-count]').textContent = count + ' matching units';
  }
  window.addEventListener('hashchange', sections);
  document.addEventListener('console:updated', () => { sections(); filterUnits(); });
  document.addEventListener('input', e => { if (e.target.matches('[data-unit-search]')) filterUnits(); });
  document.addEventListener('change', e => { if (e.target.matches('[data-unit-state]')) filterUnits(); });
  document.addEventListener('click', e => {
    const button = e.target.closest('[data-sort]'); if (!button) return;
    const table = button.closest('table'), index = Number(button.dataset.sort);
    const desc = button.closest('th').getAttribute('aria-sort') !== 'descending';
    const rows = [...table.tBodies[0].rows].filter(r => r.cells.length === 4);
    rows.sort((a,b) => {
      const x = a.cells[index].dataset.sortValue || a.cells[index].textContent;
      const y = b.cells[index].dataset.sortValue || b.cells[index].textContent;
      const order = index === 1 ? x.localeCompare(y) : parseFloat(x) - parseFloat(y);
      return (desc ? -1 : 1) * order;
    });
    table.querySelectorAll('th').forEach(th => th.removeAttribute('aria-sort'));
    button.closest('th').setAttribute('aria-sort', desc ? 'descending' : 'ascending');
    rows.forEach(row => table.tBodies[0].append(row));
  });
  sections(); filterUnits();
})();
