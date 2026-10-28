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
      const cells = row.cells; if (cells.length !== 4) return;
      row.hidden = !cells[0].textContent.toLowerCase().includes(q) || !!(state && row.dataset.unitActive !== state && row.dataset.unitSub !== state);
      if (!row.hidden) count++;
    });
    document.querySelector('[data-unit-count]').textContent = count + ' matching units';
  }
  window.addEventListener('hashchange', sections);
  document.addEventListener('console:updated', () => { sections(); filterUnits(); document.querySelectorAll('[data-sortable] th[aria-sort]').forEach(th => sortProcesses(th.querySelector('[data-sort]'), th.getAttribute('aria-sort') === 'descending')); limitProcesses(); });
  document.addEventListener('input', e => { if (e.target.matches('[data-unit-search]')) filterUnits(); });
  document.addEventListener('change', e => { if (e.target.matches('[data-unit-state]')) filterUnits(); });
  function limitProcesses() { document.querySelectorAll('[data-process-table]').forEach(table => { const expanded = document.querySelector('[data-process-expand]')?.getAttribute('aria-expanded') === 'true'; [...table.tBodies[0].rows].forEach((row,i) => row.hidden = !expanded && i >= 5); }); }
  document.addEventListener('click', e => {
    const expand=e.target.closest('[data-process-expand]'); if(expand){ const open=expand.getAttribute('aria-expanded')!=='true'; expand.setAttribute('aria-expanded',String(open)); expand.textContent=open?'Show top five processes':'Show up to 10 processes';limitProcesses();return; }
    const button = e.target.closest('[data-sort]'); if (!button) return;
    sortProcesses(button, button.closest('th').getAttribute('aria-sort') !== 'descending');
  });
  function sortProcesses(button, desc) {
    const table = button.closest('table'), index = Number(button.dataset.sort);
    const rows = [...table.tBodies[0].rows].filter(r => r.cells.length === 4);
    rows.sort((a,b) => {
      const x = a.cells[index].dataset.sortValue || a.cells[index].textContent;
      const y = b.cells[index].dataset.sortValue || b.cells[index].textContent;
      const order = index === 1 ? x.localeCompare(y) : parseFloat(x) - parseFloat(y);
      return (desc ? -1 : 1) * order;
    });
    table.querySelectorAll('th').forEach(th => th.removeAttribute('aria-sort'));
    button.closest('th').setAttribute('aria-sort', desc ? 'descending' : 'ascending');
    rows.forEach(row => table.tBodies[0].append(row));limitProcesses();
  }
  sections(); filterUnits();limitProcesses();
})();
