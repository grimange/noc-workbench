'use strict';
(() => {
 const root=document.querySelector('[data-console-events]');if(!root)return;
 const status=document.getElementById('console-live-status');let busy=false,pending=false,focusDeferred=false;
 async function reconcile(){if(busy){pending=true;return;}busy=true;
 try{const response=await fetch(location.href,{cache:'no-store'});if(!response.ok)throw Error();const doc=new DOMParser().parseFromString(await response.text(),'text/html');
 for(const node of doc.querySelectorAll('[data-console-live]')){const old=root.querySelector('[data-console-live="'+node.dataset.consoleLive+'"]');if(!old)continue;if(old.contains(document.activeElement)){focusDeferred=true;continue;}
 const opened=[...old.querySelectorAll('details')].map(d=>d.open);[...node.querySelectorAll('details')].forEach((d,i)=>d.open=!!opened[i]);old.replaceWith(node);}
 document.dispatchEvent(new Event('console:updated'));
 status.textContent=focusDeferred?'Monitoring update pending while a control has focus.':'Live monitoring evidence · times in Philippine time (PHT)';
 }catch{status.textContent='Updates unavailable; displayed evidence may be older.';}finally{busy=false;if(pending){pending=false;reconcile();}}}
 root.addEventListener('click',e=>{if(e.target.closest('[data-refresh-display]'))reconcile();});
 root.addEventListener('focusout',()=>{if(focusDeferred)queueMicrotask(()=>{focusDeferred=false;reconcile();});});
 const url=new URL(root.dataset.consoleEvents,location.origin);if(location.pathname==='/' || location.pathname==='/servers')url.search=location.search;
 const source=new EventSource(url);source.addEventListener('reconcile',reconcile);source.onerror=()=>{status.textContent='Live updates interrupted; reconnect will reconcile stored evidence.';};window.addEventListener('pagehide',()=>source.close());
})();
