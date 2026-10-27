'use strict';
(() => {
 const root=document.querySelector('[data-monitoring]'); if(!root)return;
 const rows=()=>[...document.querySelectorAll('#history-samples tbody tr[data-at]')];
 const zone=document.getElementById('history-zone');
 const dates=()=>rows().forEach(row=>{const t=row.querySelector('time');t.textContent=new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'long',...(zone.value==='UTC'?{timeZone:'UTC'}:{})}).format(new Date(row.dataset.at));});
 zone.addEventListener('change',dates);dates();
 const svg=document.getElementById('history-chart'),ns='http://www.w3.org/2000/svg';
 function draw(){svg.replaceChildren();const points=rows().map(r=>({x:Date.parse(r.dataset.at),y:Number(r.dataset.value),gap:r.dataset.gap==='true'})).filter(p=>Number.isFinite(p.x)&&Number.isFinite(p.y));
 if(points.length){const min=Math.min(...points.map(p=>p.y)),max=Math.max(...points.map(p=>p.y));const lo=Math.min(...points.map(p=>p.x)),hi=Math.max(...points.map(p=>p.x));let prev;
 const text=document.createElementNS(ns,'text');text.setAttribute('x','8');text.setAttribute('y','20');text.textContent=`Range ${min} – ${max} (exact units and values below)`;svg.append(text);
 for(const p of points){const x=40+(p.x-lo)/Math.max(1,hi-lo)*820,y=230-(p.y-min)/Math.max(1,max-min)*190;if(prev&&!p.gap){const line=document.createElementNS(ns,'line');for(const [k,v]of Object.entries({x1:prev.x,y1:prev.y,x2:x,y2:y}))line.setAttribute(k,v);svg.append(line);}const dot=document.createElementNS(ns,'circle');dot.setAttribute('cx',x);dot.setAttribute('cy',y);dot.setAttribute('r','3');svg.append(dot);prev={x,y};}}}
 draw();
 const status=document.getElementById('live-status');
 // Reconcile displayed alert/evaluation sections from the server-rendered,
 // authorized document. Keep chart controls and rule forms intact.
 async function reconcile(){try{const response=await fetch(location.href,{cache:'no-store'});if(!response.ok)throw Error();const doc=new DOMParser().parseFromString(await response.text(),'text/html');for(const node of doc.querySelectorAll('[data-live]')){const old=root.querySelector('[data-live="'+node.dataset.live+'"]');if(old&&!old.contains(document.activeElement))old.replaceWith(node);}const samples=doc.getElementById('history-samples');if(samples)document.getElementById('history-samples').replaceWith(samples);dates();draw();status.textContent='Live state reconciled from PostgreSQL, including retained historical samples.';}catch{status.textContent='Reconciliation unavailable. Displayed evidence may be older.';}}
 const source=new EventSource(root.dataset.monitoring+'/events');source.addEventListener('reconcile',reconcile);source.onopen=()=>{status.textContent='Live connection established; reconciling PostgreSQL state.';};source.onerror=()=>{status.textContent='Live connection interrupted; reconnect will reconcile stored state.';};
 document.getElementById('refresh-monitoring').addEventListener('click',()=>location.reload());window.addEventListener('pagehide',()=>source.close());
})();
