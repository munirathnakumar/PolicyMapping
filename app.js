'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   State
═══════════════════════════════════════════════════════════════════════════ */
const state = {
  app: '',
  mappings: [],
  orphans: [],
  manuallyRemoved: [],
  manuallyMoved: [],
  activeDomainFilter: null,  // null = show all domains
  activePolDomainFilter: null, // null = show all policy domains
};

let dragData = null;
let isDragging = false;

/* ═══════════════════════════════════════════════════════════════════════════
   DOM refs
═══════════════════════════════════════════════════════════════════════════ */
const ghost         = document.getElementById('drag-ghost');
const toastEl       = document.getElementById('toast');
const screenUpload  = document.getElementById('screen-upload');
const screenResults = document.getElementById('screen-results');

/* ═══════════════════════════════════════════════════════════════════════════
   Toast
═══════════════════════════════════════════════════════════════════════════ */
let toastTimer;
function showToast(msg, type='') {
  toastEl.textContent = msg;
  toastEl.className = 'toast show' + (type ? ' toast-'+type : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2800);
}

/* ═══════════════════════════════════════════════════════════════════════════
   File drop zones
═══════════════════════════════════════════════════════════════════════════ */
function initDropZone(dzId, inputId, labelId, onLoad) {
  const dz = document.getElementById(dzId);
  const inp = document.getElementById(inputId);
  const lbl = document.getElementById(labelId);

  const handleFile = (file) => {
    if (!file) return;
    lbl.textContent = '✓ ' + file.name;
    lbl.style.display = 'block';
    dz.classList.add('has-file');
    const reader = new FileReader();
    reader.onload = e => onLoad(e.target.result, file.name);
    reader.readAsText(file);
  };

  inp.addEventListener('change', () => handleFile(inp.files[0]));
  dz.addEventListener('dragover',  e => { e.preventDefault(); e.stopPropagation(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); e.stopPropagation();
    dz.classList.remove('drag-over');
    handleFile(e.dataTransfer.files[0]);
  });
}

initDropZone('dz-controls','file-controls','fn-controls', (text, name) => {
  window._controlsText = text; window._controlsName = name; checkBothLoaded();
});
initDropZone('dz-policies','file-policies','fn-policies', (text, name) => {
  window._policiesText = text; window._policiesName = name; checkBothLoaded();
});
initDropZone('dz-json','file-json','fn-json', (text) => {
  try { loadFromReport(JSON.parse(text)); showResults(); }
  catch(e) { alert('Could not parse JSON: ' + e.message); }
});

function checkBothLoaded() {
  if (window._controlsText && window._policiesText)
    document.getElementById('load-btn').style.display = 'flex';
}

/* ═══════════════════════════════════════════════════════════════════════════
   CSV parser
═══════════════════════════════════════════════════════════════════════════ */
function parseCSV(text) {
  const lines = text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
  if (lines.length < 2) return [];
  const header = lines[0].replace(/^\uFEFF/,'').split(',').map(h => h.trim().toLowerCase());
  return lines.slice(1).filter(l=>l.trim()).map(line => {
    const vals=[], cur={inQ:false, s:''};
    for (const ch of line) {
      if (ch==='"') cur.inQ=!cur.inQ;
      else if (ch===',' && !cur.inQ) { vals.push(cur.s.trim()); cur.s=''; }
      else cur.s += ch;
    }
    vals.push(cur.s.trim());
    const obj={};
    header.forEach((h,i) => obj[h] = vals[i]||'');
    return obj;
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   Load CSV files
═══════════════════════════════════════════════════════════════════════════ */
window.loadFiles = function() {
  const appName = document.getElementById('app-name').value.trim() || 'App';
  let controls=[], policies=[];
  try {
    controls = (window._controlsName||'').toLowerCase().endsWith('.json')
      ? JSON.parse(window._controlsText)
      : parseCSV(window._controlsText);
    policies = (window._policiesName||'').toLowerCase().endsWith('.json')
      ? JSON.parse(window._policiesText)
      : parseCSV(window._policiesText);
  } catch(e) { alert('Parse error: '+e.message); return; }

  const ctrlList = (Array.isArray(controls)?controls:[]).map((r,i) => ({
    id:        r.control_id||r.id||r.ctrl_id||r.no||`CTR-${String(i+1).padStart(3,'0')}`,
    text:      r.control_text||r.control||r.requirement||r.text||'',
    domain:    r.domain||r.security_domain||r.category||'General',
    framework: r.framework||r.standard||'',
  })).filter(c=>c.text);

  const polList = (Array.isArray(policies)?policies:[]).map((r,i) => ({
    id:          r.policy_id||r.id||r.pol_id||`POL-${String(i+1).padStart(3,'0')}`,
    name:        r.policy_name||r.policy||r.name||'',
    category:    r.category||r.type||'',
    description: r.description||r.desc||'',
    impact:      r.impact||r.impact_level||r.severity||'',
  })).filter(p=>p.name);

  loadFromReport({
    app: appName,
    control_mappings: ctrlList.map(c => ({
      control_id: c.id, control_text: c.text, domain: c.domain, framework: c.framework, matches:[]
    })),
    orphan_policies: polList.map(p => ({
      policy_id: p.id, policy_name: p.name, policy_category: p.category, description: p.description
    })),
  });
  showToast(`Loaded ${ctrlList.length} controls · ${polList.length} policies`);
  showResults();
};

/* ═══════════════════════════════════════════════════════════════════════════
   Load from JSON report
═══════════════════════════════════════════════════════════════════════════ */
function loadFromReport(report) {
  state.app = report.app || 'App';
  state.manuallyRemoved = [];
  state.manuallyMoved   = [];
  state.activeDomainFilter    = null;
  state.activePolDomainFilter = null;

  state.mappings = (report.control_mappings||[]).map(cm => ({
    ctrl: { id:cm.control_id, text:cm.control_text, domain:cm.domain||'General', framework:cm.framework||'' },
    matches: (cm.matches||[]).map(m => ({
      pol: { id:m.policy_id, name:m.policy_name, category:m.policy_category||'',
             description:m.description||'', impact:m.impact||'' },
      coverage:    m.coverage||'PARTIAL',
      source:      m.match_source||'domain_paired',
      removed:     false,
      manual:      false,
    })),
  }));

  state.orphans = (report.orphan_policies||[]).map(p => ({
    id: p.policy_id, name: p.policy_name, category: p.policy_category||'',
    description: p.description||'', fromReport: true,
  }));
}

/* ═══════════════════════════════════════════════════════════════════════════
   Navigation
═══════════════════════════════════════════════════════════════════════════ */
function showResults() {
  screenUpload.classList.remove('active');
  screenResults.classList.add('active');
  document.getElementById('btn-new').style.display = 'block';
  render();
}
window.resetToUpload = function() {
  screenResults.classList.remove('active');
  screenUpload.classList.add('active');
  document.getElementById('btn-new').style.display = 'none';
};
window.runWithSample = function() {
  document.getElementById('app-name').value = 'Salesforce';
  loadFromReport(SAMPLE_REPORT);
  showResults();
};

/* ═══════════════════════════════════════════════════════════════════════════
   Derived data helpers
═══════════════════════════════════════════════════════════════════════════ */
function getStandardDomains() {
  return [...new Set(state.mappings.map(cm => cm.ctrl.domain))].sort();
}

function getPolicyDomains() {
  const cats = new Set();
  state.mappings.forEach(cm => cm.matches.forEach(m => {
    if (m.pol.category) cats.add(m.pol.category);
  }));
  state.orphans.forEach(p => { if(p.category) cats.add(p.category); });
  state.manuallyRemoved.forEach(r => { if(r.polCat) cats.add(r.polCat); });
  return [...cats].sort();
}

function filteredMappings() {
  return state.mappings.filter(cm => {
    if (state.activeDomainFilter && cm.ctrl.domain !== state.activeDomainFilter) return false;
    return true;
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   Main render
═══════════════════════════════════════════════════════════════════════════ */
function render() {
  renderToolbar();
  renderFilters();
  renderMain();
  renderOrphans();
  setupGlobalDrop();
}

/* ── Toolbar ─────────────────────────────────────────────────────────────── */
function renderToolbar() {
  document.getElementById('toolbar-app').textContent = state.app;
  let full=0,partial=0,indirect=0,removed=0,cross=0;
  state.mappings.forEach(cm => cm.matches.forEach(m => {
    if(m.removed){removed++;return;}
    if(m.coverage==='FULL') full++;
    else if(m.coverage==='PARTIAL') partial++;
    else indirect++;
    if(m.source==='cross_domain') cross++;
  }));
  const totalOrphans = state.orphans.length + state.manuallyRemoved.length;

  document.getElementById('stat-chips').innerHTML = [
    full     ? `<span class="stat-chip chip-full">${full} FULL</span>` : '',
    partial  ? `<span class="stat-chip chip-partial">${partial} PARTIAL</span>` : '',
    indirect ? `<span class="stat-chip chip-indirect">${indirect} INDIRECT</span>` : '',
    cross    ? `<span class="stat-chip chip-cross">${cross} cross-domain</span>` : '',
    removed  ? `<span class="stat-chip chip-removed">${removed} removed</span>` : '',
    `<span class="stat-chip chip-orphan">${totalOrphans} orphan</span>`,
  ].join('');
}

/* ── Filter bar ──────────────────────────────────────────────────────────── */
function renderFilters() {
  const bar = document.getElementById('filter-bar');
  const stdDomains = getStandardDomains();
  const polDomains = getPolicyDomains();

  bar.innerHTML = `
    <div class="filter-section">
      <span class="filter-label">Standard domain:</span>
      <div class="filter-chips">
        <span class="filter-chip ${!state.activeDomainFilter?'active':''}"
              onclick="setDomainFilter(null)">All</span>
        ${stdDomains.map(d => `
          <span class="filter-chip ${state.activeDomainFilter===d?'active':''}"
                onclick="setDomainFilter('${escA(d)}_STD')">
            ${escH(d)}
          </span>`).join('')}
      </div>
    </div>
    <div class="filter-section">
      <span class="filter-label">Policy domain:</span>
      <div class="filter-chips">
        <span class="filter-chip ${!state.activePolDomainFilter?'active':''}"
              onclick="setPolDomainFilter(null)">All</span>
        ${polDomains.map(d => `
          <span class="filter-chip ${state.activePolDomainFilter===d?'active':''}"
                onclick="setPolDomainFilter('${escA(d)}_POL')">
            ${escH(d)}
          </span>`).join('')}
      </div>
    </div>
  `;
}

window.setDomainFilter = function(key) {
  if (!key) { state.activeDomainFilter = null; }
  else {
    const d = key.replace('_STD','');
    const domains = getStandardDomains();
    // find actual domain name from escaped key
    state.activeDomainFilter = domains.find(x => escA(x)+'_STD' === key) || null;
  }
  render();
};

window.setPolDomainFilter = function(key) {
  if (!key) { state.activePolDomainFilter = null; }
  else {
    const polDomains = getPolicyDomains();
    state.activePolDomainFilter = polDomains.find(x => escA(x)+'_POL' === key) || null;
  }
  render();
};

/* ── Main results ────────────────────────────────────────────────────────── */
function renderMain() {
  const domainMap = {};
  const visible = filteredMappings();
  visible.forEach(cm => {
    const d = cm.ctrl.domain || 'General';
    if (!domainMap[d]) domainMap[d] = [];
    domainMap[d].push(cm);
  });

  const main = document.getElementById('results-main');
  main.innerHTML = '';

  if (Object.keys(domainMap).length === 0) {
    main.innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px;">No controls match the current filter.</div>`;
    return;
  }

  Object.entries(domainMap).forEach(([domain, controls]) => {
    const covered = controls.filter(cm =>
      cm.matches.some(m => !m.removed && matchesPolDomainFilter(m))
    ).length;
    const pct = controls.length ? Math.round(covered/controls.length*100) : 0;
    const pctClass = pct>=80?'pct-full':pct>=50?'pct-partial':'pct-low';

    const block = document.createElement('div');
    block.className = 'domain-block';
    block.innerHTML = `
      <div class="domain-header">
        <span class="domain-name">${escH(domain)}</span>
        <div class="domain-meta">
          <span>${covered}/${controls.length} covered</span>
          <span class="domain-pct ${pctClass}">${pct}%</span>
        </div>
      </div>
    `;

    controls.forEach(cm => block.appendChild(buildCtrlRow(cm)));
    main.appendChild(block);
  });
}

function matchesPolDomainFilter(m) {
  if (!state.activePolDomainFilter) return true;
  return (m.pol.category||'') === state.activePolDomainFilter;
}

/* ── Control row ─────────────────────────────────────────────────────────── */
function buildCtrlRow(cm) {
  const div = document.createElement('div');
  div.className = 'ctrl-row';
  div.id = `ctrl-row-${cm.ctrl.id}`;

  // Filter matches by policy domain filter
  const visibleMatches = state.activePolDomainFilter
    ? cm.matches.filter(m => matchesPolDomainFilter(m))
    : cm.matches;
  const activeVisible = visibleMatches.filter(m => !m.removed);
  const n = activeVisible.length;
  const countClass = n>0?'count-ok':'count-none';
  const countLabel = n>0 ? `${n} match${n!==1?'es':''}` : 'no match';

  div.innerHTML = `
    <div class="ctrl-header" onclick="toggleCtrl('${escA(cm.ctrl.id)}')">
      <span class="ctrl-id">${escH(cm.ctrl.id)}</span>
      <span class="ctrl-text">${escH(cm.ctrl.text)}</span>
      <div class="ctrl-right">
        <span class="ctrl-match-count ${countClass}">${countLabel}</span>
        <span class="ctrl-chevron" id="chev-${escA(cm.ctrl.id)}">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9,18 15,12 9,6"/></svg>
        </span>
      </div>
    </div>
    <div class="policies-list" id="pols-${escA(cm.ctrl.id)}">
      <div id="polcards-${escA(cm.ctrl.id)}">${buildPolicyCards(cm, visibleMatches)}</div>
      <div class="drop-strip" id="drop-${escA(cm.ctrl.id)}">↓ Drop a policy here to assign</div>
    </div>
  `;
  return div;
}

function buildPolicyCards(cm, visibleMatches) {
  if (!visibleMatches || visibleMatches.length === 0) {
    if (state.activePolDomainFilter) {
      return `<div class="no-match-msg">No policies in this policy domain match. <a href="#" onclick="setPolDomainFilter(null);return false;" style="color:var(--info);">Clear filter</a></div>`;
    }
    return `<div class="no-match-msg">No policies matched — drag from orphan panel to assign.</div>`;
  }

  return visibleMatches.map(m => {
    const cls = [
      'policy-card',
      m.removed      ? 'removed'      : '',
      m.source==='cross_domain' ? 'cross-domain' : '',
      m.manual       ? 'manual-assign' : '',
    ].filter(Boolean).join(' ');

    const covCls  = m.manual ? 'badge-manual' : `badge-${m.coverage}`;
    const dotCls  = m.manual ? 'dot-manual'   : `dot-${m.coverage}`;

    return `
      <div class="${cls}" id="pc-${escA(cm.ctrl.id)}-${escA(m.pol.id)}"
           draggable="${!m.removed}"
           ondragstart="onCardDragStart(event,'${escA(cm.ctrl.id)}','${escA(m.pol.id)}')"
           ondragend="onDragEnd()">
        <span class="cov-dot ${dotCls}"></span>
        <div class="pol-body">
          <div class="pol-meta">
            <span class="pol-id">${escH(m.pol.id)}</span>
            <span class="cov-badge ${covCls}">${m.manual?'MANUAL':escH(m.coverage)}</span>
            ${m.pol.category ? `<span class="pol-cat-badge">${escH(m.pol.category)}</span>` : ''}
            ${m.source==='cross_domain' ? `<span class="cross-label">↕ cross-domain</span>` : ''}
            ${m.removed ? `<span class="badge-removed">REMOVED</span>` : ''}
          </div>
          <div class="pol-name">${escH(m.pol.name)}</div>
          ${m.pol.description ? `<div class="pol-desc">${escH(m.pol.description.slice(0,120))}${m.pol.description.length>120?'…':''}</div>` : ''}
          ${m.removed ? `<div class="removed-label">✕ Removed — will appear in orphan sheet on download</div>` : ''}
        </div>
        <div class="pol-actions">
          ${!m.removed
            ? `<button class="icon-btn remove" title="Mark as wrong mapping"
                 onclick="event.stopPropagation();removeMapping('${escA(cm.ctrl.id)}','${escA(m.pol.id)}')">
                 <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
               </button>`
            : `<button class="icon-btn restore" title="Restore mapping"
                 onclick="event.stopPropagation();restoreMapping('${escA(cm.ctrl.id)}','${escA(m.pol.id)}')">
                 <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="1,4 1,10 7,10"/><path d="M3.51 15a9 9 0 1 0 .49-4.88"/></svg>
               </button>`
          }
        </div>
      </div>
    `;
  }).join('');
}

/* ── Orphan panel ────────────────────────────────────────────────────────── */
function renderOrphans() {
  const all = [
    ...state.orphans.map(p => ({...p, manuallyRemoved:false})),
    ...state.manuallyRemoved.map(r => ({
      id:r.polId, name:r.polName, category:r.polCat||'', manuallyRemoved:true
    })),
  ];

  // Apply policy domain filter to orphans too
  const visible = state.activePolDomainFilter
    ? all.filter(p => p.category === state.activePolDomainFilter)
    : all;

  document.getElementById('orphan-count').textContent = all.length;

  document.getElementById('orphan-list').innerHTML = visible.map(p => `
    <div class="orphan-chip ${p.manuallyRemoved?'manually-removed':''}"
         id="orp-${escA(p.id)}" draggable="true"
         ondragstart="onOrphanDragStart(event,'${escA(p.id)}','${escJS(p.name)}','${escJS(p.category||'')}',${p.manuallyRemoved})"
         ondragend="onDragEnd()">
      <span class="chip-name">${escH(p.name)}</span>
      ${p.category ? `<span class="chip-cat">${escH(p.category)}</span>` : ''}
      ${p.manuallyRemoved ? `<span class="chip-removed-label">Manually removed</span>` : ''}
    </div>
  `).join('') || `<div style="padding:12px;font-size:12px;color:var(--text3);font-style:italic;">No orphans in this policy domain.</div>`;
}

/* ── Toggle ──────────────────────────────────────────────────────────────── */
window.toggleCtrl = function(ctrlId) {
  const pols  = document.getElementById(`pols-${ctrlId}`);
  const chev  = document.getElementById(`chev-${ctrlId}`);
  const strip = document.getElementById(`drop-${ctrlId}`);
  const open  = pols.classList.toggle('open');
  chev.classList.toggle('open', open);
  if (strip) strip.classList.toggle('visible', open);
};

/* ═══════════════════════════════════════════════════════════════════════════
   Mutation actions
═══════════════════════════════════════════════════════════════════════════ */
window.removeMapping = function(ctrlId, polId) {
  const cm = state.mappings.find(c=>c.ctrl.id===ctrlId);
  if (!cm) return;
  const m = cm.matches.find(x=>x.pol.id===polId);
  if (!m||m.removed) return;
  m.removed = true;
  state.manuallyRemoved.push({ctrlId, polId, polName:m.pol.name, polCat:m.pol.category});
  showToast(`"${m.pol.name}" marked wrong — moved to orphans`, 'warn');
  render();
  setTimeout(()=>openCtrl(ctrlId), 50);
};

window.restoreMapping = function(ctrlId, polId) {
  const cm = state.mappings.find(c=>c.ctrl.id===ctrlId);
  if (!cm) return;
  const m = cm.matches.find(x=>x.pol.id===polId);
  if (!m) return;
  m.removed = false;
  state.manuallyRemoved = state.manuallyRemoved.filter(r=>!(r.ctrlId===ctrlId&&r.polId===polId));
  showToast('Mapping restored');
  render();
  setTimeout(()=>openCtrl(ctrlId), 50);
};

function openCtrl(ctrlId) {
  const pols = document.getElementById(`pols-${ctrlId}`);
  if (pols && !pols.classList.contains('open')) toggleCtrl(ctrlId);
}

function assignPolicy(ctrlId, polId, polName, polCat, polDesc, fromOrphan, fromCtrlId) {
  const cm = state.mappings.find(c=>c.ctrl.id===ctrlId);
  if (!cm) return;

  const existing = cm.matches.find(m=>m.pol.id===polId);
  if (existing) {
    existing.removed = false;
    state.manuallyRemoved = state.manuallyRemoved.filter(r=>!(r.ctrlId===ctrlId&&r.polId===polId));
  } else {
    cm.matches.push({
      pol:{id:polId,name:polName,category:polCat,description:polDesc||''},
      coverage:'PARTIAL', source:'manual', removed:false, manual:true,
    });
  }

  if (fromOrphan) {
    state.orphans = state.orphans.filter(p=>p.id!==polId);
    state.manuallyRemoved = state.manuallyRemoved.filter(r=>r.polId!==polId);
  } else if (fromCtrlId && fromCtrlId !== ctrlId) {
    const src = state.mappings.find(c=>c.ctrl.id===fromCtrlId);
    if (src) {
      const m = src.matches.find(x=>x.pol.id===polId);
      if (m) m.removed = true;
      state.manuallyRemoved.push({ctrlId:fromCtrlId, polId, polName, polCat});
    }
    state.manuallyMoved.push({fromCtrlId, toCtrlId:ctrlId, polId});
  }

  showToast(`"${polName}" assigned to ${ctrlId}`);
  render();
  setTimeout(()=>openCtrl(ctrlId), 50);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Drag & drop
═══════════════════════════════════════════════════════════════════════════ */
window.onCardDragStart = function(e, ctrlId, polId) {
  if (e.target.closest('.icon-btn')) { e.preventDefault(); return; }
  const cm = state.mappings.find(c=>c.ctrl.id===ctrlId);
  const m  = cm&&cm.matches.find(x=>x.pol.id===polId);
  if (!m||m.removed) { e.preventDefault(); return; }
  dragData = {type:'card', ctrlId, polId, name:m.pol.name, cat:m.pol.category||'', desc:m.pol.description||''};
  ghost.textContent = m.pol.name;
  ghost.style.opacity = '1';
  isDragging = true;
  e.dataTransfer.effectAllowed = 'move';
  showDropStrips();
};

window.onOrphanDragStart = function(e, polId, polName, polCat, isManual) {
  dragData = {type:'orphan', polId, name:polName, cat:polCat, fromOrphan:true};
  ghost.textContent = polName;
  ghost.style.opacity = '1';
  isDragging = true;
  e.dataTransfer.effectAllowed = 'copy';
  showDropStrips();
};

window.onDragEnd = function() {
  dragData = null; isDragging = false;
  ghost.style.opacity = '0';
  document.querySelectorAll('.dragging').forEach(el=>el.classList.remove('dragging'));
  document.querySelectorAll('.drag-over').forEach(el=>el.classList.remove('drag-over'));
  hideDropStrips();
};

function showDropStrips() {
  document.querySelectorAll('.drop-strip').forEach(el => {
    if (el.closest('.policies-list.open')) el.classList.add('visible');
  });
}
function hideDropStrips() {
  document.querySelectorAll('.drop-strip').forEach(el=>el.classList.remove('visible'));
}

function setupGlobalDrop() {
  document.querySelectorAll('.drop-strip').forEach(strip => {
    const ctrlId = strip.id.replace('drop-','');
    strip.addEventListener('dragover',  e=>{e.preventDefault();strip.classList.add('drag-over');});
    strip.addEventListener('dragleave', ()=>strip.classList.remove('drag-over'));
    strip.addEventListener('drop', e=>{
      e.preventDefault(); strip.classList.remove('drag-over');
      if (!dragData) return;
      assignPolicy(ctrlId, dragData.polId, dragData.name, dragData.cat, dragData.desc||'', dragData.fromOrphan, dragData.ctrlId);
    });
  });

  document.querySelectorAll('.policies-list').forEach(list => {
    const ctrlId = list.id.replace('pols-','');
    list.addEventListener('dragover',  e=>e.preventDefault());
    list.addEventListener('drop', e=>{
      e.preventDefault();
      if (!dragData) return;
      assignPolicy(ctrlId, dragData.polId, dragData.name, dragData.cat, dragData.desc||'', dragData.fromOrphan, dragData.ctrlId);
    });
  });
}

document.addEventListener('mousemove', e => {
  if (isDragging) {
    ghost.style.left = (e.clientX+16)+'px';
    ghost.style.top  = (e.clientY-10)+'px';
  }
});

/* ═══════════════════════════════════════════════════════════════════════════
   Excel download modal
═══════════════════════════════════════════════════════════════════════════ */
const ALL_SHEETS = [
  { id:'Summary',          label:'Summary',           desc:'KPI counts + domain coverage table' },
  { id:'Control Mappings', label:'Control Mappings',   desc:'Every control → matched policies' },
  { id:'Policy Mappings',  label:'Policy Mappings',    desc:'Every policy → matched controls' },
  { id:'Uncovered Controls',label:'Uncovered Controls',desc:'Controls with no matching policy' },
  { id:'Orphan Policies',  label:'Orphan Policies',    desc:'Policies not required by any control (inc. removed)' },
  { id:'Removed Mappings', label:'Removed Mappings',   desc:'Mappings marked wrong in this review' },
  { id:'Relationships',    label:'Relationships',      desc:'1:1, 1:many, many:1, many:many' },
  { id:'One-to-Many',      label:'One-to-Many',        desc:'Controls with multiple policy matches' },
  { id:'Mind Map',         label:'Mind Map',           desc:'Visual tree: Domain → Control → Policies' },
  { id:'Domain Graph',     label:'Domain Graph',       desc:'Security domain → Policy domain → Policies' },
];

// Track which sheets are selected
let selectedSheets = new Set(ALL_SHEETS.map(s=>s.id));

window.downloadExcel = function() {
  document.getElementById('sheet-modal').classList.add('open');
  renderSheetModal();
};

function renderSheetModal() {
  const list = document.getElementById('sheet-list');
  list.innerHTML = ALL_SHEETS.map(s => `
    <label class="sheet-item" for="sheet-${escA(s.id)}">
      <input type="checkbox" id="sheet-${escA(s.id)}"
             ${selectedSheets.has(s.id)?'checked':''}
             onchange="toggleSheet('${escJS(s.id)}', this.checked)">
      <div class="sheet-item-body">
        <span class="sheet-item-name">${escH(s.label)}</span>
        <span class="sheet-item-desc">${escH(s.desc)}</span>
      </div>
    </label>
  `).join('');

  updateSelectAllState();
}

window.toggleSheet = function(sheetId, checked) {
  if (checked) selectedSheets.add(sheetId);
  else         selectedSheets.delete(sheetId);
  updateSelectAllState();
};

window.toggleSelectAll = function(checked) {
  if (checked) ALL_SHEETS.forEach(s => selectedSheets.add(s.id));
  else         ALL_SHEETS.forEach(s => selectedSheets.delete(s.id));
  renderSheetModal();
};

function updateSelectAllState() {
  const cb = document.getElementById('select-all-sheets');
  if (!cb) return;
  const n = selectedSheets.size;
  cb.indeterminate = n > 0 && n < ALL_SHEETS.length;
  cb.checked = n === ALL_SHEETS.length;
}

window.closeSheetModal = function() {
  document.getElementById('sheet-modal').classList.remove('open');
};

window.confirmDownloadExcel = function() {
  const sheets = ALL_SHEETS.map(s=>s.id).filter(id => selectedSheets.has(id));
  if (sheets.length === 0) { showToast('Select at least one sheet', 'warn'); return; }

  closeSheetModal();
  showToast('Generating Excel…');

  const report = buildFinalReport();

  // Try server first
  const ctrl = new AbortController();
  const fetchTimer = setTimeout(() => ctrl.abort(), 20000);

  fetch('/api/export', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({report, sheets}),
    signal: ctrl.signal,
  })
  .then(r => {
    clearTimeout(fetchTimer);
    if (!r.ok) {
      return r.text().then(t => { throw new Error(t || r.statusText); });
    }
    const ct = r.headers.get('Content-Type') || '';
    if (!ct.includes('spreadsheet') && !ct.includes('octet')) {
      throw new Error('Server returned unexpected content-type: ' + ct);
    }
    return r.blob();
  })
  .then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (state.app.replace(/\s+/g,'_') || 'report') + '_reviewed.xlsx';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    showToast('Excel downloaded with full formatting ✓');
  })
  .catch(err => {
    clearTimeout(fetchTimer);
    const isOffline = err.name === 'AbortError' || err.message.includes('Failed to fetch')
                   || err.message.includes('NetworkError') || err.message.includes('abort');
    if (isOffline) {
      console.warn('Server not reachable — falling back to CSV. Start server.py for Excel.');
      downloadCSVFallback(sheets, report);
    } else {
      console.error('Export error:', err);
      showToast('Export error: ' + err.message, 'warn');
      downloadCSVFallback(sheets, report);
    }
  });
};

/* CSV fallback when server not running */
function downloadCSVFallback(sheets, report) {
  const rows = [];
  rows.push([`SSPM Policy Mapper — ${state.app}`]);
  rows.push([`Reviewed: ${new Date().toISOString().slice(0,10)}`]);
  rows.push([`Note: Run "python server.py" to get full Excel with formatting`]);
  rows.push([]);

  if (sheets.includes('Summary')) {
    rows.push(['=== SUMMARY ===']);
    const s = report.summary || {};
    Object.entries(s).forEach(([k,v]) => rows.push([k,v]));
    rows.push([]);
  }

  if (sheets.includes('Control Mappings')) {
    rows.push(['=== CONTROL MAPPINGS ===']);
    rows.push(['Control ID','Control Text','Domain','Policy ID','Policy Name','Policy Category','Coverage','Match Source']);
    (report.control_mappings||[]).forEach(cm => {
      if (cm.matches.length) cm.matches.forEach(m=>rows.push([cm.control_id,cm.control_text,cm.domain,m.policy_id,m.policy_name,m.policy_category,m.coverage,m.match_source||'']));
      else rows.push([cm.control_id,cm.control_text,cm.domain,'','','','UNCOVERED','']);
    });
    rows.push([]);
  }

  if (sheets.includes('Orphan Policies')) {
    rows.push(['=== ORPHAN POLICIES (including removed) ===']);
    rows.push(['Policy ID','Policy Name','Policy Category','Reason']);
    (report.orphan_policies||[]).forEach(p=>rows.push([p.policy_id,p.policy_name,p.policy_category||'',p.reason||'']));
    rows.push([]);
  }

  if (sheets.includes('Removed Mappings')) {
    rows.push(['=== REMOVED MAPPINGS ===']);
    rows.push(['Control ID','Policy ID','Policy Name','Reason']);
    (report.control_mappings||[]).forEach(cm=>(cm.removed_mappings||[]).forEach(r=>rows.push([cm.control_id,r.policy_id,r.policy_name,r.reason||''])));
  }

  const csv = rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download = `${state.app.replace(/\s+/g,'_')}_reviewed.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  showToast('CSV downloaded (start server.py for full Excel)','warn');
}

/* ═══════════════════════════════════════════════════════════════════════════
   JSON download
═══════════════════════════════════════════════════════════════════════════ */
window.downloadJSON = function() {
  const report = buildFinalReport();
  const blob = new Blob([JSON.stringify(report,null,2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.app.replace(/\s+/g,'_')}_reviewed.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
  showToast('JSON downloaded');
};

/* ═══════════════════════════════════════════════════════════════════════════
   Build final report
═══════════════════════════════════════════════════════════════════════════ */
function buildFinalReport() {
  let full=0,partial=0,indirect=0,covered=0,uncovered=0;
  state.mappings.forEach(cm=>{
    const active = cm.matches.filter(m=>!m.removed);
    if(active.length) covered++; else uncovered++;
    active.forEach(m=>{
      if(m.coverage==='FULL') full++;
      else if(m.coverage==='PARTIAL') partial++;
      else indirect++;
    });
  });

  const orphanPolicies = [
    ...state.orphans.map(p => ({
      policy_id:p.id, policy_name:p.name, policy_category:p.category||'',
      reason:'No org control maps to this OOTB policy',
    })),
    ...state.manuallyRemoved.map(r => ({
      policy_id:r.polId, policy_name:r.polName, policy_category:r.polCat||'',
      reason:'Manually removed — wrongly mapped (reviewer correction)',
    })),
  ];

  return {
    app:               state.app,
    review_status:     'reviewed',
    reviewed_at:       new Date().toISOString(),
    manual_removals:   state.manuallyRemoved.length,
    manual_assignments:state.manuallyMoved.length,
    summary: {
      total_controls:    state.mappings.length,
      covered_controls:  covered,
      uncovered_controls:uncovered,
      total_policies:    orphanPolicies.length + state.mappings.reduce((s,cm)=>s+cm.matches.filter(m=>!m.removed).length,0),
      orphan_policies:   orphanPolicies.length,
      full_matches:  full,
      partial_matches:   partial,
      indirect_matches:  indirect,
    },
    control_mappings: state.mappings.map(cm => ({
      control_id:   cm.ctrl.id,
      control_text: cm.ctrl.text,
      domain:       cm.ctrl.domain,
      framework:    cm.ctrl.framework,
      risk_level:   cm.ctrl.risk_level || '',
      subdomain:    cm.ctrl.subdomain  || '',
      is_covered:   cm.matches.some(m=>!m.removed),
      matches: cm.matches.filter(m=>!m.removed).map(m => ({
        policy_id:         m.pol.id,
        policy_name:       m.pol.name,
        policy_category:   m.pol.category,
        coverage:          m.coverage,
        similarity_score:  m.similarity_score || 0,
        match_source:      m.source,
        description:       m.pol.description || '',
        impact:            m.pol.impact || '',
        manually_assigned: m.manual || false,
      })),
      removed_mappings: cm.matches.filter(m=>m.removed).map(m => ({
        policy_id:       m.pol.id,
        policy_name:     m.pol.name,
        policy_category: m.pol.category || '',
        reason:          'Manually removed by reviewer — wrong mapping',
      })),
    })),
    orphan_policies: orphanPolicies,
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Escape helpers
═══════════════════════════════════════════════════════════════════════════ */
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escA(s){return String(s||'').replace(/[^a-zA-Z0-9_-]/g,'_');}
function escJS(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"');}

/* ═══════════════════════════════════════════════════════════════════════════
   Sample data
═══════════════════════════════════════════════════════════════════════════ */
const SAMPLE_REPORT = {
  app: 'Salesforce',
  control_mappings: [
    { control_id:'IAM-001', domain:'Identity and Access Management', framework:'ISO 27001',
      control_text:'All SaaS applications must be federated using SSO in alignment with org IAM Standards', risk_level:'HIGH',
      matches:[
        {policy_id:'SF-SSO',    policy_name:'Enable SSO',    policy_category:'Identity', coverage:'FULL',    match_source:'domain_paired', description:'Enforce SSO via SAML for all users.', impact:'HIGH'},
        {policy_id:'SF-DOM',    policy_name:'Enforce Authentication Through Custom Domain', policy_category:'Identity', coverage:'PARTIAL', match_source:'domain_paired', description:'Require custom domain to enforce SSO flows.', impact:'HIGH'},
      ]},
    { control_id:'IAM-002', domain:'Identity and Access Management', framework:'ISO 27001',
      control_text:'Multi-Factor Authentication must be enforced for all user accounts', risk_level:'HIGH',
      matches:[
        {policy_id:'SF-MFA',     policy_name:'Physical Security Key Authentication', policy_category:'MFA', coverage:'FULL',     match_source:'domain_paired', description:'Require FIDO2 hardware security keys for phishing-resistant MFA.', impact:'HIGH'},
        {policy_id:'SF-PASS',    policy_name:'Enable Authenticator Passwordless Login', policy_category:'MFA', coverage:'PARTIAL', match_source:'domain_paired', description:'Allow Lightning Login as a passwordless MFA option.', impact:'MEDIUM'},
        {policy_id:'SF-SMS',     policy_name:'Identity Verification with SMS', policy_category:'MFA', coverage:'INDIRECT', match_source:'domain_paired', description:'SMS second factor for identity verification.', impact:'LOW'},
      ]},
    { control_id:'IAM-003', domain:'Identity and Access Management', framework:'ISO 27001',
      control_text:'Conditional and geofencing access controls must adhere to org Global IAM Standards', risk_level:'HIGH',
      matches:[
        {policy_id:'SF-IP',      policy_name:'Trusted IP Ranges Configuration', policy_category:'Access Control', coverage:'PARTIAL', match_source:'domain_paired', description:'Restrict Salesforce to approved IP ranges.', impact:'HIGH'},
        {policy_id:'SF-HIPROF',  policy_name:'High Privilege Profile IP Restriction', policy_category:'Access Control', coverage:'PARTIAL', match_source:'domain_paired', description:'IP restrictions on admin profiles.', impact:'HIGH'},
        {policy_id:'SF-TLS',     policy_name:'Remote Endpoints without TLS', policy_category:'Access Control', coverage:'INDIRECT', match_source:'cross_domain', description:'Recommends TLS-secured remote site callouts.', impact:'HIGH'},
      ]},
    { control_id:'IAM-004', domain:'Identity and Access Management', framework:'ISO 27001',
      control_text:'Session management controls must adhere to org IAM standards', risk_level:'MEDIUM',
      matches:[
        {policy_id:'SF-SES',     policy_name:'Inactive Sessions Logout Timeout', policy_category:'Access Control', coverage:'FULL',    match_source:'domain_paired', description:'Auto-logout after inactivity.', impact:'MEDIUM'},
        {policy_id:'SF-SESLOCK', policy_name:'Lock Sessions to Domain', policy_category:'Access Control', coverage:'PARTIAL', match_source:'domain_paired', description:'Bind sessions to originating domain.', impact:'MEDIUM'},
      ]},
    { control_id:'IAM-005', domain:'Identity and Access Management', framework:'ISO 27001',
      control_text:'Account lockout thresholds must align with org IAM Standards', risk_level:'MEDIUM',
      matches:[
        {policy_id:'SF-LOCK',    policy_name:'Lockout interval', policy_category:'Password Management', coverage:'FULL', match_source:'domain_paired', description:'Configure lockout duration.', impact:'MEDIUM'},
        {policy_id:'SF-INVLD',   policy_name:'Invalid Login Attempts', policy_category:'Password Management', coverage:'FULL', match_source:'domain_paired', description:'Max failed login attempts before lockout.', impact:'MEDIUM'},
      ]},
    { control_id:'DP-001', domain:'Data Protection', framework:'ISO 27001',
      control_text:'All data in transit must be encrypted per Cryptography and Key Management Standards', risk_level:'HIGH',
      matches:[
        {policy_id:'SF-TLS',     policy_name:'Remote Endpoints without TLS', policy_category:'Access Control', coverage:'FULL',    match_source:'cross_domain', description:'TLS for all remote site callouts — in-transit encryption.', impact:'HIGH'},
        {policy_id:'SF-EDGE',    policy_name:'Remote Sites Protocol (HTTP/S) Security', policy_category:'Access Control', coverage:'PARTIAL', match_source:'cross_domain', description:'Enforces HTTPS-only for remote integrations.', impact:'HIGH'},
      ]},
    { control_id:'AC-001', domain:'Access Control', framework:'ISO 27001',
      control_text:'Access for all identities must adhere to least privilege principle', risk_level:'HIGH',
      matches:[
        {policy_id:'SF-PRIV',    policy_name:'Restrict Customers and Partners API Access', policy_category:'Permissions', coverage:'FULL',    match_source:'domain_paired', description:'Limit external API access to minimum required.', impact:'HIGH'},
        {policy_id:'SF-CONNLMT', policy_name:'Limit Connected Apps to Specific Profiles', policy_category:'Permissions', coverage:'PARTIAL', match_source:'domain_paired', description:'Restrict OAuth apps to specific permission sets.', impact:'HIGH'},
      ]},
  ],
  orphan_policies: [
    {policy_id:'SF-SEC',   policy_name:'Security check',            policy_category:'Secure Baseline'},
    {policy_id:'SF-DORM',  policy_name:'Dormant Users',             policy_category:'Access Control'},
    {policy_id:'SF-SELF',  policy_name:'Self Registration For Digital Workspace Site', policy_category:'Access Control'},
    {policy_id:'SF-SOSL',  policy_name:'Disable SOSL Search on Custom Settings', policy_category:'Permissions'},
    {policy_id:'SF-PUBR',  policy_name:'Public Report Folders Accessible By All Users', policy_category:'Permissions'},
  ]
};
