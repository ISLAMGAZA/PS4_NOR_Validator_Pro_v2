let norFile = null, sysconFile = null;

function setupDropZone(id, callback) {
  const el = document.getElementById(id);
  ['dragenter','dragover'].forEach(e => el.addEventListener(e, e => { e.preventDefault(); el.classList.add('dragover'); }));
  ['dragleave','drop'].forEach(e => el.addEventListener(e, e => { e.preventDefault(); el.classList.remove('dragover'); }));
  el.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) callback(f); });
  el.addEventListener('click', () => { const inp = document.createElement('input'); inp.type = 'file';
    inp.onchange = () => { if (inp.files[0]) callback(inp.files[0]); }; inp.click(); });
}

setupDropZone('dropNor', f => { norFile = f; updateStatus('norStatus', f.name, true); document.getElementById('dropNor').classList.add('loaded'); checkReady(); });
setupDropZone('dropSyscon', f => { sysconFile = f; updateStatus('sysconStatus', f.name, true); document.getElementById('dropSyscon').classList.add('loaded'); checkReady(); });

function updateStatus(id, name, ok) {
  document.getElementById(id).innerHTML = ok ? '<span style="color:#3fb950;">✓</span> ' + name : '';
}
function checkReady() { document.getElementById('btnAnalyze').disabled = !norFile; }

document.getElementById('btnAnalyze').addEventListener('click', async () => {
  if (!norFile) return;
  const btn = document.getElementById('btnAnalyze');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  btn.disabled = true; loading.style.display = 'block'; results.style.display = 'none';

  const form = new FormData();
  form.append('nor', norFile);
  if (sysconFile) form.append('syscon', sysconFile);

  try {
    const res = await fetch('/analyze', { method: 'POST', body: form });
    const data = await res.json();
    loading.style.display = 'none'; results.style.display = 'grid';
    renderResults(data);
  } catch(e) {
    loading.style.display = 'none';
    alert('Error: ' + e.message);
  }
  btn.disabled = false;
});

function renderResults(d) {
  // NOR
  document.getElementById('norData').innerHTML =
    stat('Model', d.nor.sku) + stat('FW Version', d.nor.fw) +
    stat('Board ID', d.nor.board_id) + stat('Active Slot', d.nor.active_slot) +
    stat('MAC', d.nor.mac || 'N/A') + stat('Overall', badge(d.nor.healthy));

  // Syscon
  document.getElementById('sysconData').innerHTML = d.syscon ?
    stat('Chip', d.syscon.chip) + stat('ARV', d.syscon.arv) +
    stat('FW Area', badge(d.syscon.fw_healthy)) +
    stat('Entries', d.syscon.valid_entries) +
    stat('Severity', badge_sev(d.syscon.severity)) +
    stat('Missing Types', d.syscon.missing_types.map(t => '0x' + t.toString(16).padStart(2,'0')).join(', ') || 'None')
    : '<p style="color:var(--dim)">No syscon provided</p>';

  // Diagnosis
  let diagHtml = '';
  const diag = d.diagnosis || [];
  diag.forEach(x => { diagHtml += '<div class="diag-item diag-' + x.level + '">' +
    '<strong>' + x.title + '</strong><br>' + x.detail + '</div>'; });
  document.getElementById('diagnosisData').innerHTML = diagHtml || '<p style="color:var(--dim)">No issues detected</p>';

  // Match
  document.getElementById('matchData').innerHTML = d.syscon ?
    stat('Pair Status', d.match.status) + stat('Match Detail', d.match.detail) +
    (d.match.donors && d.match.donors.length ?
      '<br><strong>Top 3 donors:</strong><br>' + d.match.donors.slice(0,3).map(r =>
        '<div style="padding:4px 0">' + r.filename + ' <span style="color:var(--dim)">score=' + r.score + '</span></div>'
      ).join('') : '')
    : '<p style="color:var(--dim)">Upload a syscon to see matching</p>';
}

function stat(l, v) { return '<div class="stat"><span class="label">' + l + '</span><span>' + (v||'?') + '</span></div>'; }
function badge(ok) { return '<span class="badge '+(ok?'badge-ok':'badge-fail')+'">'+(ok?'HEALTHY':'ISSUE')+
  '</span>'; }
function badge_sev(s) {
  const m = {none:'badge-ok',minor:'badge-ok',moderate:'badge-warn',severe:'badge-fail',critical:'badge-fail'};
  return '<span class="badge '+(m[s]||'badge-warn')+'">'+s+'</span>';
}
