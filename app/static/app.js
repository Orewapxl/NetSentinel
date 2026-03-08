const state = {
  snapshot: null,
  history: [],
  filter: ''
};

const severityColors = {
  low: '#93c5fd',
  medium: '#f6c453',
  high: '#fb923c',
  critical: '#ff4d6d'
};
const protocolColors = ['#4f8cff', '#3fd0ff', '#28d391', '#f6c453', '#fb923c', '#ff4d6d'];

function el(id) { return document.getElementById(id); }
function fmtTime(v){ try { return new Date(v).toLocaleString('tr-TR'); } catch { return v || '-'; } }
function n(v){ return Number(v || 0); }
function escapeHtml(str){ return String(str ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
function scrollToSection(id){ document.getElementById(id)?.scrollIntoView({behavior:'smooth', block:'start'}); }
window.scrollToSection = scrollToSection;

async function fetchStats(manual=false){
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    state.snapshot = data;
    state.history.push(n(data.totals?.events));
    state.history = state.history.slice(-20);
    render(data);
    if (manual) setStatus('Snapshot yenilendi. Dashboard ayık durumda.');
  } catch (err) {
    setStatus('Stats alınamadı: ' + err);
  }
}

function render(data){
  const totals = data.totals || {};
  const protocols = data.protocols || {};
  const severities = data.severities || {};
  const events = data.recent_events || [];
  const alerts = data.recent_alerts || [];
  const eventTypes = data.event_types || {};

  el('eventsTotal').textContent = n(totals.events).toLocaleString('tr-TR');
  el('alertsTotal').textContent = n(totals.alerts).toLocaleString('tr-TR');
  el('protoTcp').textContent = n(protocols.tcp).toLocaleString('tr-TR');
  el('protoUdp').textContent = n(protocols.udp).toLocaleString('tr-TR');
  el('generatedAt').textContent = fmtTime(data.generated_at);

  const iocHits = alerts.filter(a => a.rule_id === 'TI-001').length;
  const hotAlerts = alerts.filter(a => ['high', 'critical'].includes(a.severity)).length;
  const dangerScore = Math.min(100, Math.round((hotAlerts * 12) + (iocHits * 7) + (n(totals.alerts) ? (hotAlerts / Math.max(1, n(totals.alerts))) * 30 : 0)));

  el('iocHits').textContent = iocHits;
  el('hotAlerts').textContent = hotAlerts;
  el('dangerScore').textContent = `${dangerScore}/100`;
  el('alertRate').textContent = hotAlerts > 0 ? `${hotAlerts} yüksek kritik alarm öne çıkıyor.` : 'Şimdilik çok bağıran bir şey yok.';
  el('riskFill').style.width = `${dangerScore}%`;
  el('riskLabel').textContent = dangerScore >= 75 ? 'Kırmızı bayrak seviyesi yüksek' : dangerScore >= 45 ? 'Dikkat modu açık' : 'Düşük profil';

  renderSparkline();
  renderProtocolDonut(protocols);
  renderSeverityBars(severities);
  renderTopSources(events);
  renderTopPorts(events);
  renderEventTypes(eventTypes);
  renderAlerts(alerts);
  renderEvents(events);
}

function renderSparkline(){
  const wrap = el('eventsSpark');
  wrap.innerHTML = '';
  const hist = state.history.length ? state.history : [0];
  const min = Math.min(...hist), max = Math.max(...hist);
  hist.forEach(v => {
    const span = document.createElement('span');
    const h = max === min ? 22 : Math.max(8, Math.round(((v - min) / (max - min)) * 38) + 6);
    span.style.height = `${h}px`;
    wrap.appendChild(span);
  });
}

function renderProtocolDonut(protocols){
  const entries = Object.entries(protocols).sort((a,b)=>b[1]-a[1]);
  const total = entries.reduce((s,[,v])=>s+n(v),0) || 1;
  let offset = 0;
  const parts = entries.map(([key, value], i) => {
    const pct = (n(value)/total)*100;
    const color = protocolColors[i % protocolColors.length];
    const piece = `${color} ${offset}% ${offset + pct}%`;
    offset += pct;
    return piece;
  });
  el('protocolDonut').style.background = entries.length
    ? `conic-gradient(${parts.join(',')})`
    : 'conic-gradient(rgba(255,255,255,.08) 0 100%)';

  const legend = el('protocolLegend');
  legend.innerHTML = '';
  if (!entries.length) {
    legend.innerHTML = '<div class="muted">Henüz protokol verisi yok.</div>';
    return;
  }
  entries.forEach(([key, value], i) => {
    const pct = ((n(value)/total)*100).toFixed(1);
    legend.insertAdjacentHTML('beforeend', `
      <div class="legend-item">
        <span class="legend-key"><span class="legend-dot" style="background:${protocolColors[i % protocolColors.length]}"></span>${escapeHtml(key.toUpperCase())}</span>
        <strong>${n(value)} · %${pct}</strong>
      </div>
    `);
  });
}

function renderSeverityBars(severities){
  const order = ['critical', 'high', 'medium', 'low'];
  const total = Object.values(severities).reduce((s,v)=>s+n(v),0) || 1;
  const box = el('severityBars');
  box.innerHTML = '';
  order.forEach(key => {
    const value = n(severities[key]);
    const pct = (value / total) * 100;
    box.insertAdjacentHTML('beforeend', `
      <div class="bar-row">
        <div class="legend-item"><span class="legend-key"><span class="legend-dot" style="background:${severityColors[key]}"></span>${key}</span><strong>${value}</strong></div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%; background:${severityColors[key]}"></div></div>
      </div>
    `);
  });
}

function countBy(items, selector){
  return items.reduce((acc, item) => {
    const key = selector(item);
    if (!key) return acc;
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function renderRankList(targetId, entries, formatter){
  const box = el(targetId);
  box.innerHTML = '';
  if (!entries.length) {
    box.innerHTML = '<div class="muted">Henüz veri yok.</div>';
    return;
  }
  entries.slice(0, 6).forEach(([key, value], idx) => {
    box.insertAdjacentHTML('beforeend', `
      <div class="rank-item">
        <span>${idx + 1}. ${formatter ? formatter(key) : escapeHtml(key)}</span>
        <strong>${value}</strong>
      </div>
    `);
  });
}

function renderTopSources(events){
  const entries = Object.entries(countBy(events, e => e.src_ip)).sort((a,b)=>b[1]-a[1]);
  renderRankList('topSources', entries, k => `<span class="small-code">${escapeHtml(k)}</span>`);
}

function renderTopPorts(events){
  const entries = Object.entries(countBy(events, e => e.dst_port)).sort((a,b)=>b[1]-a[1]);
  renderRankList('topPorts', entries, k => `Port <span class="small-code">${escapeHtml(k)}</span>`);
}

function renderEventTypes(eventTypes){
  const box = el('eventTypeTags');
  box.innerHTML = '';
  const entries = Object.entries(eventTypes).sort((a,b)=>b[1]-a[1]).slice(0, 8);
  if (!entries.length) {
    box.innerHTML = '<span class="muted">Henüz event türü yok.</span>';
    return;
  }
  entries.forEach(([key, value]) => {
    box.insertAdjacentHTML('beforeend', `<span class="tag">${escapeHtml(key)} · ${value}</span>`);
  });
}

function filterText(){ return (state.filter || '').trim().toLowerCase(); }
function matchesFilter(obj){
  const f = filterText();
  if (!f) return true;
  return JSON.stringify(obj).toLowerCase().includes(f);
}

function renderAlerts(alerts){
  const body = el('alertsBody');
  body.innerHTML = '';
  const rows = alerts.filter(matchesFilter).slice(0, 40);
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="muted">Filtreye uyan alarm yok.</td></tr>';
    return;
  }
  rows.forEach(a => {
    body.insertAdjacentHTML('beforeend', `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td><strong>${escapeHtml(a.rule_id)}</strong><br><span class="muted">${escapeHtml(a.title || '')}</span></td>
        <td class="${'sev-' + a.severity}">${escapeHtml(a.severity)}</td>
        <td>${n(a.score)}</td>
        <td class="small-code">${escapeHtml(a.src_ip || '-')}</td>
        <td class="small-code">${escapeHtml(a.dst_ip || '-')}</td>
        <td>${escapeHtml(a.reason || '-')}</td>
      </tr>
    `);
  });
}

function renderEvents(events){
  const body = el('eventsBody');
  body.innerHTML = '';
  const rows = events.filter(matchesFilter).slice(0, 50);
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="muted">Filtreye uyan event yok.</td></tr>';
    return;
  }
  rows.forEach(e => {
    const qh = e.query || e.http_host || e.hostname || e.http_uri || '-';
    body.insertAdjacentHTML('beforeend', `
      <tr>
        <td>${fmtTime(e.timestamp)}</td>
        <td>${escapeHtml(e.source || '-')}</td>
        <td class="small-code">${escapeHtml(e.src_ip || '-')} : ${escapeHtml(e.src_port || '-')}</td>
        <td class="small-code">${escapeHtml(e.dst_ip || '-')} : ${escapeHtml(e.dst_port || '-')}</td>
        <td>${escapeHtml((e.protocol || '-').toUpperCase())}</td>
        <td>${escapeHtml(e.event_type || '-')}</td>
        <td>${escapeHtml(qh)}</td>
      </tr>
    `);
  });
}

function setStatus(msg){ el('statusBox').textContent = msg; }

async function startSniffer(){
  try {
    const iface = el('ifaceInput').value.trim();
    const url = iface ? `/api/sniffer/start?iface=${encodeURIComponent(iface)}` : '/api/sniffer/start';
    const res = await fetch(url, { method: 'POST' });
    const data = await res.json();
    setStatus(data.message + (data.iface ? ` (${data.iface})` : ''));
    fetchStats();
  } catch (err) { setStatus('Sniffer başlatılamadı: ' + err); }
}
window.startSniffer = startSniffer;

async function stopSniffer(){
  try {
    const res = await fetch('/api/sniffer/stop', { method: 'POST' });
    const data = await res.json();
    setStatus(data.message);
  } catch (err) { setStatus('Sniffer durdurulamadı: ' + err); }
}
window.stopSniffer = stopSniffer;

async function reloadIntel(){
  try {
    const res = await fetch('/api/intel/reload', { method: 'POST' });
    const data = await res.json();
    setStatus(`Threat intel yenilendi. IP IOC=${data.ip_ioc_count}, domain IOC=${data.domain_ioc_count}`);
    fetchStats();
  } catch (err) { setStatus('Intel yenilenemedi: ' + err); }
}
window.reloadIntel = reloadIntel;

async function uploadJsonl(){
  const file = el('jsonFile').files?.[0];
  if (!file) { setStatus('Önce bir JSONL dosyası seç. Boş form bile seni kandırmasın.'); return; }
  try {
    const form = new FormData();
    form.append('file', file);
    setStatus('JSONL ingest başladı...');
    const res = await fetch('/api/ingest/jsonl', { method: 'POST', body: form });
    const data = await res.json();
    setStatus(`İçe aktarma bitti. İşlenen=${data.processed}, hata=${data.errors}`);
    fetchStats();
  } catch (err) {
    setStatus('JSONL yüklenemedi: ' + err);
  }
}
window.uploadJsonl = uploadJsonl;

async function exportJson(kind){
  const url = kind === 'alerts' ? '/api/export/alerts' : '/api/export/events';
  const res = await fetch(url);
  const data = await res.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `netsentinel_${kind}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  setStatus(`${kind} export hazır.`);
}
window.exportJson = exportJson;

function applyFilter(){
  state.filter = el('globalFilter').value || '';
  if (state.snapshot) {
    renderAlerts(state.snapshot.recent_alerts || []);
    renderEvents(state.snapshot.recent_events || []);
  }
}
window.applyFilter = applyFilter;

function connectWs(){
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    el('socketBadge').textContent = 'WS bağlı';
    ws.send('ping');
  };
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'alert') {
        setStatus(`Yeni alarm: ${msg.data?.rule_id || 'unknown'} · ${msg.data?.severity || '-'}`);
        fetchStats();
      }
    } catch {}
  };
  ws.onclose = () => {
    el('socketBadge').textContent = 'WS reconnect';
    setTimeout(connectWs, 2000);
  };
  ws.onerror = () => { el('socketBadge').textContent = 'WS sorunlu'; };
}

fetchStats();
setInterval(fetchStats, 5000);
connectWs();
