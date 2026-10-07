const API_BASE = (window.CTI_API_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '');
const IOC_LIMIT = 50;
const pageState = { skip: 0, total: 0, search: '', source: 'All' };
const byId = (id) => document.getElementById(id);

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `${response.status} ${response.statusText}`);
  return body;
}
function validHttps(raw) { try { const u = new URL(raw); return u.protocol === 'https:' ? u.href : null; } catch { return null; } }
function sourceAnchor(url, label = 'Open source ↗') {
  const a = document.createElement('a'); const target = validHttps(url);
  if (!target) { a.textContent = 'Source link unavailable'; a.className = 'source-unavailable'; return a; }
  a.href = target; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = label; return a;
}
function setText(element, text) { if (element) element.textContent = text; }

async function loadSources() {
  const holder = byId('source-list'); if (!holder) return;
  holder.textContent = 'Loading verified source inventory…';
  try {
    const data = await request('/api/sources'); const rows = data.sources || []; holder.replaceChildren();
    const totals = data.totals || {};
    byId('source-summary').replaceChildren();
    for (const [label, value] of [['Threat feed records', totals.threat_feed_items], ['Unique MISP events', totals.unique_misp_events], ['Data feed records', totals.datafeed_records], ['VirusTotal lookups', totals.virustotal_lookups]]) {
      const card = document.createElement('div'); card.className = 'metric-card';
      const title = document.createElement('div'); title.className = 'metric-label'; title.textContent = label.toUpperCase();
      const count = document.createElement('div'); count.className = 'metric-value'; count.textContent = Number(value || 0).toLocaleString(); card.append(title, count); byId('source-summary').append(card);
    }
    for (const row of rows) {
      const card = document.createElement('article'); card.className = 'source-card';
      const top = document.createElement('div'); top.className = 'source-card-top';
      const heading = document.createElement('h2'); heading.textContent = row.name;
      const kind = document.createElement('span'); kind.className = `source-kind ${row.kind === 'data feed' ? 'data-kind' : 'misp-kind'}`; kind.textContent = row.kind;
      top.append(heading, kind);
      const count = document.createElement('div'); count.className = 'source-record-count'; count.textContent = Number(row.count || 0).toLocaleString();
      const label = document.createElement('div'); label.className = 'source-record-label'; label.textContent = row.record_label || 'records';
      const description = document.createElement('p'); description.className = 'source-description'; description.textContent = row.description || 'Verified threat intelligence source.';
      const actions = document.createElement('div'); actions.className = 'source-actions';
      actions.append(sourceAnchor(row.url, 'Open original source ↗'));
      const feedLink = document.createElement('a'); feedLink.className = 'btn secondary'; feedLink.href = `index.html?source=${encodeURIComponent(row.name)}`; feedLink.textContent = 'View feed records';
      actions.append(feedLink); card.append(top, count, label, description, actions); holder.append(card);
    }
  } catch (error) { holder.textContent = `Could not load source inventory: ${error.message}`; }
}

async function loadIocs() {
  const holder = byId('ioc-list'); if (!holder) return;
  holder.textContent = 'Loading indicator records…';
  const query = new URLSearchParams({ limit: IOC_LIMIT, skip: pageState.skip, source: pageState.source });
  if (pageState.search) query.set('search', pageState.search);
  try {
    const result = await request(`/api/iocs?${query}`); pageState.total = result.total || 0;
    setText(byId('ioc-count'), `${pageState.total.toLocaleString()} records`);
    setText(byId('ioc-page'), `Page ${Math.floor(pageState.skip / IOC_LIMIT) + 1} of ${Math.max(1, Math.ceil(pageState.total / IOC_LIMIT)).toLocaleString()}`);
    byId('ioc-prev').disabled = pageState.skip <= 0; byId('ioc-next').disabled = pageState.skip + IOC_LIMIT >= pageState.total;
    holder.replaceChildren();
    const table = document.createElement('table'); table.innerHTML = '<thead><tr><th>INDICATOR</th><th>TYPE / CLASS</th><th>SOURCE</th><th>FIRST SEEN</th><th>PROVENANCE</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const row of result.iocs || []) {
      const tr = document.createElement('tr');
      const value = document.createElement('td'); value.className = 'code-cell'; value.textContent = String(row.value || '—');
      const type = document.createElement('td'); type.textContent = String(row.type || row.file_type || row.threat_type || row.category || row.record_type || '—');
      const source = document.createElement('td'); source.textContent = String(row.source || '—');
      const seen = document.createElement('td'); seen.textContent = String(row.first_seen || row.date_added || '—');
      const link = document.createElement('td'); link.append(sourceAnchor(row.source_url));
      tr.append(value, type, source, seen, link); body.append(tr);
    }
    if (!body.children.length) { const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan = 5; td.textContent = 'No indicators match these filters.'; tr.append(td); body.append(tr); }
    table.append(body); holder.replaceChildren(table);
  } catch (error) { holder.textContent = `Could not load indicator records: ${error.message}`; }
}

async function initIocs() {
  if (!byId('ioc-list')) return;
  try {
    const sources = (await request('/api/sources')).sources || []; const select = byId('ioc-source');
    for (const row of sources) {
      if (!row.indicators && !['CTIDigest', 'MalwareBazaar'].includes(row.name)) continue;
      const option = document.createElement('option'); option.value = row.name; option.textContent = `${row.name} (${Number(row.indicators).toLocaleString()})`; select.append(option);
    }
  } catch {}
  byId('ioc-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') { pageState.search = e.target.value.trim(); pageState.skip = 0; loadIocs(); } });
  byId('ioc-source').addEventListener('change', (e) => { pageState.source = e.target.value; pageState.skip = 0; loadIocs(); });
  byId('ioc-prev').addEventListener('click', () => { pageState.skip = Math.max(0, pageState.skip - IOC_LIMIT); loadIocs(); });
  byId('ioc-next').addEventListener('click', () => { if (pageState.skip + IOC_LIMIT < pageState.total) { pageState.skip += IOC_LIMIT; loadIocs(); } });
  loadIocs();
}

async function lookupVirusTotal(value, output) {
  const indicator = value.trim(); if (!indicator) return;
  output.textContent = `Looking up ${indicator}…`;
  try {
    const result = await request(`/api/virustotal/${encodeURIComponent(indicator)}`);
    const stats = result.status === 'found' ? `${result.malicious || 0} malicious · ${result.suspicious || 0} suspicious · ${result.harmless || 0} clean` : 'No VirusTotal record found.';
    const p = document.createElement('p'); p.className = 'verification-result'; p.textContent = `${indicator}: ${stats}`;
    const a = sourceAnchor(result.vt_url || `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`, 'Open VirusTotal record ↗');
    const feed = document.createElement('a'); feed.className = 'btn secondary'; feed.href = 'index.html?source=VirusTotal'; feed.textContent = 'View in threat feed';
    output.replaceChildren(p, a, feed);
  } catch (error) { output.textContent = `Lookup failed: ${error.message}`; }
}

async function verifyIndicator(value, output) {
  const indicator = value.trim(); if (!indicator) return;
  output.textContent = 'Checking your indicator and feed collections…';
  try {
    const result = await request(`/api/verify/${encodeURIComponent(indicator)}`); output.replaceChildren();
    const p = document.createElement('p'); p.className = result.found ? 'verification-result verified' : 'verification-result not-found';
    p.textContent = result.found ? `Verified in ${result.record.source} (${result.record.type || result.record.record_type || 'indicator'}).` : 'No exact match was found in the configured collections.';
    output.append(p);
    if (result.found) { output.append(sourceAnchor(result.record.source_url)); const pre = document.createElement('pre'); pre.className = 'bson-viewer'; pre.textContent = JSON.stringify(result.record, null, 2); output.append(pre); }
  } catch (error) { output.textContent = `Verification failed: ${error.message}`; }
}

document.addEventListener('DOMContentLoaded', () => {
  loadSources();
  byId('source-refresh')?.addEventListener('click', loadSources);
  initIocs();
  byId('vt-page-form')?.addEventListener('submit', (e) => { e.preventDefault(); lookupVirusTotal(byId('vt-page-input').value, byId('vt-page-result')); });
  byId('verify-form')?.addEventListener('submit', (e) => { e.preventDefault(); verifyIndicator(byId('verify-input').value, byId('verify-result')); });
});
