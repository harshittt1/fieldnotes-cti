const API_BASE = (window.CTI_API_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '');
const PAGE_SIZE = 12;
const state = { page: 0, total: 0, search: '', category: 'All', source: 'All', year: 'All', severity: 'All', sort: 'newest', view: 'grid' };
const initialSource = new URLSearchParams(window.location.search).get('source');
if (initialSource) state.source = initialSource;
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '');

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { const body = await response.json(); message = body.detail || message; } catch {}
    throw new Error(message);
  }
  return response.json();
}

function paramsForFeed() {
  const p = new URLSearchParams({ limit: PAGE_SIZE, skip: state.page * PAGE_SIZE, sort: state.sort });
  for (const [key, value] of Object.entries({ search: state.search, category: state.category, source: state.source, year: state.year, severity: state.severity })) {
    if (value && value !== 'All') p.set(key, value);
  }
  return p;
}

function safeExternalUrl(url) {
  try { const parsed = new URL(url); return parsed.protocol === 'https:' ? parsed.href : null; } catch { return null; }
}

function addSourceLink(parent, url, label = '🔗 Verified Source') {
  const verified = safeExternalUrl(url);
  if (!verified) {
    const text = document.createElement('span'); text.className = 'source-unavailable'; text.textContent = 'Source link unavailable'; parent.append(text); return;
  }
  const a = document.createElement('a'); a.className = 'btn source-link'; a.href = verified; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.title = 'Open the original source record'; a.textContent = label; a.addEventListener('click', (event) => event.stopPropagation()); parent.append(a);
}

function renderCard(event) {
  const card = document.createElement('article'); card.className = 'threat-card'; card.tabIndex = 0; card.setAttribute('role', 'button');
  const header = document.createElement('div'); header.className = 'card-header';
  const sourceNames = Array.isArray(event.sources) && event.sources.length ? event.sources : [event.source];
  const source = document.createElement('span'); source.textContent = `${sourceNames.map((name) => esc(name).toUpperCase()).join(' · ')} INTELLIGENCE`;
  const category = document.createElement('span'); category.textContent = `● ${esc(event.category).toUpperCase()}`;
  const time = document.createElement('time'); time.textContent = esc(event.date || 'Date unavailable');
  header.append(source, category, time);
  const title = document.createElement('h2'); title.className = 'card-title'; title.textContent = esc(event.info || 'Untitled report');
  const desc = document.createElement('p'); desc.className = 'card-desc'; desc.textContent = esc(event.description || 'Threat intelligence report from the source feed.');
  const footer = document.createElement('div'); footer.className = 'card-footer';
  const left = document.createElement('div'); const id = document.createElement('div'); id.className = 'card-id'; id.textContent = event.event_uuid ? `ID-${event.event_uuid.slice(0, 18).toUpperCase()}` : 'Source ID unavailable';
  left.append(id); addSourceLink(left, event.source_url);
  const right = document.createElement('div'); right.className = 'card-right';
  const observables = document.createElement('div'); observables.className = 'observables-count'; observables.textContent = `${Number(event.indicator_count || 0).toLocaleString()} Observables`;
  const severity = document.createElement('span'); severity.className = `severity-badge severity-${String(event.severity || 'low').toLowerCase()}`; severity.textContent = esc(event.severity || 'Low').toUpperCase();
  right.append(observables, severity);
  const value = event.value || event.vt_value;
  if (value) {
    const vt = document.createElement('button'); vt.type = 'button'; vt.className = 'btn vt-card-action'; vt.textContent = '🛡 Check with VirusTotal';
    vt.title = `Look up ${value} on VirusTotal (one explicit lookup)`;
    vt.addEventListener('click', async (e) => {
      e.stopPropagation(); vt.disabled = true; vt.textContent = 'Checking…';
      const status = document.createElement('span'); status.className = 'vt-inline-status'; right.append(status);
      await runVTLookup(value, status); vt.disabled = false; vt.textContent = '🛡 Check with VirusTotal';
    });
    right.append(vt);
  }
  footer.append(left, right); card.append(header, title, desc, footer);
  const open = () => openDetails(event);
  card.addEventListener('click', open); card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  return card;
}

async function loadFeed() {
  const grid = $('feed-grid'); grid.replaceChildren();
  const loading = document.createElement('div'); loading.className = 'empty-state'; loading.textContent = 'Loading intelligence streams…'; grid.append(loading);
  try {
    const data = await api(`/api/events?${paramsForFeed()}`); state.total = data.total || 0;
    $('results-count').textContent = `${state.total.toLocaleString()} articles`;
    $('total-reports').textContent = state.total.toLocaleString();
    const pages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
    $('pagination-info').textContent = `Page ${state.page + 1} of ${pages.toLocaleString()} (${state.total.toLocaleString()} reports)`;
    $('previous-page').disabled = state.page <= 0; $('next-page').disabled = state.page + 1 >= pages;
    $('current-category').textContent = state.category;
    grid.replaceChildren();
    if (!data.events?.length) { const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = 'No intelligence matches your filters.'; grid.append(empty); return; }
    data.events.forEach((event) => grid.append(renderCard(event)));
    renderActiveFilters();
  } catch (error) {
    grid.replaceChildren(); const msg = document.createElement('div'); msg.className = 'empty-state error-state'; msg.textContent = `Could not load feed: ${error.message}. Start the backend and check its database connection.`; grid.append(msg);
    $('db-status').textContent = '● API unavailable'; $('db-status').classList.add('status-error');
  }
}

function renderActiveFilters() {
  const box = $('active-filters'); box.replaceChildren();
  Object.entries({ search: state.search, category: state.category, source: state.source, year: state.year, severity: state.severity }).forEach(([name, value]) => {
    if (!value || value === 'All') return;
    const chip = document.createElement('span'); chip.className = 'filter-chip'; chip.textContent = `${name}: ${value}`; box.append(chip);
  });
}

async function loadFacets() {
  const facets = await api('/api/facets');
  $('count-all').textContent = Number(facets.total || 0).toLocaleString();
  $('total-reports').textContent = Number(facets.total || 0).toLocaleString();
  document.querySelectorAll('#category-list li[data-category]').forEach((li) => {
    if (li.dataset.category === 'All') return;
    const badge = li.querySelector('.count');
    if (badge) badge.textContent = Number(facets.categories?.[li.dataset.category] || 0).toLocaleString();
  });
  const source = $('source-filter');
  for (const item of facets.sources || []) { const option = document.createElement('option'); option.value = item.name; option.textContent = `${item.name} (${Number(item.count).toLocaleString()})`; source.append(option); }
  if ([...source.options].some((option) => option.value === state.source)) source.value = state.source;
  const year = $('year-filter');
  for (const item of facets.years || []) { const option = document.createElement('option'); option.value = item.year; option.textContent = `${item.year} Telemetry (${Number(item.count).toLocaleString()})`; year.append(option); }
}

async function loadMetrics() {
  try {
    const data = await api('/api/metrics');
    $('metric-working').textContent = `${data.working_set_mb} MB (${Number(data.event_count).toLocaleString()} feed records)`;
    $('metric-cache').textContent = `${data.cache_max_mb} MB`;
    $('metric-hit').textContent = `${data.hit_ratio}%`;
    $('metric-bson').textContent = `${data.avg_bson_kb} KB`;
    $('sync-time').textContent = `Updated ${new Date().toLocaleTimeString('en-GB', { timeZone: 'UTC', hour12: false })} UTC`;
  } catch { $('sync-time').textContent = 'Database telemetry unavailable'; }
}

function renderJson(value) {
  const pre = document.createElement('pre'); pre.className = 'bson-viewer'; pre.textContent = JSON.stringify(value, null, 2); return pre;
}

async function openDetails(event) {
  $('modal-title').textContent = event.info || `${event.source} report`;
  const body = $('modal-body'); body.replaceChildren();
  const meta = document.createElement('div'); meta.className = 'modal-grid';
  const detailPairs = [['Source', event.source], ['Record type', event.record_type], ['Report / indicator', event.value || event.event_uuid], ['Category', event.category], ['Severity', event.severity], ['Date', event.date], ['Observables', event.indicator_count]];
  for (const [label, value] of detailPairs) { const item = document.createElement('div'); const key = document.createElement('div'); key.className = 'modal-meta-label'; key.textContent = label; const val = document.createElement('div'); val.className = 'modal-meta-value'; val.textContent = esc(value || '—'); item.append(key, val); meta.append(item); }
  const linkBox = document.createElement('div'); linkBox.className = 'modal-source'; addSourceLink(linkBox, event.source_url, '↗ Open Original Live Report');
  body.append(meta, linkBox);
  if (event.record_type === 'misp_event' && event.event_uuid) {
    const title = document.createElement('h3'); title.className = 'modal-section-title'; title.textContent = 'Report and linked observables'; body.append(title);
    const loading = document.createElement('p'); loading.className = 'help-text'; loading.textContent = 'Loading source record…'; body.append(loading);
    try { const details = await api(`/api/events/${encodeURIComponent(event.event_uuid)}`); loading.remove(); body.append(renderJson(details)); }
    catch (error) { loading.textContent = `Could not load full report: ${error.message}`; }
  }
  $('modal-overlay').hidden = false;
}

function resetFilters() {
  Object.assign(state, { page: 0, search: '', category: 'All', source: 'All', year: 'All', severity: 'All', sort: 'newest' });
  $('feed-search').value = ''; $('source-filter').value = 'All'; $('year-filter').value = 'All'; $('sort-filter').value = 'newest';
  document.querySelectorAll('#category-list li').forEach((li) => li.classList.toggle('active', li.dataset.category === 'All'));
  document.querySelectorAll('#severity-filter button').forEach((button) => button.classList.toggle('selected', button.dataset.severity === 'All'));
  loadFeed();
}

async function runVTLookup(value, output = $('sync-message')) {
  const target = value.trim(); if (!target) return;
  output.textContent = `Checking ${target} with VirusTotal…`;
  try {
    const data = await api(`/api/virustotal/${encodeURIComponent(target)}`);
    const summary = data.status === 'found' ? `${data.malicious || 0} malicious, ${data.suspicious || 0} suspicious, ${data.harmless || 0} harmless engines.` : 'No VirusTotal record found.';
    output.textContent = `VirusTotal: ${summary}`;
    const url = data.vt_url || `https://www.virustotal.com/gui/search/${encodeURIComponent(target)}`;
    const a = document.createElement('a'); a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = ' Open verified VirusTotal record ↗'; output.append(a);
    if (data.status === 'found') await Promise.all([loadFeed(), loadFacets(), loadMetrics()]);
  } catch (error) { output.textContent = `VirusTotal lookup failed: ${error.message}`; }
}

async function syncFeed(feed) {
  const output = $('sync-message');
  if (feed === 'virustotal') { output.textContent = 'Use the VirusTotal lookup field to inspect a specific IP, domain, URL, or hash. Bulk VirusTotal checks can consume your API quota.'; return; }
  output.textContent = `Starting ${feed === 'all' ? 'live-feed ingestion' : 'MalwareBazaar sync'}…`;
  document.querySelectorAll('[data-sync]').forEach((button) => { button.disabled = true; });
  try {
    const result = await api(`/api/sync/${feed}`, { method: 'POST' });
    output.textContent = result.message || 'Feed sync completed.';
    if (result.status === 'queued' || result.status === 'running') {
      const timer = setInterval(async () => {
        try {
          const status = await api('/api/sync/status');
          output.textContent = status.message || 'Feed sync is running…';
          if (status.status === 'complete' || status.status === 'failed') {
            clearInterval(timer);
            document.querySelectorAll('[data-sync]').forEach((button) => { button.disabled = false; });
            if (status.status === 'complete') await Promise.all([loadFeed(), loadFacets(), loadMetrics()]);
          }
        } catch (error) { clearInterval(timer); output.textContent = `Could not read sync status: ${error.message}`; }
      }, 3000);
    } else {
      await Promise.all([loadFeed(), loadFacets(), loadMetrics()]);
    }
  } catch (error) { output.textContent = `Sync failed: ${error.message}`; }
  finally { if (feed !== 'all' || $('sync-message').textContent.startsWith('Sync failed:')) document.querySelectorAll('[data-sync]').forEach((button) => { button.disabled = false; }); }
}

document.addEventListener('DOMContentLoaded', async () => {
  $('feed-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') { state.search = e.currentTarget.value.trim(); state.page = 0; loadFeed(); } });
  $('category-list').addEventListener('click', (e) => { const li = e.target.closest('li[data-category]'); if (!li) return; state.category = li.dataset.category; state.page = 0; document.querySelectorAll('#category-list li').forEach((x) => x.classList.toggle('active', x === li)); loadFeed(); });
  $('source-filter').addEventListener('change', (e) => { state.source = e.target.value; state.page = 0; loadFeed(); });
  $('year-filter').addEventListener('change', (e) => { state.year = e.target.value; state.page = 0; loadFeed(); });
  $('severity-filter').addEventListener('click', (e) => { const b = e.target.closest('button[data-severity]'); if (!b) return; state.severity = b.dataset.severity; state.page = 0; document.querySelectorAll('#severity-filter button').forEach((x) => x.classList.toggle('selected', x === b)); loadFeed(); });
  $('sort-filter').addEventListener('change', (e) => { state.sort = e.target.value; state.page = 0; loadFeed(); });
  $('previous-page').addEventListener('click', () => { if (state.page > 0) { state.page--; loadFeed(); } });
  $('next-page').addEventListener('click', () => { if ((state.page + 1) * PAGE_SIZE < state.total) { state.page++; loadFeed(); } });
  $('reset-filters').addEventListener('click', resetFilters); $('refresh-feed').addEventListener('click', () => { loadFeed(); loadMetrics(); });
  $('grid-view').addEventListener('click', () => { state.view = 'grid'; $('feed-grid').classList.remove('list-view'); $('grid-view').classList.add('active-view'); $('list-view').classList.remove('active-view'); });
  $('list-view').addEventListener('click', () => { state.view = 'list'; $('feed-grid').classList.add('list-view'); $('list-view').classList.add('active-view'); $('grid-view').classList.remove('active-view'); });
  $('modal-close').addEventListener('click', () => { $('modal-overlay').hidden = true; });
  $('modal-overlay').addEventListener('click', (e) => { if (e.target === $('modal-overlay')) $('modal-overlay').hidden = true; });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('modal-overlay').hidden = true; });
  $('quick-vt-form').addEventListener('submit', (e) => { e.preventDefault(); runVTLookup($('quick-vt-value').value); });
  document.querySelectorAll('[data-sync]').forEach((b) => b.addEventListener('click', () => syncFeed(b.dataset.sync)));
  try { await loadFacets(); $('db-status').textContent = '● MongoDB Atlas Connected'; } catch (error) { $('db-status').textContent = '● Backend unavailable'; $('db-status').classList.add('status-error'); }
  await Promise.all([loadFeed(), loadMetrics()]);
});
