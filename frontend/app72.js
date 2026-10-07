const LAB_API = (window.CTI_API_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '');
let timeLabels = [];
let hitRatioData = [];

async function pollWiredTigerStats(stress = false) {
  const status = document.getElementById('lab-status');
  try {
    const suffix = stress ? '?stress=true' : '';
    const response = await fetch(`${LAB_API}/api/wiredtiger${suffix}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `${response.status} ${response.statusText}`);
    const maxCache = Number(data.wt_max_mb) || 0;
    const working = Number(data.working_set_mb) || 0;
    const resident = Number(data.resident_mb) || 0;
    const ratio = Number(data.hit_ratio) || 0;
    document.getElementById('working-set').textContent = `${working.toFixed(2)} MB`;
    document.getElementById('max-cache').textContent = `${maxCache.toFixed(0)} MB`;
    document.getElementById('resident-cache').textContent = `${resident.toFixed(2)} MB`;
    const ratioEl = document.getElementById('cache-ratio');
    ratioEl.textContent = `${ratio.toFixed(2)}%`;
    ratioEl.style.color = ratio < 95 ? '#FBBF24' : '#22C55E';

    const residentPct = maxCache ? Math.min(100, resident / maxCache * 100) : 0;
    const workingOnlyPct = maxCache ? Math.min(100 - residentPct, Math.max(0, working - resident) / maxCache * 100) : 0;
    const headroomMb = Math.max(0, maxCache - working);
    const headroomPct = Math.max(0, 100 - residentPct - workingOnlyPct);
    document.getElementById('bar-resident').style.width = `${residentPct}%`;
    document.getElementById('bar-working').style.width = `${workingOnlyPct}%`;
    document.getElementById('bar-headroom').style.width = `${headroomPct}%`;
    document.getElementById('label-resident').textContent = `Resident in cache (${resident.toFixed(2)} MB / ${residentPct.toFixed(1)}%)`;
    document.getElementById('label-working').textContent = `Working set total (${working.toFixed(2)} MB / ${(residentPct + workingOnlyPct).toFixed(1)}%)`;
    document.getElementById('label-headroom').textContent = `Free cache headroom (${headroomMb.toFixed(2)} MB / ${headroomPct.toFixed(1)}%)`;
    document.getElementById('atlas-status').textContent = '● MongoDB Atlas Connected';
    if (status) status.textContent = `Updated ${new Date().toLocaleTimeString()} · ${Number(data.faults_delta || 0).toLocaleString()} page faults since last read`;

    timeLabels.push(new Date().toLocaleTimeString()); hitRatioData.push(ratio);
    if (timeLabels.length > 20) { timeLabels.shift(); hitRatioData.shift(); }
    drawHitRatioChart();
  } catch (error) {
    if (status) status.textContent = `Could not load live cache metrics: ${error.message}. Confirm the backend is running.`;
    document.getElementById('atlas-status').textContent = '● Backend unavailable';
    document.getElementById('atlas-status').classList.add('status-error');
  }
}

function drawHitRatioChart() {
  const canvas = document.getElementById('hitRatioChart');
  const ctx = canvas?.getContext('2d'); if (!ctx) return;
  const rect = canvas.getBoundingClientRect(); const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, rect.width * dpr); canvas.height = Math.max(1, rect.height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const width = rect.width, height = rect.height, left = 44, right = 12, top = 14, bottom = 30;
  ctx.clearRect(0, 0, width, height); ctx.font = '11px Inter, sans-serif'; ctx.strokeStyle = 'rgba(255,255,255,.10)'; ctx.fillStyle = '#94A3B8';
  for (const value of [90, 95, 100]) {
    const y = top + (100 - value) / 10 * (height - top - bottom);
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - right, y); ctx.stroke(); ctx.fillText(`${value}%`, 4, y + 4);
  }
  if (!hitRatioData.length) { ctx.fillText('Waiting for first sample…', left + 8, height / 2); return; }
  const xFor = (i) => left + (hitRatioData.length <= 1 ? (width - left - right) : i * (width - left - right) / (hitRatioData.length - 1));
  const yFor = (v) => top + (100 - Math.max(90, Math.min(100, v))) / 10 * (height - top - bottom);
  ctx.beginPath(); hitRatioData.forEach((v, i) => i ? ctx.lineTo(xFor(i), yFor(v)) : ctx.moveTo(xFor(i), yFor(v)));
  ctx.strokeStyle = '#2DD4BF'; ctx.lineWidth = 2; ctx.stroke();
  const step = Math.max(1, Math.ceil(timeLabels.length / 5));
  timeLabels.forEach((label, i) => { if (i % step === 0 || i === timeLabels.length - 1) ctx.fillText(label, Math.max(left, xFor(i) - 20), height - 8); });
}

function triggerStressLoad() { pollWiredTigerStats(true); }

document.addEventListener('DOMContentLoaded', () => {
  document.querySelector('.nav-right .btn.secondary')?.addEventListener('click', () => pollWiredTigerStats());
  document.getElementById('stress-load-btn')?.addEventListener('click', triggerStressLoad);
  window.addEventListener('resize', drawHitRatioChart);
  pollWiredTigerStats();
  setInterval(() => pollWiredTigerStats(false), 10000);
});
