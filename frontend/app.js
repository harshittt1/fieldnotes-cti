const LAB_API = (window.CTI_API_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '');

async function labRequest(path) {
  const response = await fetch(`${LAB_API}${path}`);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `${response.status} ${response.statusText}`);
  return data;
}

function showLabStatus(message, error = false) {
  const element = document.getElementById('lab-status');
  if (element) { element.textContent = message; element.classList.toggle('status-error', error); }
  const apiStatus = document.getElementById('lab-api-status');
  if (apiStatus) apiStatus.textContent = error ? '● Backend unavailable' : '● MongoDB Atlas Connected';
}

async function fetchSchemaAnalysis() {
  const btn = document.getElementById('recalculate-btn');
  if (btn) { btn.textContent = 'Calculating…'; btn.disabled = true; }
  try {
    const data = await labRequest('/api/schema-analysis');
    const avg = Number(data.avg_size_bytes || 0), max = Number(data.max_size_bytes || 0), min = Number(data.min_size_bytes || 0);
    const limitBytes = Number(data.limit_16mb || 16 * 1024 * 1024);
    document.getElementById('avg-size').textContent = `${(avg / 1024).toFixed(2)} KB`;
    document.getElementById('avg-pct').textContent = `~${((avg / limitBytes) * 100).toFixed(4)}% of 16 MB limit`;
    document.getElementById('max-size').textContent = `${(max / 1024).toFixed(2)} KB`;
    document.getElementById('max-sub').textContent = `${((max / limitBytes) * 100).toFixed(3)}% of 16 MB limit`;
    document.getElementById('min-size').textContent = `${(min / 1024).toFixed(2)} KB`;
    const compliance = document.getElementById('compliance-status');
    compliance.textContent = data.passed ? 'PASSED' : 'FAILED';
    compliance.className = `metric-value ${data.passed ? 'success-text' : 'error-text'}`;
    showLabStatus(`Analyzed ${Number(data.total_documents || 0).toLocaleString()} unique MISP events.`);
  } catch (error) {
    showLabStatus(`Could not calculate document sizes: ${error.message}. Start the backend and verify its database connection.`, true);
  } finally { if (btn) { btn.textContent = 'Recalculate $bsonSize'; btn.disabled = false; } }
}

async function runBenchmark() {
  const btn = document.getElementById('run-benchmark-btn');
  if (btn) { btn.textContent = 'Benchmarking…'; btn.disabled = true; }
  try {
    const data = await labRequest('/api/benchmark');
    document.getElementById('ref-time').textContent = `${data.referenced_ms} ms`;
    document.getElementById('emb-time').textContent = `${data.embedded_ms} ms (${data.faster_multiplier}× faster)`;
    showLabStatus('Benchmark completed against the live event collection.');
  } catch (error) { showLabStatus(`Benchmark failed: ${error.message}`, true); }
  finally { if (btn) { btn.textContent = '⚡ Run Performance Benchmark'; btn.disabled = false; } }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelector('.nav-right .btn.secondary')?.addEventListener('click', fetchSchemaAnalysis);
  fetchSchemaAnalysis();
});
