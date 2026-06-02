/**
 * app.js — URL Shield Frontend Logic
 * Connects to Flask API at http://127.0.0.1:5000
 */

const API_BASE = 'http://127.0.0.1:5000';

// ════════════════════════════════════════════════════════════════════
// Particle Background
// ════════════════════════════════════════════════════════════════════
(function initParticles() {
  const container = document.getElementById('bgParticles');
  const colors = ['#3b82f6', '#8b5cf6', '#06b6d4', '#22c55e'];
  for (let i = 0; i < 30; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const size = Math.random() * 3 + 1.5;
    const color = colors[Math.floor(Math.random() * colors.length)];
    const left = Math.random() * 100;
    const dur = Math.random() * 20 + 15;
    const delay = Math.random() * 25;
    p.style.cssText = `
      width:${size}px; height:${size}px; background:${color};
      left:${left}%; bottom:-20px;
      animation-duration:${dur}s; animation-delay:-${delay}s;
    `;
    container.appendChild(p);
  }
})();

// ════════════════════════════════════════════════════════════════════
// API Health Check
// ════════════════════════════════════════════════════════════════════
async function checkApiHealth() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const data = await res.json();
      dot.className = 'status-dot online';
      text.textContent = `API Online · ${data.n_features} features`;
      return true;
    }
  } catch (_) {}
  dot.className = 'status-dot offline';
  text.textContent = 'API Offline';
  return false;
}

// ════════════════════════════════════════════════════════════════════
// Stats Panel
// ════════════════════════════════════════════════════════════════════
async function refreshStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return;
    const d = await res.json();
    const total = d.total_predictions || 0;
    const safe = d.safe_detected || 0;
    const malicious = d.malicious_detected || 0;
    const rate = total > 0 ? ((malicious / total) * 100).toFixed(1) : '0.0';

    // Main stat cards
    document.getElementById('statTotal').textContent = total.toLocaleString();
    document.getElementById('statSafe').textContent = safe.toLocaleString();
    document.getElementById('statMalicious').textContent = malicious.toLocaleString();
    document.getElementById('statRate').textContent = rate + '%';

    // Bars
    document.getElementById('statSafeBar').style.width = total > 0 ? `${(safe / total) * 100}%` : '0%';
    document.getElementById('statMaliciousBar').style.width = total > 0 ? `${(malicious / total) * 100}%` : '0%';
    document.getElementById('statRateBar').style.width = `${Math.min(parseFloat(rate), 100)}%`;

    // Hero mini-stats
    document.getElementById('heroTotal').textContent = total.toLocaleString();
    document.getElementById('heroMalicious').textContent = malicious.toLocaleString();
  } catch (_) {}
}

// ════════════════════════════════════════════════════════════════════
// Gauge Animation
// ════════════════════════════════════════════════════════════════════
function animateGauge(maliciousProb) {
  const pct = Math.round(maliciousProb * 100);
  const totalArcLen = 188.5; // semi-circle
  const offset = totalArcLen - (maliciousProb * totalArcLen);

  document.getElementById('gaugeArc').setAttribute('stroke-dashoffset', offset);
  document.getElementById('gaugePct').textContent = pct + '%';

  // Move needle dot along the arc
  const angle = Math.PI - (maliciousProb * Math.PI); // left edge = safe=0, right=malicious=1
  const cx = 80 + 60 * Math.cos(angle);
  const cy = 90 - 60 * Math.sin(angle);
  document.getElementById('gaugeNeedle').setAttribute('cx', cx.toFixed(1));
  document.getElementById('gaugeNeedle').setAttribute('cy', cy.toFixed(1));
}

// ════════════════════════════════════════════════════════════════════
// Single URL Prediction
// ════════════════════════════════════════════════════════════════════
const urlInput   = document.getElementById('urlInput');
const scanBtn    = document.getElementById('scanBtn');
const clearBtn   = document.getElementById('clearBtn');
const scanText   = document.getElementById('scanBtnText');
const scanSpin   = document.getElementById('scanSpinner');
const resultPanel = document.getElementById('resultPanel');
const errorPanel  = document.getElementById('errorPanel');

function showResult(data) {
  errorPanel.classList.add('hidden');
  resultPanel.classList.remove('hidden');

  const isMalicious = data.label === 'Malicious';

  // Verdict
  document.getElementById('verdictIcon').className = `verdict-icon ${isMalicious ? 'malicious' : 'safe'}`;
  document.getElementById('verdictIcon').textContent = isMalicious ? '🚨' : '✅';
  document.getElementById('verdictLabel').className = `verdict-label ${isMalicious ? 'malicious' : 'safe'}`;
  document.getElementById('verdictLabel').textContent = data.label;
  document.getElementById('verdictUrl').textContent = data.url;

  // Gauge
  animateGauge(data.malicious_prob);

  // Chips
  const riskEl = document.getElementById('chipRiskVal');
  riskEl.textContent = data.risk_level;
  riskEl.className = `chip-val risk-${data.risk_level}`;
  document.getElementById('chipConf').textContent    = (data.confidence  * 100).toFixed(1) + '%';
  document.getElementById('chipSafe').textContent    = (data.safe_prob   * 100).toFixed(1) + '%';
  document.getElementById('chipMal').textContent     = (data.malicious_prob * 100).toFixed(1) + '%';
  document.getElementById('chipMs').textContent      = data.processing_ms + ' ms';
  document.getElementById('chipFeatures').textContent= data.features_used;
}

function showError(msg) {
  resultPanel.classList.add('hidden');
  errorPanel.classList.remove('hidden');
  document.getElementById('errorMsg').textContent = msg;
}

function setScanLoading(loading) {
  scanBtn.disabled = loading;
  scanText.textContent = loading ? 'Scanning…' : 'Scan URL';
  scanSpin.classList.toggle('hidden', !loading);
}

async function scanUrl() {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }

  setScanLoading(true);
  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || 'Prediction failed. Check API is running.');
    } else {
      showResult(data);
      setTimeout(refreshStats, 500);
    }
  } catch (err) {
    if (err.name === 'TimeoutError') {
      showError('Request timed out. Make sure the Flask API is running on port 5000.');
    } else {
      showError('Cannot connect to API. Start the Flask server: cd api && python app.py');
    }
  }
  setScanLoading(false);
}

scanBtn.addEventListener('click', scanUrl);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanUrl(); });
clearBtn.addEventListener('click', () => {
  urlInput.value = '';
  resultPanel.classList.add('hidden');
  errorPanel.classList.add('hidden');
  urlInput.focus();
});

// Quick test buttons
document.querySelectorAll('.qt-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    urlInput.value = btn.dataset.url;
    scanUrl();
  });
});

// ════════════════════════════════════════════════════════════════════
// Batch Prediction
// ════════════════════════════════════════════════════════════════════
const batchInput   = document.getElementById('batchInput');
const batchScanBtn = document.getElementById('batchScanBtn');
const batchBtnText = document.getElementById('batchBtnText');
const batchSpinner = document.getElementById('batchSpinner');
const batchCount   = document.getElementById('batchCount');
const batchEmpty   = document.getElementById('batchEmpty');
const batchSummary = document.getElementById('batchSummary');
const batchList    = document.getElementById('batchList');

batchInput.addEventListener('input', () => {
  const lines = batchInput.value.split('\n').filter(l => l.trim()).length;
  batchCount.textContent = `${Math.min(lines, 50)} / 50`;
  batchCount.style.color = lines > 50 ? 'var(--red)' : '';
});

document.getElementById('batchClear').addEventListener('click', () => {
  batchInput.value = '';
  batchCount.textContent = '0 / 50';
  batchEmpty.classList.remove('hidden');
  batchSummary.classList.add('hidden');
  batchList.innerHTML = '';
});

function getRiskColor(level) {
  const map = {
    CRITICAL: '#ff2d55', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#22c55e'
  };
  return map[level] || '#7c8fa8';
}

function setBatchLoading(loading) {
  batchScanBtn.disabled = loading;
  batchBtnText.textContent = loading ? 'Scanning…' : 'Scan All';
  batchSpinner.classList.toggle('hidden', !loading);
}

async function runBatchScan() {
  const raw = batchInput.value.trim();
  if (!raw) return;

  const urls = raw.split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0)
    .slice(0, 50);

  if (urls.length === 0) return;

  setBatchLoading(true);
  batchList.innerHTML = '';
  batchSummary.classList.add('hidden');
  batchEmpty.classList.add('hidden');

  try {
    const res = await fetch(`${API_BASE}/batch_predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await res.json();

    if (!res.ok) {
      batchEmpty.classList.remove('hidden');
      batchEmpty.querySelector('p').textContent = data.error || 'Batch prediction failed.';
      setBatchLoading(false);
      return;
    }

    const results = data.results || [];
    let safeCount = 0, malCount = 0;

    results.forEach(r => {
      if (r.error) return;
      if (r.label === 'Malicious') malCount++; else safeCount++;

      const div = document.createElement('div');
      div.className = 'batch-item';

      const badge = document.createElement('div');
      badge.className = `bi-badge ${r.label === 'Malicious' ? 'malicious' : 'safe'}`;
      badge.textContent = r.label === 'Malicious' ? '✕' : '✓';

      const urlEl = document.createElement('div');
      urlEl.className = 'bi-url';
      urlEl.title = r.url;
      urlEl.textContent = r.url;

      const riskEl = document.createElement('div');
      riskEl.className = 'bi-risk';
      riskEl.style.color = getRiskColor(r.risk_level);
      riskEl.textContent = r.risk_level;

      const confEl = document.createElement('div');
      confEl.className = 'bi-conf';
      confEl.textContent = (r.confidence * 100).toFixed(0) + '%';

      div.append(badge, urlEl, riskEl, confEl);
      batchList.appendChild(div);
    });

    // Summary
    document.getElementById('bsSafe').textContent = safeCount;
    document.getElementById('bsMalicious').textContent = malCount;
    document.getElementById('bsTotal').textContent = results.length;
    batchSummary.classList.remove('hidden');
    setTimeout(refreshStats, 500);

  } catch (err) {
    batchEmpty.classList.remove('hidden');
    batchEmpty.querySelector('p').textContent =
      'Cannot connect to API. Start the Flask server: cd api && python app.py';
  }

  setBatchLoading(false);
}

batchScanBtn.addEventListener('click', runBatchScan);

// ════════════════════════════════════════════════════════════════════
// Init & Auto-refresh
// ════════════════════════════════════════════════════════════════════
async function init() {
  await checkApiHealth();
  await refreshStats();
  // Auto-refresh stats every 10 seconds
  setInterval(refreshStats, 10000);
  // Re-check health every 30 seconds
  setInterval(checkApiHealth, 30000);
}

init();
