const form = document.getElementById('scan-form');
const input = document.getElementById('url');
const button = document.getElementById('scan-button');
const result = document.getElementById('result');
const message = document.getElementById('scan-message');
const historyBody = document.getElementById('history-body');
let total = 0, threats = 0, safe = 0;
let historyItems = [];

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;
  button.disabled = true;
  button.textContent = 'ANALYZING...';
  message.textContent = 'Analyzing URL features...';
  result.innerHTML = '<div class="result-card panel"><b>Analyzing target URL…</b><p>Please wait for the scan result.</p></div>';
  try {
    const response = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Scan request failed.');
    const isSafe = String(data.label).toLowerCase() === 'safe';
    const score = Math.max(0, Math.min(100, Number(data.risk_score) || 0));
    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    const features = data.features || {};
    total++; isSafe ? safe++ : threats++;
    document.getElementById('total-scans').textContent = total;
    document.getElementById('threat-count').textContent = threats;
    document.getElementById('safe-count').textContent = safe;
    result.innerHTML = `<article class="result-card panel ${isSafe ? 'safe-result' : 'danger-result'}">
      <div class="result-head"><span class="result-symbol">${isSafe ? '✓' : '⚠'}</span><div class="result-name"><h3>${escapeHTML(data.verdict || (isSafe ? 'Likely Legitimate' : 'Potentially Malicious'))}</h3><p>${escapeHTML(url)}</p></div><div class="risk"><strong>${score}<small>/100</small></strong><span>ESTIMATED RISK</span></div></div>
      <div class="risk-track"><div class="risk-fill" style="width:${score}%"></div></div>
      <div class="result-columns"><div><h4>ANALYSIS DETAILS</h4><ul>${reasons.map(x => `<li>${escapeHTML(x)}</li>`).join('')}</ul></div><div><h4>TARGET INFORMATION</h4><ul><li>Classification: ${escapeHTML(data.label || 'unknown')}</li><li>URL length: ${escapeHTML(features.url_length ?? 'N/A')}</li><li>HTTPS: ${escapeHTML(features.uses_https ?? 'N/A')}</li><li>IP address: ${escapeHTML(features.has_ip_address ?? 'N/A')}</li></ul></div></div>
      <details><summary>View extracted URL features</summary><div class="feature-grid">${Object.entries(features).map(([k,v]) => `<div class="feature"><span>${escapeHTML(k.replaceAll('_',' '))}</span><b>${escapeHTML(v)}</b></div>`).join('')}</div></details><p class="disclaimer">${escapeHTML(data.disclaimer || 'Educational prototype only; do not rely on this result alone.')}</p></article>`;
    historyItems.unshift({url, isSafe, score}); historyItems = historyItems.slice(0, 6); renderHistory();
    message.textContent = '✓ Analysis complete.';
  } catch (err) {
    result.innerHTML = `<div class="result-card panel"><b class="error">Scan failed</b><p>${escapeHTML(err.message)}</p><p class="disclaimer">Check that the Flask server is running and /api/scan is available.</p></div>`;
    message.textContent = 'Scan could not be completed.';
  } finally { button.disabled = false; button.innerHTML = '⌕ &nbsp; SCAN URL <b>→</b>'; }
});
function renderHistory() {
  historyBody.innerHTML = historyItems.map(x => `<tr><td>${escapeHTML(x.url)}</td><td><span class="status ${x.isSafe ? 'status-safe' : 'status-danger'}">${x.isSafe ? 'LIKELY SAFE' : 'FLAGGED'}</span></td><td>${x.score}/100</td></tr>`).join('');
}
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
