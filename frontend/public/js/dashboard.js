// public/js/dashboard.js

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const resultContainer = document.getElementById('result-container');
  const progress = document.getElementById('progress');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    resultContainer.innerHTML = '';
    progress.innerText = '🔍 Pengujian sedang berjalan...';

    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());
    payload.dos_enabled = document.getElementById('enable-dos')?.checked;

    try {
      const res = await fetch('/test/scan-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) throw new Error('Gagal menjalankan pengujian');

      const data = await res.json();
      progress.innerText = '✅ Pengujian selesai';
      displayResults(data);
    } catch (err) {
      progress.innerText = '❌ Gagal menjalankan pengujian';
      resultContainer.innerHTML = `<pre>${err.message}</pre>`;
    }
  });
});

function displayResults(data) {
  const resultContainer = document.getElementById('result-container');
  let html = '';

  if (data.xss_results?.length) {
    html += '<h3>XSS Results</h3><ul>' +
      data.xss_results.map(r => `<li><strong>${r.payload}</strong>: ${r.result}</li>`).join('') + '</ul>';
  }
  if (data.sqli_results?.length) {
    html += '<h3>SQLi Results</h3><ul>' +
      data.sqli_results.map(r => `<li><strong>${r.payload}</strong>: ${r.result}</li>`).join('') + '</ul>';
  }
  if (data.tech?.length) {
    html += '<h3>Software Detected</h3><ul>' +
      data.tech.map(t => `<li>${t}</li>`).join('') + '</ul>';
  }
  if (data.cves?.length) {
    html += '<h3>Vulnerabilities</h3><ul>' +
      data.cves.map(cve => `<li><strong>${cve.software}</strong>: ${cve.cve_id} - ${cve.description}</li>`).join('') + '</ul>';
  }
  if (data.zap_alerts?.length) {
    html += '<h3>ZAP Alerts</h3>' +
      data.zap_alerts.map(a => `
        <div style="background-color: ${riskColor(a.risk)}; padding: 10px; margin-bottom: 10px">
          <strong>[${a.risk}] ${a.alert}</strong><br>
          <strong>Deskripsi:</strong> ${a.desc}<br>
          <strong>Solusi:</strong> ${a.solution}<br>
          <strong>URL:</strong> ${a.url}<br>
        </div>
      `).join('');
  }
  if (data.dos_summary) {
    html += `<h3>DoS Summary</h3><pre>${data.dos_summary}</pre>`;
  }

  resultContainer.innerHTML = html;
}

function riskColor(level) {
  switch (level) {
    case 'High': return '#ffcaca';
    case 'Medium': return '#fff4c2';
    case 'Low': return '#d0e7ff';
    default: return '#eee';
  }
}
