document.addEventListener("DOMContentLoaded", function () {
    // --- 1. GLOBAL VARIABLES ---
    let dosChart = null
    let originalResult = null
    let translatedResult = null
    let currentLang = "en"

    const selectAll = document.getElementById("select-all")
    const testCheckboxes = document.querySelectorAll('input[name="tests"]')
    const enableDos = document.getElementById("enable-dos")
    const dosOptions = document.getElementById("dos-options")
    const enableNmap = document.getElementById("enable-nmap")
    const nmapOptionsHolder = document.getElementById("nmap-options")
    const enableRatelimit = document.getElementById("enable-ratelimit")
    const ratelimitOptionsHolder = document.getElementById("ratelimit-options")

    // --- 2. DYNAMIC STYLE INJECTION ---
    function injectResultStyles() {
        if (document.getElementById("scan-result-styles")) return
        const style = document.createElement("style")
        style.id = "scan-result-styles"
        style.innerHTML = `
            .badge { display:inline-block; padding:4px 10px; border-radius:4px; color:#fff; font-weight:600; font-size:0.8em; min-width:60px; text-align:center; }
            .bg-critical { background:#000; border:1px solid #333; }
            .bg-high { background:#dc2626; }
            .bg-medium { background:#ea580c; }
            .bg-low { background:#ffe100; color:#000; }
            .bg-info { background:#2563eb; }
            .bg-safe { background:#10b981; }
            .bg-secondary { background:#6b7280; }
            .zap-high { background:#dc2626; } 
            .zap-medium { background:#ea580c; } 
            .zap-low { background:#ffe100; } 
            .zap-info { background:#2563eb; }
            .score-card { background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); text-align: center; margin-bottom: 30px; border: 1px solid #e5e7eb; }
            .final-grade { font-size: 3.5em; font-weight: 800; display: block; margin: 10px 0; }
            .cve-software-group { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px; overflow: hidden; background: #fff; }
            .cve-summary { padding: 15px; background: #f8fafc; cursor: pointer; font-weight: 600; display: flex; justify-content: space-between; align-items: center; list-style: none; }
            .cve-list-container { border-top: 1px solid #e5e7eb; }
            .cve-row { padding: 15px; border-bottom: 1px solid #f3f4f6; }
            .section-title { margin-top: 35px; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 1.3em; font-weight: 700; color: #111827; }
            .secure-box { padding: 15px; background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; border-radius: 8px; display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
            .skip-box { padding: 15px; background: #f3f4f6; color: #6b7280; border: 1px dashed #d1d5db; border-radius: 8px; text-align: center; font-style: italic; margin-bottom: 15px; }
            .error-box { padding: 15px; background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; border-radius: 8px; margin-bottom: 15px; }
            .secure-icon { font-size: 1.8em; }
            details.alert-entry { margin-bottom: 8px; border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; background: #fff; }
            details.alert-entry summary { padding: 12px 15px; background: #f9fafb; cursor: pointer; font-weight: 600; list-style: none; display: flex; justify-content: space-between; }
            .alert-content { padding: 15px; background: #fff; border-top: 1px solid #e5e7eb; }
            .url-list { margin: 5px 0; padding-left: 0; list-style: none; max-height: 150px; overflow-y: auto; background: #f8fafc; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; }
            .url-list li { font-family: 'Courier New', monospace; font-size: 0.85em; color: #be185d; margin-bottom: 4px; border-bottom: 1px dashed #e2e8f0; padding-bottom: 2px; word-break: break-all; }
        `
        document.head.appendChild(style)
    }
    injectResultStyles()

    // --- 3. UI LISTENERS ---
    if (selectAll && testCheckboxes.length) {
        selectAll.addEventListener("change", function () { testCheckboxes.forEach((cb) => (cb.checked = this.checked)) })
        testCheckboxes.forEach((cb) => cb.addEventListener("change", function () {
            const allChecked = Array.from(testCheckboxes).every((c) => c.checked)
            selectAll.checked = allChecked
        }))
    }

    if (enableNmap && nmapOptionsHolder) {
        enableNmap.addEventListener("change", function () {
            nmapOptionsHolder.style.display = this.checked ? "block" : "none"
            if (this.checked) createNmapOptions(); else nmapOptionsHolder.innerHTML = ""
        })
    }

    // --- FIX: Tambahkan fungsi createNmapOptions yang hilang ---
    function createNmapOptions() {
        if (!nmapOptionsHolder) return
        nmapOptionsHolder.innerHTML = `
            <div style="padding:12px; background:#f0f9ff; border-radius:6px; border:1px solid #bae6fd;">
                <label style="font-weight:600; display:block; margin-bottom:8px;">Target Ports:</label>
                <div style="display:flex; gap:15px; flex-wrap:wrap;">
                    <label><input type="radio" name="nmap_ports" value="top100"> Top 100</label>
                    <label><input type="radio" name="nmap_ports" value="top1000" checked> Top 1000</label>
                    <label><input type="radio" name="nmap_ports" value="all"> Semua</label>
                    <label><input type="radio" name="nmap_ports" value="specific"> Spesifik</label>
                </div>
                <div id="nmap-specific-wrapper" style="display:none; margin-top:8px;">
                    <input type="text" name="nmap_specific_ports" placeholder="Contoh: 80,443" style="width:100%; padding:6px; border-radius:4px; border:1px solid #ccc;" />
                </div>
                <div style="margin-top:10px; border-top:1px solid #bae6fd; padding-top:8px;">
                    <label style="margin-right:15px;"><input type="checkbox" name="nmap_show_os"> Deteksi OS (-O)</label>
                    <label><input type="checkbox" name="nmap_show_service" checked> Deteksi Versi (-sV)</label>
                </div>
            </div>
        `
        const radios = nmapOptionsHolder.querySelectorAll('input[name="nmap_ports"]')
        const specWrap = nmapOptionsHolder.querySelector("#nmap-specific-wrapper")
        radios.forEach((r) => r.addEventListener("change", () => {
            if (specWrap) specWrap.style.display = nmapOptionsHolder.querySelector('input[name="nmap_ports"]:checked').value === "specific" ? "block" : "none"
        }))
    }

    if (enableRatelimit && ratelimitOptionsHolder) {
        enableRatelimit.addEventListener("change", function () {
            ratelimitOptionsHolder.style.display = this.checked ? "block" : "none"
        })
    }

    // --- 4. HELPER FUNCTIONS ---
    function escapeHTML(str) { return (str || "").replace(/[&<>"'`]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]) }
    function linkify(text) { return escapeHTML(text).replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" style="color:#2563eb; text-decoration:underline;">$1</a>') }
    function formatDuration(ms) { const s = ms / 1000; return s < 60 ? `${s.toFixed(1)} detik` : `${Math.floor(s / 60)} menit ${Math.floor(s % 60)} detik` }
    
    function toggleOverlay(show) {
        const overlay = document.getElementById("translate-overlay")
        if (overlay) overlay.style.display = show ? "block" : "none"
    }

    // --- 5. TRANSLATION LOGIC (OPTIMIZED DEDUPLICATION) ---
    async function translateBulk(texts, targetLang = "id") {
        if (!texts || texts.length === 0) return []
        try {
            const res = await fetch("http://localhost:5000/translate", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ q: texts, source: "en", target: targetLang, format: "text" }),
            })
            const data = await res.json()
            if (Array.isArray(data.translatedText)) return data.translatedText
            return typeof data.translatedText === 'string' ? [data.translatedText] : texts
        } catch (e) { return texts }
    }

    async function translateResults(result, targetLang) {
        if (targetLang !== "id") return result
        const newResult = JSON.parse(JSON.stringify(result))
        
        // --- OPTIMASI: Gunakan Map untuk menyimpan teks unik saja ---
        let textMap = new Map(); 
        let pointerList = []; 

        function register(obj, keys) { 
            keys.forEach(k => { 
                if (obj && obj[k] && typeof obj[k] === 'string') { 
                    const txt = obj[k];
                    if (!textMap.has(txt)) {
                        textMap.set(txt, null); 
                    }
                    pointerList.push({ obj: obj, key: k, originalText: txt });
                } 
            }) 
        }

        // Kumpulkan semua teks
        // Fix: Cek apakah array valid sebelum forEach
        if (newResult.zap_alerts && Array.isArray(newResult.zap_alerts)) newResult.zap_alerts.forEach(a => register(a, ['description', 'solution']))
        if (newResult.cves && Array.isArray(newResult.cves)) newResult.cves.forEach(c => register(c, ['description']))
        if (newResult.impact_analysis) register(newResult.impact_analysis, ['summary', 'label'])
        if (newResult.nmap_result && newResult.nmap_result.open_ports && Array.isArray(newResult.nmap_result.open_ports)) {
            newResult.nmap_result.open_ports.forEach(p => register(p, ['advice']))
        }

        // Terjemahkan HANYA teks unik
        const uniqueTexts = Array.from(textMap.keys());
        if (uniqueTexts.length > 0) {
            const CHUNK = 50
            for (let i = 0; i < uniqueTexts.length; i += CHUNK) {
                const chunk = uniqueTexts.slice(i, i + CHUNK)
                const translatedChunk = await translateBulk(chunk, "id")
                
                chunk.forEach((original, idx) => {
                    if (translatedChunk[idx]) {
                        textMap.set(original, translatedChunk[idx]);
                    }
                });
            }

            // Distribusikan hasil ke semua objek
            pointerList.forEach(pt => {
                const trans = textMap.get(pt.originalText);
                if (trans) pt.obj[pt.key] = trans;
            });
        }
        
        return newResult
    }

    // --- BAR CHART GENERATOR ---
    function createRateLimitBarChart(codeData) {
        const container = document.getElementById('rateLimitChartContainer');
        if (!container) return;

        // Selalu buat ulang canvas untuk mencegah error "Canvas is already in use"
        container.innerHTML = '<canvas id="rateLimitChart"></canvas>';
        const canvasElement = document.getElementById('rateLimitChart');
        const ctx = canvasElement.getContext('2d');

        if (dosChart) dosChart.destroy();

        const labels = Object.keys(codeData).sort();
        const dataValues = labels.map(code => codeData[code]);
        
        const backgroundColors = labels.map(code => {
            const c = parseInt(code);
            if (c >= 200 && c < 300) return 'rgba(16, 185, 129, 0.7)'; // Green
            if (c >= 300 && c < 400) return 'rgba(59, 130, 246, 0.7)'; // Blue
            if (c === 429 || c === 403) return 'rgba(239, 68, 68, 0.7)'; // Red
            if (c === 415) return 'rgba(236, 72, 153, 0.7)'; // Pink
            if (c >= 400 && c < 500) return 'rgba(245, 158, 11, 0.7)'; // Orange
            if (c >= 500) return 'rgba(153, 27, 27, 0.7)'; // Dark Red
            return 'rgba(107, 114, 128, 0.7)';
        });

        dosChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels.map(l => `HTTP ${l}`),
                datasets: [{
                    label: 'Jumlah Request',
                    data: dataValues,
                    backgroundColor: backgroundColors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: { label: function(context) { return ` ${context.parsed.y} Request`; } }
                    }
                },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Total Request' } }
                }
            }
        });
    }

    // --- 6. RENDER FUNCTION ---
    async function renderScanResult(result) {
        let html = ""

        // 1. SCORE CARD
        if (result.security_score) {
            const score = result.security_score
            const grade = score.final_score
            let color = grade === 'A' ? '#10b981' : grade === 'B' ? '#3b82f6' : grade === 'C' ? '#ffb71cff' : (grade === 'N/A' ? '#6b7280' : '#ef4444')
            
            html += `
            <div class="score-card" style="border-top: 5px solid ${color};">
                <h2 style="margin:0; color:#4b5563;">${grade === 'N/A' ? 'Status Pengujian' : 'Penilaian Keamanan Akhir'}</h2>
                <span class="final-grade" style="color:${color}">${grade}</span>
                <div style="display:flex; justify-content:center; gap:15px; margin-top:10px;">
                    <div class="badge bg-secondary">Software: ${score.cve_score || 'N/A'}</div>
                    <div class="badge bg-secondary">Security: ${score.zap_score || 'N/A'}</div>
                </div>
                ${result.impact_analysis ? `<div style="margin-top:15px; padding:10px; background:#f8fafc; border-radius:6px; color:#555;"><strong>Ringkasan:</strong> ${escapeHTML(result.impact_analysis.summary)}</div>` : ''}
            </div>`
        }

        // 2. TECH & CVE
        html += `<h3 class="section-title">1. Vulnerability Assessment</h3>`
        if (result.tech !== null) {
            if (result.tech.length > 0) {
                html += `<div style="margin-bottom:15px;"><strong>Teknologi:</strong> ${result.tech.map(t => `<span style="background:#e5e7eb; padding:3px 8px; border-radius:4px; margin-right:5px;">${escapeHTML(t)}</span>`).join('')}</div>`
            }
            if (result.cves && result.cves.length > 0) {
                const grouped = {}
                result.cves.forEach(c => { if (!grouped[c.software]) grouped[c.software] = []; grouped[c.software].push(c) })
                Object.keys(grouped).forEach(software => {
                    const list = grouped[software]
                    let maxScore = 0
                    list.forEach(c => { if (c.cvss_score > maxScore) maxScore = c.cvss_score })
                    let badgeClass = maxScore >= 9 ? "bg-critical" : maxScore >= 7 ? "bg-high" : maxScore >= 4 ? "bg-medium" : "bg-low"
                    html += `<details class="cve-software-group"><summary class="cve-summary"><span><strong>${escapeHTML(software)}</strong></span><span class="badge ${badgeClass}">${list.length} CVE (Max ${maxScore.toFixed(1)})</span></summary><div class="cve-list-container" style="padding:0 15px;">${list.map(c => `<div class="cve-row"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;"><a href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" style="font-weight:bold; color:#2563eb;">${c.cve_id}</a><span class="badge ${c.cvss_score >= 9? "bg-critical" : c.cvss_score >= 7 ? "bg-high" : c.cvss_score >= 4 ? "bg-medium" : "bg-low"}">CVSS ${Number(c.cvss_score).toFixed(1)}</span></div><p style="margin:0 0 8px 0; font-size:0.9em; line-height:1.4;">${escapeHTML(c.description).replace(/^\[.*?\]\s*/, '')}</p><div style="font-size:0.85em; color:#059669;"><strong>Solusi:</strong> ${linkify(c.solution || "")}</div></div>`).join('')}</div></details>`
                })
            } else {
                html += `<div class="secure-box"><span class="secure-icon"></span><div><strong>Tidak Ditemukan CVE.</strong><br><small>Software aman berdasarkan versi.</small></div></div>`
            }
        } else { html += `<div class="skip-box">Test Deteksi Teknologi & CVE tidak dijalankan.</div>` }

        // 3. INJECTION
        html += `<h3 class="section-title">2. Injection Testing</h3>`
        if (result.xss_results !== null) {
             let hasInjection = false
            if (result.xss_results?.length || result.sqli_results?.length) {
                hasInjection = true
                if (result.xss_results?.length) {
                    html += `<h4>XSS</h4><table><tr><th>Endpoint</th><th>Payload</th><th>Hasil</th></tr>`
                    result.xss_results.forEach(r => html += `<tr><td>${escapeHTML(r.endpoint)}</td><td><code>${escapeHTML(r.payload)}</code></td><td style="color:red;">${escapeHTML(r.result)}</td></tr>`)
                    html += `</table>`
                }
                if (result.sqli_results?.length) {
                    html += `<h4>SQL Injection</h4><table><tr><th>Endpoint</th><th>Payload</th><th>Hasil</th></tr>`
                    result.sqli_results.forEach(r => html += `<tr><td>${escapeHTML(r.endpoint)}</td><td><code>${escapeHTML(r.payload)}</code></td><td style="color:red;">${escapeHTML(r.result)}</td></tr>`)
                    html += `</table>`
                }
            }
            if (!hasInjection) html += `<div class="secure-box"><span class="secure-icon"></span><div><strong>Aman dari Injeksi Dasar.</strong></div></div>`
        } else { html += `<div class="skip-box">Test Injection tidak dijalankan.</div>` }

        // 4. CONFIGURATION
        html += `<h3 class="section-title">3. Server Configuration</h3>`
        
        // ZAP Check (FIXED NULL CHECK)
        if (result.zap_alerts !== null) { 
            if (!result.zap_alerts || !Array.isArray(result.zap_alerts) || result.zap_alerts.length === 0) {
                html += `<div class="secure-box"><span class="secure-icon"></span><div><strong>ZAP: Konfigurasi Aman atau Tidak Ada Temuan.</strong></div></div>`
            } else {
                html += `<h4>ZAP Alerts</h4>`
                const grouped = { High: {}, Medium: {}, Low: {}, Informational: {} }
                result.zap_alerts.forEach(a => {
                    let risk = a.risk || "Informational"
                    if (/high/i.test(risk)) risk = "High"; else if (/medium/i.test(risk)) risk = "Medium"; else if (/low/i.test(risk)) risk = "Low"
                    const name = a.alert
                    if (!grouped[risk][name]) grouped[risk][name] = { description: a.description, solution: a.solution, urls: new Set() }
                    if (a.url) grouped[risk][name].urls.add(a.url)
                });
                ["High", "Medium", "Low", "Informational"].forEach(risk => {
                    const alerts = grouped[risk]
                    const keys = Object.keys(alerts)
                    if (keys.length > 0) {
                        const cls = risk === 'High' ? 'zap-high' : risk === 'Medium' ? 'zap-medium' : risk === 'Low' ? 'zap-low' : 'zap-info'
                        html += `<div style="margin:10px 0;"><span class="badge ${cls}" style="width:100%; text-align:left; padding:8px;">${risk} (${keys.length})</span></div>`
                        keys.forEach(name => {
                            const d = alerts[name]
                            html += `<details class="alert-entry"><summary>${escapeHTML(name)} <span style="color:#666;">(${d.urls.size} URL)</span></summary><div class="alert-content"><p><strong>Desc:</strong> ${escapeHTML(d.description)}</p><p><strong>Sol:</strong> ${escapeHTML(d.solution)}</p><ul class="url-list">${Array.from(d.urls).map(u => `<li>${escapeHTML(u)}</li>`).join('')}</ul></div></details>`
                        })
                    }
                })
            }
        } else { 
            html += `<div class="skip-box">Test ZAP tidak dijalankan.</div>` 
        }

        // SSL & NMAP
        if (result.ssl_result !== null) {
            const ssl = result.ssl_result
            if (!ssl) html += `<div style="padding:10px; color:red;">Gagal SSL Scan.</div>`
            else if (ssl.error) html += `<div style="padding:10px; color:red;">${escapeHTML(ssl.error)}</div>`
            else {
                html += `<h4>SSL/TLS</h4>`
                let issues = [...(ssl.weak_ciphers || []), ...(ssl.vulnerabilities || [])]
                if (issues.length === 0 && !ssl.certificate?.error) {
                    html += `<div class="secure-box"><span class="secure-icon"></span><div><strong>SSL Aman.</strong></div></div>`
                } else {
                    html += `<div style="background:#fef2f2; border:1px solid #fecaca; padding:10px; border-radius:6px; margin-bottom:10px;"><ul>${issues.map(i => `<li>${escapeHTML(i)}</li>`).join('')}</ul></div>`
                }
                if (ssl.certificate && !ssl.certificate.error) {
                    html += `<div style="font-size:0.9em; background:#f3f4f6; padding:10px; border-radius:6px;">
                    <div><strong>Subject:</strong> ${escapeHTML(ssl.certificate.subject)}</div>
                    <div><strong>Issuer:</strong> ${escapeHTML(ssl.certificate.issuer)}</div>
                    <div><strong>Valid:</strong> ${escapeHTML(ssl.certificate.valid_from).split('T')[0]} s/d ${escapeHTML(ssl.certificate.valid_until).split('T')[0]}</div>
                    <div><strong>Trusted:</strong> ${ssl.certificate.is_trusted ? 'Ya' : 'Tidak'}</div>
                    </div>`
                }
            }
        } else { html += `<div class="skip-box">Test SSL tidak dijalankan.</div>` }

        if (result.nmap_result !== null) {
            html += `<h4>Port Scanning</h4>`
            if (result.nmap_result.open_ports && result.nmap_result.open_ports.length > 0) {
                html += `<table><thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Version</th><th>Analisis</th></tr></thead><tbody>`
                result.nmap_result.open_ports.forEach(p => {
                    let cls = p.state === 'open' ? 'bg-high' : 'bg-secondary'
                    let riskCls = p.risk === 'Critical' ? 'bg-critical' : p.risk === 'High' ? 'bg-high' : p.risk === "Medium" ? 'bg-medium' : p.risk === "Safe" ? 'bg-safe' : 'bg-info'
                    html += `<tr><td><b>${p.port}</b></td><td><span class="badge ${cls}">${escapeHTML(p.state)}</span></td><td>${escapeHTML(p.service)}</td><td>${escapeHTML(p.version || "-")}</td><td><span class="badge ${riskCls}" style="font-size:0.7em;">${p.risk || "Info"}</span> <br><span style="font-size:0.85em;">${escapeHTML(p.advice || "")}</span></td></tr>`
                })
                html += `</tbody></table>`
            } else { html += `<div class="secure-box"><div><strong>Tidak Ada Port Terbuka.</strong></div></div>` }
        } else { html += `<div class="skip-box">Test Nmap tidak dijalankan.</div>` }

        // RESILIENCE & RATE LIMITING
        html += `<h3 class="section-title">4. Resilience & Rate Limiting</h3>`
        if (result.ratelimit_result !== null) {
            const rl = result.ratelimit_result
            if (rl.error) {
                 html += `<div class="error-box"><strong>Gagal Menjalankan Test:</strong><br>${escapeHTML(rl.error)}</div>`
            } else {
                const isSafe = rl.summary && (rl.summary.toUpperCase().includes("AMAN") || rl.summary.toUpperCase().includes("MITIGATED"));
                const color = isSafe ? "d1fae5" : (rl.summary && rl.summary.toUpperCase().includes("RENTAN") ? "fee2e2" : "ffedd5")
                
                html += `<div style="padding:15px; margin-bottom:15px; background:#${color}; border-radius:8px; font-weight:500;">${escapeHTML(rl.summary || "Pengujian selesai.")}</div>`
                
                if (rl.details && rl.details.codes) {
                    html += `
                    <div style="background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:15px; margin-top:10px;">
                        <h4 style="margin-top:0; color:#334155;">Visualisasi Grafik Respons</h4>
                        <div id="rateLimitChartContainer" style="height:300px; width:100%; position:relative;">
                            <canvas id="rateLimitChart"></canvas>
                        </div>
                        <div style="text-align:center; margin-top:10px; font-size:0.85em; color:#64748b;">
                        Distribusi kode status HTTP (misal: 200=Sukses, 429=Terblokir).
                        </div>
                    </div>`
                }
            }
        } else { 
            html += `<div class="skip-box">Test Rate Limit tidak dijalankan.</div>` 
        }

        document.getElementById("scan-result").innerHTML = html
        
        // --- TRIGGER CHART RENDERING (BAR CHART) ---
        if (result.ratelimit_result && result.ratelimit_result.details && result.ratelimit_result.details.codes) {
            setTimeout(() => {
                createRateLimitBarChart(result.ratelimit_result.details.codes);
            }, 400); 
        }
    
        // PDF BUTTON (Enhanced Error Handling)
        const pdfContainer = document.createElement('div');
        pdfContainer.innerHTML = `
            <div style="text-align:center; margin-top:40px; margin-bottom:20px;">
                <button id="btn-download-pdf" class="btn-submit" style="background:#1e293b; width:auto; padding:12px 30px;">Download Laporan PDF</button>
                <p id="pdf-status" style="margin-top:10px; font-size:0.9em; color:#666;"></p>
            </div>`;
        document.getElementById("scan-result").appendChild(pdfContainer);

        document.getElementById("btn-download-pdf").addEventListener("click", async function() {
            const btn = this;
            const status = document.getElementById("pdf-status");
            btn.disabled = true;
            btn.innerText = "Sedang Membuat PDF...";
            status.innerText = "Menyiapkan layout laporan...";

            try {
                const res = await fetch("/test/generate-report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ result: result })
                });

                if (!res.ok) {
                    const errText = await res.text();
                    try {
                        const jsonErr = JSON.parse(errText);
                        throw new Error(jsonErr.error || `Server Error ${res.status}`);
                    } catch (e) {
                        throw new Error(`Server Error (${res.status}): ${errText.substring(0, 100)}... (Kemungkinan data scan terlalu besar)`);
                    }
                }

                const resp = await res.json();
                if (resp.status === "success") {
                    btn.innerText = "Berhasil!";
                    status.innerHTML = `Laporan siap. <a href="${resp.download_url}" target="_blank" style="color:blue; font-weight:bold;">Klik di sini untuk download</a>`;
                    window.open(resp.download_url, '_blank' );
                } else { throw new Error(resp.error || "Gagal generate PDF"); }
            } catch (e) {
                btn.innerText = "Gagal";
                status.innerText = "Error: " + e.message;
                console.error(e);
                setTimeout(() => { btn.disabled = false; btn.innerText = "Coba Lagi"; }, 3000);
            }
        });
    }

    // --- SUBMIT HANDLER ---
    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const btn = document.getElementById("btn-start-scan"); 
            if (btn) {
                btn.disabled = true; 
                btn.classList.add("scan-btn-disabled");
                btn.innerText = "Sedang Memproses...";
            }

            const progressBar = document.getElementById("progress-bar");
            document.getElementById("progress-container").style.display = "block";
            progressBar.style.width = "5%"; progressBar.innerText = "5%";
            document.getElementById("progress-status").innerHTML = "Sedang memproses scan...";
            
            let progress = 5;
            const timer = setInterval(() => { 
                if(progress < 90) { 
                    progress += 0.4; 
                    progressBar.style.width = progress + "%"; 
                    progressBar.innerText = Math.floor(progress) + "%"; 
                }
            }, 500);

            const formData = new FormData(this);
            const tests = Array.from(document.querySelectorAll('input[name="tests"]:checked')).map(c => c.value);
            
            let rlLevel = "0";
            const isRlChecked = document.querySelector('input[name="tests"][value="ratelimit"]')?.checked;
            const rlEl = document.getElementById("ratelimit-level");
            if (isRlChecked && rlEl) {
                rlLevel = rlEl.value;
            }

            const payload = {
                url: formData.get("url"),
                cookie: formData.get("cookie_header").trim(),
                tests: tests,
                ratelimit_level: rlLevel, 
                nmap_enabled: document.getElementById("enable-nmap")?.checked || false,
                nmap_ports: document.querySelector('input[name="nmap_ports"]:checked')?.value || "top1000",
                nmap_specific_ports: document.querySelector('input[name="nmap_specific_ports"]')?.value || "",
                nmap_show_os: document.querySelector('input[name="nmap_show_os"]')?.checked || false,
                nmap_show_service: document.querySelector('input[name="nmap_show_service"]')?.checked || false,
                ssl_enabled: document.querySelector('input[name="tests"][value="ssl"]')?.checked || false,
                lang: document.getElementById("dropdown-bahasa")?.value || "en"
            };

            try {
                const res = await fetch("/test/scan-all", { 
                    method: "POST", 
                    headers: { "Content-Type": "application/json" }, 
                    body: JSON.stringify(payload) 
                });
                
                clearInterval(timer);
                
                if (!res.ok) throw new Error("Server Error");
                const data = await res.json();
                
                progressBar.style.width = "100%"; 
                progressBar.innerText = "Selesai";
                progressBar.classList.add("done");
                document.getElementById("progress-status").innerHTML = `Selesai`;

                originalResult = data;
                currentLang = document.getElementById("dropdown-bahasa").value;
                
                if(currentLang === "id") {
                    toggleOverlay(true);
                    await new Promise(r => setTimeout(r, 100));
                    translatedResult = await translateResults(originalResult, "id");
                    await renderScanResult(translatedResult);
                    toggleOverlay(false);
                } else {
                    await renderScanResult(originalResult);
                }

            } catch (err) {
                clearInterval(timer);
                progressBar.classList.add("error"); 
                progressBar.innerText = "Gagal";
                alert("Scan Error: " + err.message);
                toggleOverlay(false);
            } finally {
                if (btn) { 
                    btn.disabled = false; 
                    btn.classList.remove("scan-btn-disabled");
                    btn.innerText = "Mulai Analisis Keamanan";
                }
            }
        });
    }

    document.getElementById("dropdown-bahasa")?.addEventListener("change", async function () {
        const lang = this.value
        if (!originalResult) return
        if (lang === "id") {
            toggleOverlay(true)
            await new Promise(r => setTimeout(r, 100))
            if (!translatedResult) translatedResult = await translateResults(originalResult, "id")
            await renderScanResult(translatedResult)
            toggleOverlay(false)
        } else {
            await renderScanResult(originalResult)
        }
    })
})