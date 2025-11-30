document.addEventListener("DOMContentLoaded", function () {
    let dosChart = null;
    let originalResult = null;
    let translatedResult = null;
    
    // --- 1. STYLE INJECTION (UPDATE UNTUK FOLDING) ---
    function injectResultStyles() {
        if (document.getElementById("scan-result-styles")) return;
        const style = document.createElement("style");
        style.id = "scan-result-styles";
        style.innerHTML = `
            /* Badges & General */
            .badge { display:inline-block; padding:4px 10px; border-radius:4px; color:#fff; font-weight:600; font-size:0.8em; min-width:60px; text-align:center; }
            .bg-critical { background:#000; border:1px solid #333; }
            .bg-high { background:#dc2626; }
            .bg-medium { background:#ea580c; }
            .bg-low { background:#ca8a04; color:#000; }
            .bg-safe { background:#10b981; }
            .section-title { margin-top: 35px; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 1.3em; font-weight: 700; color: #111827; }
            .secure-box { padding: 15px; background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; border-radius: 8px; display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
            .skip-box { padding: 15px; background: #f3f4f6; color: #6b7280; border: 1px dashed #d1d5db; border-radius: 8px; margin-bottom: 15px; font-style: italic; }

            /* --- CVE FOLDING STYLES (BARU) --- */
            .cve-software-group { 
                border: 1px solid #e5e7eb; 
                border-radius: 8px; 
                margin-bottom: 12px; 
                overflow: hidden; 
                background: #fff; 
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            }
            /* Header Software (Bisa diklik) */
            .cve-summary { 
                padding: 15px; 
                background: #f8fafc; 
                cursor: pointer; 
                font-weight: 600; 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
                list-style: none; /* Hilangkan segitiga default browser */
            }
            .cve-summary::-webkit-details-marker { display: none; } /* Chrome fix */
            .cve-summary:hover { background: #f1f5f9; }
            
            /* Container list CVE didalamnya */
            .cve-list-container { border-top: 1px solid #e5e7eb; background: #fff; }
            
            /* Baris per CVE */
            .cve-row { 
                padding: 15px; 
                border-bottom: 1px solid #f3f4f6; 
                transition: background 0.2s;
            }
            .cve-row:last-child { border-bottom: none; }
            .cve-row:hover { background: #fafafa; }
            
            .cve-header-line { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
            .cve-id-link { font-weight: 700; color: #2563eb; text-decoration: none; font-family: monospace; font-size: 1.1em; }
            .cve-id-link:hover { text-decoration: underline; }
            .cve-desc { font-size: 0.95em; line-height: 1.5; color: #374151; margin: 0 0 8px 0; }
            .cve-solution { font-size: 0.9em; color: #059669; background: #ecfdf5; padding: 8px; border-radius: 6px; border-left: 3px solid #10b981; }

            /* Score Card */
            .score-card { background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); text-align: center; margin-top: 30px; border: 1px solid #e5e7eb; }
            .final-grade { font-size: 3.5em; font-weight: 800; display: block; margin: 10px 0; }
            .btn-disabled { opacity: 0.6; cursor: not-allowed !important; pointer-events: none; }
        `;
        document.head.appendChild(style);
    }
    injectResultStyles();

    // --- HELPERS ---
    function toggleOverlay(show) {
        const overlay = document.getElementById("translate-overlay");
        if (overlay) overlay.style.display = show ? "flex" : "none";
    }

    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function linkify(text) {
        if (!text) return "";
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        return text.replace(urlRegex, function(url) {
            return `<a href="${url}" target="_blank" style="color:#2563eb; text-decoration:underline;">${url}</a>`;
        });
    }

    // --- 5. TRANSLATE (Tidak berubah) ---
    async function translateBulk(texts, targetLang = "id") {
        if (!texts || texts.length === 0) return [];
        try {
            const res = await fetch("http://localhost:5000/translate", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ q: texts, source: "en", target: targetLang, format: "text" }),
            });
            const data = await res.json();
            if (Array.isArray(data.translatedText)) return data.translatedText;
            return typeof data.translatedText === 'string' ? [data.translatedText] : texts;
        } catch (e) { return texts; }
    }

    async function translateResults(result, targetLang) {
        if (targetLang !== "id") return result;
        const newResult = JSON.parse(JSON.stringify(result));
        let textQueue = [], mapPointer = [];
        function register(obj, keys) { keys.forEach(k => { if (obj && obj[k] && typeof obj[k] === 'string') { textQueue.push(obj[k]); mapPointer.push({ obj: obj, key: k }); }}); }

        if (newResult.zap_alerts) newResult.zap_alerts.forEach(a => register(a, ['description', 'solution']));
        if (newResult.cves) newResult.cves.forEach(c => register(c, ['description']));
        if (newResult.impact_analysis) register(newResult.impact_analysis, ['summary', 'label']);

        if (textQueue.length > 0) {
            const CHUNK = 50;
            for (let i = 0; i < textQueue.length; i += CHUNK) {
                const chunk = textQueue.slice(i, i + CHUNK);
                const translated = await translateBulk(chunk, "id");
                for (let j = 0; j < translated.length; j++) {
                    const pt = mapPointer[i + j]; if (pt) pt.obj[pt.key] = translated[j];
                }
            }
        }
        return newResult;
    }

    // --- 6. RENDER FUNCTION (UPDATED) ---
    async function renderScanResult(result) {
        let html = "";

        // 1. SCORE CARD (Top)
        if (result.security_score) {
            const score = result.security_score;
            const grade = score.final_score;
            let color = grade === 'A' ? '#10b981' : grade === 'B' ? '#3b82f6' : grade === 'C' ? '#ff880aff' : (grade === 'N/A' ? '#6b7280' : '#ef4444');
            let summaryText = result.impact_analysis ? escapeHTML(result.impact_analysis.summary) : "";
            
            html += `<div class="score-card" style="border-top: 5px solid ${color};">
                <h2 style="margin:0; color:#4b5563;">${grade === 'N/A' ? 'Status Scan' : 'Penilaian Keamanan Akhir'}</h2>
                <span class="final-grade" style="color:${color}">${grade}</span>
                ${grade !== 'N/A' ? `<div style="display:flex; justify-content:center; gap:15px; margin-top:10px;">
                    <div class="badge bg-secondary" style="background:#e5e7eb; color:#374151;">Software: ${score.cve_score}</div>
                    <div class="badge bg-secondary" style="background:#e5e7eb; color:#374151;">Security: ${score.zap_score}</div>
                </div>` : ''}
                <div style="margin-top:15px; font-size:0.95em; color:#555;">${summaryText}</div>
            </div>`;
        }

        // ============================================================
        // 2. TECH & CVE (FOLDING MODE - REVISI UTAMA)
        // ============================================================
        html += `<h3 class="section-title">1. Vulnerability Assessment</h3>`;
        
        if (result.tech !== null) {
            // Render Daftar Teknologi
            if (result.tech.length > 0) {
                html += `<div style="margin-bottom:20px; padding:15px; background:#f8fafc; border-radius:8px; border:1px solid #e2e8f0;">
                    <strong style="display:block; margin-bottom:8px; color:#475569;">Teknologi Terdeteksi:</strong> 
                    ${result.tech.map(t => `<span style="display:inline-block; background:#fff; border:1px solid #cbd5e1; padding:4px 10px; border-radius:20px; margin-right:5px; margin-bottom:5px; font-size:0.9em; color:#334155;">${escapeHTML(t)}</span>`).join('')}
                </div>`;
            } else { 
                html += `<div style="margin-bottom:15px; color:#666;"><em>Tidak ada teknologi spesifik terdeteksi.</em></div>`; 
            }

            // Render CVE dengan Folding
            if (result.cves && result.cves.length > 0) {
                
                // 1. Grouping Logic: Kelompokkan CVE berdasarkan Nama Software
                const grouped = {};
                result.cves.forEach(c => {
                    const softwareName = c.software || "Unknown Software";
                    if (!grouped[softwareName]) grouped[softwareName] = [];
                    grouped[softwareName].push(c);
                });

                // 2. Render Loop per Group (Software)
                Object.keys(grouped).forEach(software => {
                    const list = grouped[software];
                    
                    // Hitung Max Risk untuk Badge di Header
                    let maxScore = 0;
                    list.forEach(c => { 
                        const s = parseFloat(c.cvss_score || 0);
                        if(s > maxScore) maxScore = s; 
                    });
                    
                    let headerBadgeClass = maxScore >= 9 ? "bg-critical" : maxScore >= 7 ? "bg-high" : maxScore >= 4 ? "bg-medium" : "bg-low";
                    
                    // Buat elemen DETAILS (Folding)
                    html += `
                    <details class="cve-software-group">
                        <summary class="cve-summary">
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="font-size:1.05em; color:#1e293b;">${escapeHTML(software)}</span>
                            </div>
                            <span class="badge ${headerBadgeClass}">
                                ${list.length} Issue${list.length > 1 ? 's' : ''} (Max CVSS ${maxScore.toFixed(1)}) ▾
                            </span>
                        </summary>
                        
                        <div class="cve-list-container">
                            ${list.map(cve => {
                                const score = parseFloat(cve.cvss_score || 0);
                                let riskCls = score >= 9 ? "bg-critical" : score >= 7 ? "bg-high" : score >= 4 ? "bg-medium" : "bg-low";
                                let desc = escapeHTML(cve.description).replace(/^\[.*?\]\s*/, '').replace(/^\|.*?\|\s*/, '');
                                
                                return `
                                <div class="cve-row">
                                    <div class="cve-header-line">
                                        <a href="https://nvd.nist.gov/vuln/detail/${cve.cve_id}" target="_blank" class="cve-id-link">
                                            ${cve.cve_id} <span style="font-size:0.8em; color:#9ca3af; font-weight:normal;">↗</span>
                                        </a>
                                        <span class="badge ${riskCls}">CVSS ${score.toFixed(1)}</span>
                                    </div>
                                    <p class="cve-desc">${desc}</p>
                                    <div class="cve-solution">
                                        <strong>Solusi:</strong> ${linkify(cve.solution || "Update ke versi terbaru atau lihat advisory resmi.")}
                                    </div>
                                </div>`;
                            }).join('')}
                        </div>
                    </details>`;
                });

            } else {
                html += `<div class="secure-box"><div><strong>Tidak Ditemukan CVE.</strong><br><small>Versi software yang terdeteksi tidak memiliki kerentanan publik yang diketahui.</small></div></div>`;
            }
        } else { 
            html += `<div class="skip-box">Test Deteksi Teknologi & CVE tidak dijalankan.</div>`; 
        }
        // ============================================================

        // 3. INJECTION
        html += `<h3 class="section-title">2. Injection Testing</h3>`;
        if (result.xss_results !== null) {
            let hasInjection = false;
            if (result.xss_results?.length) {
                hasInjection = true;
                html += `<h4>XSS</h4><table><tr><th>Endpoint</th><th>Payload</th><th>Hasil</th></tr>`;
                result.xss_results.forEach(r => html+=`<tr><td>${escapeHTML(r.endpoint)}</td><td><code>${escapeHTML(r.payload)}</code></td><td style="color:red;">${escapeHTML(r.result)}</td></tr>`);
                html += `</table>`;
            }
            if (result.sqli_results?.length) {
                hasInjection = true;
                html += `<h4>SQL Injection</h4><table><tr><th>Endpoint</th><th>Payload</th><th>Hasil</th></tr>`;
                result.sqli_results.forEach(r => html+=`<tr><td>${escapeHTML(r.endpoint)}</td><td><code>${escapeHTML(r.payload)}</code></td><td style="color:red;">${escapeHTML(r.result)}</td></tr>`);
                html += `</table>`;
            }
            if (!hasInjection) html += `<div class="secure-box"><span style="font-size:1.5em"></span><div><strong>Aman dari Injeksi Dasar.</strong></div></div>`;
        } else { html += `<div class="skip-box">Test Injection tidak dijalankan.</div>`; }

        // 4. CONFIG
        html += `<h3 class="section-title">3. Server Configuration</h3>`;
        if (result.zap_alerts !== null) {
            if (!result.zap_alerts || result.zap_alerts.length === 0) {
                html += `<div class="secure-box"><div><strong>ZAP: Konfigurasi Aman.</strong></div></div>`;
            } else {
                html += `<h4>ZAP Alerts</h4>`;
                const grouped = { High: {}, Medium: {}, Low: {}, Informational: {} };
                result.zap_alerts.forEach(a => {
                    let risk = a.risk || "Informational";
                    if (/high/i.test(risk)) risk = "High"; else if (/medium/i.test(risk)) risk = "Medium"; else if (/low/i.test(risk)) risk = "Low"; else risk = "Informational";
                    const name = a.alert;
                    if (!grouped[risk][name]) grouped[risk][name] = { description: a.description, solution: a.solution, urls: new Set() };
                    if(a.url) grouped[risk][name].urls.add(a.url);
                });
                ["High", "Medium", "Low", "Informational"].forEach(risk => {
                    const alerts = grouped[risk];
                    const keys = Object.keys(alerts);
                    if (keys.length > 0) {
                        const cls = risk === 'High' ? 'zap-high' : risk === 'Medium' ? 'zap-medium' : risk === 'Low' ? 'zap-low' : 'zap-info';
                        html += `<div style="margin:10px 0;"><span class="badge ${cls}" style="font-size:1em; width:100%; text-align:left; padding:8px;">${risk} (${keys.length})</span></div>`;
                        keys.forEach(name => {
                            const d = alerts[name];
                            html += `<details class="alert-entry"><summary>${escapeHTML(name)} <span style="color:#666;">(${d.urls.size} URL)</span></summary><div class="alert-content"><p><strong>Desc:</strong> ${escapeHTML(d.description)}</p><p><strong>Sol:</strong> ${escapeHTML(d.solution)}</p><ul class="url-list">${Array.from(d.urls).map(u=>`<li>${escapeHTML(u)}</li>`).join('')}</ul></div></details>`;
                        });
                    }
                });
            }
        } else { html += `<div class="skip-box">Test ZAP tidak dijalankan.</div>`; }

        if (result.ssl_result !== null) {
            const ssl = result.ssl_result;
            if (!ssl) html += `<div style="padding:10px; color:red;">Gagal SSL Scan.</div>`;
            else {
                html += `<h4>SSL/TLS Security</h4>`;
                let issues = [...(ssl.weak_ciphers || []), ...(ssl.vulnerabilities || [])];
                if (issues.length === 0 && !ssl.certificate?.error) {
                    html += `<div class="secure-box"><div><strong>SSL Aman.</strong></div></div>`;
                } else {
                    html += `<div style="background:#fef2f2; border:1px solid #fecaca; padding:10px; border-radius:6px; color:#991b1b; margin-bottom:10px;"><ul>${issues.map(i => `<li>${escapeHTML(i)}</li>`).join('')}</ul></div>`;
                }
                if (ssl.certificate && !ssl.certificate.error) {
                    html += `<div style="font-size:0.9em; background:#f3f4f6; padding:10px; border-radius:6px;"><div><strong>Subject:</strong> ${escapeHTML(ssl.certificate.subject)}</div><div><strong>Issuer:</strong> ${escapeHTML(ssl.certificate.issuer)}</div><div><strong>Trusted:</strong> ${ssl.certificate.is_trusted ? '<span style="color:green">YA</span>' : '<span style="color:red">TIDAK</span>'}</div></div>`;
                }
            }
        } else { html += `<div class="skip-box">Test SSL tidak dijalankan.</div>`; }

        if (result.nmap_result !== null) {
            html += `<h4>Port Scanning</h4>`;
            if (result.nmap_result.open_ports && result.nmap_result.open_ports.length > 0) {
                html += `<table><thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Analisis</th></tr></thead><tbody>`;
                result.nmap_result.open_ports.forEach(p => {
                    let cls = p.state === 'open' ? 'bg-high' : 'bg-secondary';
                    html += `<tr><td><b>${p.port}</b></td><td><span class="badge ${cls}">${escapeHTML(p.state)}</span></td><td>${escapeHTML(p.service)} ${escapeHTML(p.version||"")}</td><td>${escapeHTML(p.advice||"")}</td></tr>`;
                });
                html += `</tbody></table>`;
            } else { html += `<div class="secure-box"><div><strong>Tidak Ada Port Terbuka.</strong></div></div>`; }
        } else { html += `<div class="skip-box">Test Nmap tidak dijalankan.</div>`; }

        // 5. RESILIENCE
        if (result.ratelimit_result !== null) {
             html += `<h3 class="section-title">4. Resilience</h3>`;
             const rl = result.ratelimit_result;
             const isSafe = rl.summary.includes("AMAN");
             const color = isSafe ? "d1fae5" : "fee2e2";
             html += `<div style="padding:15px; background:#${color}; border-radius:8px;">${escapeHTML(rl.summary)}</div>`;
        } else { html += `<h3 class="section-title">4. Resilience</h3><div class="skip-box">Test Rate Limit tidak dijalankan.</div>`; }

        document.getElementById("scan-result").innerHTML = html;
    }

    // --- 7. FORM SUBMIT (SAMA PERSIS) ---
    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const btn = document.getElementById('btn-start-scan');
            
            btn.disabled = true;
            btn.classList.add("btn-disabled");
            btn.innerText = "Sedang Memproses...";

            const progressBar = document.getElementById("progress-bar");
            document.getElementById("progress-container").style.display = "block";
            
            const start = Date.now();
            let w = 0;
            const timer = setInterval(() => { 
                if(w < 95) { w += 0.5; progressBar.style.width = w+"%"; progressBar.innerText = Math.floor(w)+"%"; }
            }, 500);
            // document.getElementById("progress-status").innerHTML = `Selesai dalam <strong>${formatDuration(Date.now()-start)}</strong>`;
            try {
                const formData = new FormData(this);
                const payload = {
                    url: formData.get("url"),
                    cookie: formData.get("cookie_header").trim(),
                    tests: Array.from(document.querySelectorAll('input[name="tests"]:checked')).map(c => c.value),
                    lang: document.getElementById("dropdown-bahasa")?.value || "en"
                };

                const res = await fetch("/test/scan-all", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
                clearInterval(timer);
                
                if (!res.ok) throw new Error("Server Error");
                const data = await res.json();
                
                progressBar.style.width = "100%"; progressBar.innerText = "Selesai";
                progressBar.classList.add("done");
                
                originalResult = data;
                const lang = document.getElementById("dropdown-bahasa").value;
                
                if(lang === "id") {
                    toggleOverlay(true);
                    await new Promise(r => setTimeout(r, 100));
                    translatedResult = await translateResults(originalResult, "id");
                    renderScanResult(translatedResult);
                    toggleOverlay(false);
                } else {
                    renderScanResult(originalResult);
                }

            } catch (err) {
                clearInterval(timer);
                progressBar.classList.add("error");
                alert("Scan Error: " + err.message);
                toggleOverlay(false);
            } finally {
                btn.disabled = false;
                btn.classList.remove("btn-disabled");
                btn.innerText = "Mulai Pengujian Keamanan";
            }
        });
    }
    
    // --- Bahasa Handler ---
    document.getElementById("dropdown-bahasa")?.addEventListener("change", async function () {
        const lang = this.value;
        if (!originalResult) return;
        if (lang === "id") {
            toggleOverlay(true);
            await new Promise(r => setTimeout(r, 100));
            if (!translatedResult) translatedResult = await translateResults(originalResult, "id");
            await renderScanResult(translatedResult);
            toggleOverlay(false);
        } else {
            await renderScanResult(originalResult);
        }
    });
});