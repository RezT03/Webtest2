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
    // Menyuntikkan CSS khusus untuk elemen hasil scan yang digenerate oleh JS
    function injectResultStyles() {
        if (document.getElementById("scan-result-styles")) return
        const style = document.createElement("style")
        style.id = "scan-result-styles"
        style.innerHTML = `
            /* Badges & Colors */
            .badge { display:inline-block; padding:4px 10px; border-radius:4px; color:#fff; font-weight:600; font-size:0.8em; min-width:60px; text-align:center; }
            .bg-critical { background:#000; border:1px solid #333; }
            .bg-high { background:#dc2626; }
            .bg-medium { background:#ea580c; }
            .bg-low { background:#ffe100; color:#000; }
            .bg-info { background:#2563eb; }
            .bg-safe { background:#10b981; }
            .bg-secondary { background:#6b7280; }
            
            /* ZAP Specific Colors */
            .zap-high { background:#dc2626; } 
            .zap-medium { background:#ea580c; } 
            .zap-low { background:#ffe100; } 
            .zap-info { background:#2563eb; }

            /* Score Card */
            .score-card { background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); text-align: center; margin-bottom: 30px; border: 1px solid #e5e7eb; }
            .final-grade { font-size: 3.5em; font-weight: 800; display: block; margin: 10px 0; }

            /* CVE Folding & Table Layout */
            .cve-software-group { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px; overflow: hidden; background: #fff; }
            .cve-summary { padding: 15px; background: #f8fafc; cursor: pointer; font-weight: 600; display: flex; justify-content: space-between; align-items: center; list-style: none; }
            .cve-summary:hover { background: #f1f5f9; }
            .cve-list-container { border-top: 1px solid #e5e7eb; }
            .cve-row { padding: 15px; border-bottom: 1px solid #f3f4f6; }
            .cve-row:last-child { border-bottom: none; }
            
            /* Result Boxes */
            .section-title { margin-top: 35px; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 1.3em; font-weight: 700; color: #111827; }
            .secure-box { padding: 15px; background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; border-radius: 8px; display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
            .skip-box { padding: 15px; background: #f3f4f6; color: #6b7280; border: 1px dashed #d1d5db; border-radius: 8px; text-align: center; font-style: italic; margin-bottom: 15px; }
            .secure-icon { font-size: 1.8em; }
            
            /* Details/Summary Generic */
            details.alert-entry { margin-bottom: 8px; border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; background: #fff; }
            details.alert-entry summary { padding: 12px 15px; background: #f9fafb; cursor: pointer; font-weight: 600; list-style: none; display: flex; justify-content: space-between; }
            .alert-content { padding: 15px; background: #fff; border-top: 1px solid #e5e7eb; }
            
            /* URL List */
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

    function createNmapOptions() {
        if (!nmapOptionsHolder) return
        nmapOptionsHolder.innerHTML = `
            <div style="padding:12px; background:#f0f9ff; border-radius:6px; border:1px solid #bae6fd;">
                <label style="font-weight:600; display:block; margin-bottom:8px;">Target Ports:</label>
                <div style="display:flex; gap:15px; flex-wrap:wrap;">
                    <label><input type="radio" name="nmap_ports" value="top100"> Top 100</label>
                    <label><input type="radio" name="nmap_ports" value="top1000" checked> Top 1000</label>
                    <label><input type="radio" name="nmap_ports" value="all"> Semua (Lama)</label>
                    <label><input type="radio" name="nmap_ports" value="specific"> Spesifik</label>
                </div>
                <div id="nmap-specific-wrapper" style="display:none; margin-top:8px;">
                    <input type="text" name="nmap_specific_ports" placeholder="Contoh: 80,443,8080" style="width:100%; padding:6px; border-radius:4px; border:1px solid #ccc;" />
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
        if (overlay) overlay.style.display = show ? "flex" : "none"
    }

    // --- 5. TRANSLATION LOGIC ---
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
        let textQueue = [], mapPointer = []
        function register(obj, keys) { keys.forEach(k => { if (obj && obj[k] && typeof obj[k] === 'string') { textQueue.push(obj[k]); mapPointer.push({ obj: obj, key: k }) } }) }

        if (newResult.zap_alerts) newResult.zap_alerts.forEach(a => register(a, ['description', 'solution']))
        if (newResult.cves) newResult.cves.forEach(c => register(c, ['description']))
        if (newResult.impact_analysis) register(newResult.impact_analysis, ['summary', 'label'])
        
        // Translate Nmap Advice (Opsional)
        if (newResult.nmap_result && newResult.nmap_result.open_ports) {
            newResult.nmap_result.open_ports.forEach(p => register(p, ['advice']))
        }

        if (textQueue.length > 0) {
            const CHUNK = 50
            for (let i = 0; i < textQueue.length; i += CHUNK) {
                const chunk = textQueue.slice(i, i + CHUNK)
                const translated = await translateBulk(chunk, "id")
                for (let j = 0; j < translated.length; j++) {
                    const pt = mapPointer[i + j]
                    if (pt) pt.obj[pt.key] = translated[j]
                }
            }
        }
        return newResult
    }

    // --- 6. RENDER FUNCTION ---
    async function renderScanResult(result) {
        let html = ""

        // 1. SCORE CARD (Ringkasan Atas)
        if (result.security_score) {
            const score = result.security_score
            const grade = score.final_score
            let color = grade === 'A' ? '#10b981' : grade === 'B' ? '#3b82f6' : grade === 'C' ? '#ffb71cff' : (grade === 'N/A' ? '#6b7280' : '#ef4444')
            
            html += `
            <div class="score-card" style="border-top: 5px solid ${color};">
                <h2 style="margin:0; color:#4b5563;">${grade === 'N/A' ? 'Status Pengujian' : 'Penilaian Keamanan Akhir'}</h2>
                <span class="final-grade" style="color:${color}">${grade}</span>
                
                ${grade !== 'N/A' ? `
                <div style="display:flex; justify-content:center; gap:15px; margin-top:10px;">
                    <div class="badge bg-secondary">Software: ${score.cve_score}</div>
                    <div class="badge bg-secondary">Security: ${score.zap_score}</div>
                </div>` : ''}
                
                ${result.impact_analysis ? `<div style="margin-top:15px; padding:10px; background:#f8fafc; border-radius:6px; color:#555;"><strong>Ringkasan:</strong> ${escapeHTML(result.impact_analysis.summary)}</div>` : ''}
            </div>`
        }

        // 2. TECH & CVE (Accordion)
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

                    html += `
                    <details class="cve-software-group">
                        <summary class="cve-summary">
                            <span><strong>${escapeHTML(software)}</strong></span>
                            <span class="badge ${badgeClass}">${list.length} CVE (Max ${maxScore.toFixed(1)})</span>
                        </summary>
                        <div class="cve-list-container" style="padding:0 15px;">
                            ${list.map(c => {
                        let riskCls = c.cvss_score >= 9? "bg-critical" : c.cvss_score >= 7 ? "bg-high" : c.cvss_score >= 4 ? "bg-medium" : "bg-low"
                        let desc = escapeHTML(c.description).replace(/^\[.*?\]\s*/, '')
                        return `
                                <div class="cve-row">
                                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                                        <a href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" style="font-weight:bold; color:#2563eb;">${c.cve_id}</a>
                                        <span class="badge ${riskCls}">CVSS ${Number(c.cvss_score).toFixed(1)}</span>
                                    </div>
                                    <p style="margin:0 0 8px 0; font-size:0.9em; line-height:1.4;">${desc}</p>
                                    <div style="font-size:0.85em; color:#059669;"><strong>Solusi:</strong> ${linkify(c.solution || "")}</div>
                                </div>`
                    }).join('')}
                        </div>
                    </details>`
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
        
        // ZAP
        if (result.zap_alerts !== null) {
            if (!result.zap_alerts || result.zap_alerts.length === 0) {
                html += `<div class="secure-box"><span class="secure-icon"></span><div><strong>ZAP: Konfigurasi Aman.</strong></div></div>`
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
        } else { html += `<div class="skip-box">Test ZAP tidak dijalankan.</div>` }

        // SSL
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

        // NMAP
        if (result.nmap_result !== null) {
            html += `<h4>Port Scanning</h4>`
            if (result.nmap_result.open_ports && result.nmap_result.open_ports.length > 0) {
                html += `<table><thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Version</th><th>Analisis</th></tr></thead><tbody>`
                result.nmap_result.open_ports.forEach(p => {
                    let cls = p.state === 'open' ? 'bg-high' : 'bg-secondary'
                    let riskCls = p.risk === 'Critical' ? 'bg-critical' : p.risk === 'High' ? 'bg-high' : p.risk === "Medium" ? 'bg-medium' : p.risk === "Safe" ? 'bg-safe' : 'bg-info'
                    html += `<tr>
                        <td><b>${p.port}</b></td>
                        <td><span class="badge ${cls}">${escapeHTML(p.state)}</span></td>
                        <td>${escapeHTML(p.service)}</td>
                        <td>${escapeHTML(p.version || "-")}</td>
                        <td><span class="badge ${riskCls}" style="font-size:0.7em;">${p.risk || "Info"}</span> <br><span style="font-size:0.85em;">${escapeHTML(p.advice || "")}</span></td>
                    </tr>`
                })
                html += `</tbody></table>`
            } else { html += `<div class="secure-box"><div><strong>Tidak Ada Port Terbuka.</strong></div></div>` }
        } else { html += `<div class="skip-box">Test Nmap tidak dijalankan.</div>` }

        // 5. RESILIENCE
        if (result.ratelimit_result !== null) {
            html += `<h3 class="section-title">4. Resilience</h3>`
            const rl = result.ratelimit_result
            const isSafe = rl.summary.includes("AMAN")
            const color = isSafe ? "d1fae5" : "fee2e2"
            html += `<div style="padding:15px; background:#${color}; border-radius:8px;">${escapeHTML(rl.summary)}</div>`
        } else { html += `<h3 class="section-title">4. Resilience</h3><div class="skip-box">Test Rate Limit tidak dijalankan.</div>` }

        document.getElementById("scan-result").innerHTML = html
        if (result.dos_timeline) setTimeout(() => createDosChart(result.dos_timeline), 100)
    }

    // --- 7. SUBMIT HANDLER ---
    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        scanForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            
            // FIX: Gunakan ID eksplisit agar tombol pasti ketemu
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
            
            const start = Date.now();
            let progress = 5;
            const timer = setInterval(() => { 
                if(progress < 90) { 
                    progress += 0.2; 
                    progressBar.style.width = progress + "%"; 
                    progressBar.innerText = Math.floor(progress) + "%"; 
                }
            }, 500);

            const formData = new FormData(this);
            const tests = Array.from(document.querySelectorAll('input[name="tests"]:checked')).map(c => c.value);
            
            // FIX: Ambil Level Rate Limit dengan aman
            let rlLevel = "1";
            const rlEl = document.getElementById("ratelimit-level");
            if(rlEl) rlLevel = rlEl.value;

            const payload = {
                url: formData.get("url"),
                cookie: formData.get("cookie_header").trim(),
                tests: tests,
                ratelimit_level: rlLevel,
                nmap_enabled: document.getElementById("enable-nmap")?.checked || false,
                nmap_ports: document.querySelector('input[name="nmap_ports"]:checked')?.value || "top1000",
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
                document.getElementById("progress-status").innerHTML = `Selesai dalam <strong>${formatDuration(Date.now()-start)}</strong>`;

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
                console.error(err);
                alert("Scan Error: " + err.message);
                toggleOverlay(false);
            } finally {
                // Re-enable button
                if (btn) { 
                    btn.disabled = false; 
                    btn.classList.remove("scan-btn-disabled");
                    btn.innerText = "Mulai Analisis Keamanan";
                }
            }
        });
    }

    // Dropdown Bahasa
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