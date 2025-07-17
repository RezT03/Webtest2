document.addEventListener("DOMContentLoaded", function () {
	// Global variable untuk chart
	let dosChart = null;

	// Toggle DoS options
	document.getElementById("enable-dos").addEventListener("change", function () {
		document.getElementById("dos-options").style.display = this.checked
			? "block"
			: "none"
	})

	// Auto packet size
	document.getElementById("auto-packet-size").onclick = async function () {
		const url = document.getElementById("url").value
		if (url) {
			try {
				const res = await fetch(
					`/test/page-size?url=` + encodeURIComponent(url),
				)
				const data = await res.json()
				if (data.size) {
					document.getElementById("packet_size").value = data.size
				}
			} catch (e) {
				alert("Gagal mendapatkan ukuran otomatis.")
			}
		} else {
			alert("Isi URL terlebih dahulu.")
		}
	}

	// Fungsi untuk menentukan interval optimal berdasarkan durasi
	function getOptimalInterval(totalDuration) {
		if (totalDuration <= 60) return 1;      // 1 detik untuk <= 60 detik
		if (totalDuration <= 100) return 5;     // 5 detik untuk 60-100 detik
		if (totalDuration <= 300) return 10;    // 10 detik untuk 100-300 detik
		return 15;                              // 15 detik untuk > 300 detik
	}

	// Fungsi untuk agregasi data berdasarkan interval
	function aggregateData(data, interval) {
		if (interval === 1) return data; // Tidak perlu agregasi untuk interval 1 detik
		
		const grouped = {};
		
		data.forEach(point => {
			const bucket = Math.floor(point.detik / interval) * interval;
			if (!grouped[bucket]) {
				grouped[bucket] = {
					detik: bucket,
					pending: 0,
					connected: 0,
					error: 0,
					closed: 0,
					service_available: true,
					count: 0
				};
			}
			
			// Akumulasi nilai untuk rata-rata
			grouped[bucket].pending += point.pending || 0;
			grouped[bucket].connected += point.connected || 0;
			grouped[bucket].error += point.error || 0;
			grouped[bucket].closed += point.closed || 0;
			grouped[bucket].service_available = grouped[bucket].service_available && (point.service_available || false);
			grouped[bucket].count++;
		});
		
		// Hitung rata-rata dan urutkan
		return Object.values(grouped).map(bucket => ({
			detik: bucket.detik,
			pending: Math.round(bucket.pending / bucket.count),
			connected: Math.round(bucket.connected / bucket.count),
			error: Math.round(bucket.error / bucket.count),
			closed: Math.round(bucket.closed / bucket.count),
			service_available: bucket.service_available
		})).sort((a, b) => a.detik - b.detik);
	}

	// Function untuk membuat DoS chart dengan optimasi
	function createDosChart(timelineData) {
		const ctx = document.getElementById("dosChart")
		if (!ctx) {
			console.error("Canvas dosChart tidak ditemukan")
			return
		}

		// Hapus chart lama jika ada
		if (dosChart) {
			dosChart.destroy()
			dosChart = null
		}

		// Validasi dan default data
		if (!timelineData || timelineData.length === 0) {
			console.warn("Data timeline kosong, menggunakan data default")
			timelineData = [
				{ detik: 0, pending: 0, connected: 0, error: 0, closed: 0, service_available: true }
			]
		}

		// Hitung durasi total test
		const totalDuration = Math.max(...timelineData.map(t => t.detik || 0));
		const interval = getOptimalInterval(totalDuration);
		
		// Agregasi data berdasarkan interval
		const processedData = aggregateData(timelineData, interval);

		console.log(`Total duration: ${totalDuration}s, Using interval: ${interval}s, Data points: ${processedData.length}`);

		// Prepare data dengan validasi
		const labels = processedData.map(t => `${t.detik || 0}s`)
		const pending = processedData.map(t => t.pending || 0)
		const connected = processedData.map(t => t.connected || 0)
		const error = processedData.map(t => t.error || 0)
		const closed = processedData.map(t => t.closed || 0)
		const serviceAvailable = processedData.map(t => t.service_available ? 1 : 0)

		// Konfigurasi chart yang diperbaiki
		const config = {
			type: 'line',
			data: {
				labels: labels,
				datasets: [
					{
						label: 'Pending',
						data: pending,
						borderColor: '#6c757d',
						backgroundColor: 'rgba(108, 117, 125, 0.1)',
						fill: false,
						tension: 0.2,
						pointRadius: Math.min(4, Math.max(1, 100 / processedData.length)), // Sesuaikan ukuran point
						pointHoverRadius: 6,
						pointBackgroundColor: '#6c757d',
						pointBorderColor: '#6c757d',
						yAxisID: 'y'
					},
					{
						label: 'Connected',
						data: connected,
						borderColor: '#28a745',
						backgroundColor: 'rgba(40, 167, 69, 0.1)',
						fill: false,
						tension: 0.2,
						pointRadius: Math.min(4, Math.max(1, 100 / processedData.length)),
						pointHoverRadius: 6,
						pointBackgroundColor: '#28a745',
						pointBorderColor: '#28a745',
						yAxisID: 'y1'
					},
					{
						label: 'Error',
						data: error,
						borderColor: '#dc3545',
						backgroundColor: 'rgba(220, 53, 69, 0.1)',
						fill: false,
						tension: 0.2,
						pointRadius: Math.min(4, Math.max(1, 100 / processedData.length)),
						pointHoverRadius: 6,
						pointBackgroundColor: '#dc3545',
						pointBorderColor: '#dc3545',
						yAxisID: 'y1'
					},
					{
						label: 'Closed',
						data: closed,
						borderColor: '#007bff',
						backgroundColor: 'rgba(0, 123, 255, 0.1)',
						fill: false,
						tension: 0.2,
						pointRadius: Math.min(4, Math.max(1, 100 / processedData.length)),
						pointHoverRadius: 6,
						pointBackgroundColor: '#007bff',
						pointBorderColor: '#007bff',
						yAxisID: 'y1'
					},
					{
						label: 'Service Available',
						data: serviceAvailable,
						borderColor: '#20c997',
						backgroundColor: 'rgba(32, 201, 151, 0.2)',
						fill: true,
						stepped: true,
						pointRadius: Math.min(3, Math.max(1, 80 / processedData.length)),
						pointHoverRadius: 5,
						pointBackgroundColor: '#20c997',
						pointBorderColor: '#20c997',
						yAxisID: 'y1'
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				interaction: {
					mode: 'index',
					intersect: false
				},
				plugins: {
					title: {
						display: true,
						text: `DoS Test - Connection Timeline (Interval: ${interval}s)`,
						font: {
							size: 16,
							weight: 'bold'
						},
						color: '#222'
					},
					legend: {
						display: true,
						position: 'top',
						labels: {
							font: {
								size: 12
							},
							color: '#222',
							usePointStyle: true,
							padding: 20
						}
					},
					tooltip: {
						enabled: true,
						backgroundColor: 'rgba(0, 0, 0, 0.8)',
						titleColor: '#fff',
						bodyColor: '#fff',
						borderColor: '#ddd',
						borderWidth: 1,
						cornerRadius: 6,
						callbacks: {
							title: function(context) {
								return `Time: ${context[0].label}`;
							},
							label: function(context) {
								const label = context.dataset.label || '';
								const value = context.parsed.y;
								
								if (label === 'Service Available') {
									return `${label}: ${value === 1 ? 'Available' : 'Down'}`;
								}
								
								// Tambahkan info interval jika > 1
								if (interval > 1) {
									return `${label}: ${value} (avg over ${interval}s)`;
								}
								return `${label}: ${value}`;
							}
						}
					}
				},
				scales: {
					x: {
						title: {
							display: true,
							text: `Time (seconds) - Interval: ${interval}s`,
							font: {
								size: 14,
								weight: 'bold'
							},
							color: '#222'
						},
						ticks: {
							font: {
								size: 12
							},
							color: '#222',
							// Sesuaikan jumlah ticks untuk data yang banyak
							maxTicksLimit: Math.min(20, Math.max(5, Math.floor(processedData.length / 2)))
						},
						grid: {
							color: 'rgba(0, 0, 0, 0.1)'
						}
					},
					y: {
						type: 'linear',
						display: true,
						position: 'left',
						title: {
							display: true,
							text: 'Pending Connections',
							font: {
								size: 14,
								weight: 'bold'
							},
							color: '#222'
						},
						ticks: {
							font: {
								size: 12
							},
							color: '#222'
						},
						grid: {
							color: 'rgba(0, 0, 0, 0.1)'
						},
						beginAtZero: true
					},
					y1: {
						type: 'linear',
						display: true,
						position: 'right',
						title: {
							display: true,
							text: 'Connected/Error/Closed/Service',
							font: {
								size: 14,
								weight: 'bold'
							},
							color: '#222'
						},
						ticks: {
							font: {
								size: 12
							},
							color: '#222'
						},
						grid: {
							drawOnChartArea: false,
							color: 'rgba(0, 0, 0, 0.1)'
						},
						beginAtZero: true
					}
				}
			}
		}

		try {
			dosChart = new Chart(ctx, config)
		} catch (error) {
			console.error("Error creating chart:", error)
		}
	}

	// Form submit (bagian yang sama, tidak perlu diubah)
	const BASE_URL = "http://backend:3001"
	document
		.getElementById("scan-form")
		.addEventListener("submit", async function (e) {
			e.preventDefault()
			const progressContainer = document.getElementById("progress-container")
			const progressBar = document.getElementById("progress-bar")
			progressContainer.style.display = "block"
			progressBar.style.width = "20%"
			progressBar.innerText = "Memulai..."

			let progress = 0
			const interval = setInterval(() => {
				if (progress < 80) {
					progress += 5
					progressBar.style.width = progress + "%"
					progressBar.innerText = progress + "%"
				}
			}, 1000)

			const formData = new FormData(this)
			const data = Object.fromEntries(formData.entries())
			data.dos_enabled = document.getElementById("enable-dos").checked
			data.stop_on_down = document.getElementById("stop-on-down").checked

			try {
				const res = await fetch(`/test/scan-all`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(data),
				})
				const result = await res.json()
				let html = ""

				// Render hasil scan
				// 1. Daftar software terdeteksi
				if (result.tech && result.tech.length) {
					html += `<h3 class="section-title">Teknologi Terdeteksi</h3>
    <table>
        <tr class="medium-header"><th>Nama Software</th><th>Versi</th><th>CVE Ditemukan</th></tr>`
					result.tech.forEach((sw) => {
						const [name, ...verArr] = sw.split(" ")
						const ver = verArr.join(" ")
						const cveCount = (result.cves || []).filter((cve) =>
							(cve.software || "").toLowerCase().startsWith(sw.toLowerCase()),
						).length
						html += `<tr>
            <td>${name}</td>
            <td>${ver}</td>
            <td>${cveCount}</td>
        </tr>`
					})
					html += `</table>`
				}

				// 2. Tabel CVE
				if (result.cves && result.cves.length) {
					// Urutkan dari terbaru
					result.cves.sort((a, b) => {
						const da = new Date(a.published || a.lastModified || 0)
						const db = new Date(b.published || b.lastModified || 0)
						return db - da
					})
					const cveGroups = {}
					result.cves.forEach((cve) => {
						const sw = cve.software || "Lainnya"
						if (!cveGroups[sw]) cveGroups[sw] = []
						cveGroups[sw].push(cve)
					})
					html += `<h3 class="section-title">CVE</h3>
    <table>
        <tr class="medium-header">
            <th>Software</th>
            <th>ID</th>
            <th>Deskripsi</th>
            <th>Solusi</th>
            <th>CVSS Score</th>
            <th>Tanggal</th>
        </tr>`
					Object.keys(cveGroups).forEach((software) => {
						const cves = cveGroups[software]
						cves.forEach((cve, idx) => {
							// Penilaian status CVSS
							let cvss = cve.cvss_score
							let status = "-"
							let statusClass = ""
							if (typeof cvss === "number") {
								if (cvss >= 9) {
									status = "Critical"
									statusClass = "cvss-critical"
								} else if (cvss >= 7) {
									status = "Tinggi"
									statusClass = "cvss-tinggi"
								} else if (cvss >= 4) {
									status = "Menengah"
									statusClass = "cvss-menengah"
								} else {
									status = "Rendah"
									statusClass = "cvss-rendah"
								}
							}
							const tgl = cve.published
								? moment(cve.published).format("YYYY-MM-DD")
								: ""
							html += `<tr>`
							if (idx === 0) {
								html += `<td rowspan="${cves.length}" style="vertical-align: top; text-align: left;">${software}</td>`
							}
							html += `
                <td>${cve.cve_id || cve.id}</td>
                <td>${cve.description || cve.desc || cve.deskripsi || ""}</td>
                <td>${cve.solution || ""}</td>
                <td>${
									cvss !== undefined && cvss !== null
										? `${cvss} <span class="cvss-level ${statusClass}">${status}</span>`
										: "-"
								}</td>
                <td>${tgl}</td>
            </tr>`
						})
					})
					html += `</table>`
				}

				// 3. Jumlah alert ZAP per level
				const zapAlertLevels = { High: 0, Medium: 0, Low: 0, Informational: 0 }
				if (result.zap_alerts && result.zap_alerts.length) {
					const counted = {
						High: new Set(),
						Medium: new Set(),
						Low: new Set(),
						Informational: new Set(),
					}
					result.zap_alerts.forEach((a) => {
						const risk =
							(a.risk || "").charAt(0).toUpperCase() +
							(a.risk || "").slice(1).toLowerCase()
						const key = a.alert || a.name || ""
						if (counted[risk] && !counted[risk].has(key)) {
							zapAlertLevels[risk]++
							counted[risk].add(key)
						}
					})
					html += `<div style="margin-bottom:18px">
        <b>Jumlah Alert ZAP:</b>
        <span style="color:#b71c1c">Tinggi: ${zapAlertLevels.High}</span>,
        <span style="color:#ff9800">Medium: ${zapAlertLevels.Medium}</span>,
        <span style="color:#888">Rendah: ${zapAlertLevels.Low}</span>,
        <span style="color:#2196f3">Info: ${zapAlertLevels.Informational}</span>
    </div>`
				}

				// 4. ZAP Alerts dengan tombol vertikal per level
				if (result.zap_alerts && result.zap_alerts.length) {
					const grouped = { High: [], Medium: [], Low: [], Informational: [] }
					result.zap_alerts.forEach((a) => {
						const risk =
							(a.risk || "").charAt(0).toUpperCase() +
							(a.risk || "").slice(1).toLowerCase()
						if (grouped[risk]) grouped[risk].push(a)
					})
					const riskOrder = ["High", "Medium", "Low", "Informational"]
					const riskLabel = {
						High: "Tinggi",
						Medium: "Medium",
						Low: "Rendah",
						Informational: "Info",
					}
					html += `<h3 class="section-title">ZAP Result</h3>
    <div class="zap-level-btns">`
					riskOrder.forEach((risk) => {
						if (grouped[risk].length) {
							const listId = `zap-list-${risk}`
							html += `<button type="button" onclick="toggleZapList('${listId}')" style="background:${
								risk === "High"
									? "#dc3545"
									: risk === "Medium"
									? "#ffa500"
									: risk === "Low"
									? "#fff9c4"
									: "#90caf9"
							};color:${
								risk === "High" || risk === "Medium" ? "#fff" : "#222"
							};border:1px solid #ccc;">
                ${riskLabel[risk]} (${grouped[risk].length})
            </button>
            <div id="${listId}" style="display:none;margin-bottom:10px;margin-left:10px;">`
							grouped[risk].forEach((a, idx) => {
								html += `<table style="margin-bottom:10px">
                    <tr class="${risk.toLowerCase()}-header"><th colspan="2">[${
									riskLabel[risk]
								}] ${a.alert || a.name}</th></tr>
                    <tr><td>Deskripsi</td><td>${a.description || ""}</td></tr>
                    <tr><td>Solusi</td><td>${a.solution || ""}</td></tr>
                    <tr><td>URL Terdampak</td><td><ol>${(a.urls || [a.url])
											.map((u, i) => `<li>${u}</li>`)
											.join("")}</ol></td></tr>
                </table>`
							})
							html += `</div>`
						}
					})
					html += `</div>`
				}
				// 5a. Hasil XSS
				if (result.xss_results && result.xss_results.length) {
					html += `<h3 class="section-title">Hasil XSS</h3>
    <table>
        <tr class="medium-header"><th>Form/Endpoint</th><th>Payload</th><th>Hasil</th></tr>`
					result.xss_results.forEach((xss) => {
						html += `<tr>
            <td>${xss.endpoint || xss.form || "-"}</td>
            <td>${xss.payload || "-"}</td>
            <td>${xss.result || xss.status || "-"}</td>
        </tr>`
					})
					html += `</table>`
				}

				// 5b. Hasil SQLi
				if (result.sqli_results && result.sqli_results.length) {
					html += `<h3 class="section-title">Hasil SQL Injection</h3>
    <table>
        <tr class="medium-header"><th>Form/Endpoint</th><th>Payload</th><th>Hasil</th></tr>`
					result.sqli_results.forEach((sqli) => {
						html += `<tr>
            <td>${sqli.endpoint || sqli.form || "-"}</td>
            <td>${sqli.payload || "-"}</td>
            <td>${sqli.result || sqli.status || "-"}</td>
        </tr>`
					})
					html += `</table>`
				}
				// 6. DoS Test
				if (result.dos_summary) {
					html += `<h3 class="section-title">DoS Test</h3>
    <div class="dos-summary">${result.dos_summary}</div>`
				}

				

				// 7. Penilaian keamanan (opsional)
				if (result.security_score) {
					html += `<h3 class="section-title">Penilaian Keamanan</h3>
    <table>
        <tr><th>Aspek</th><th>Nilai</th></tr>
        <tr><td>CVSS (CVE)</td><td><b>${result.security_score.cve_score}</b></td></tr>
        <tr><td>ZAP Alert</td><td><b>${result.security_score.zap_score}</b></td></tr>
        <tr><td><b>Skor Akhir</b></td><td style="font-size:1.3em"><b>${result.security_score.final_score}</b></td></tr>
    </table>
    <div style="margin-bottom:18px;color:#555;">
        <b>Keterangan:</b> A = Sangat Aman, B = Aman, C = Cukup, D = Rentan, E = Sangat Rentan
    </div>`
				}

				// Setelah selesai:
				document.getElementById("scan-result").innerHTML = html
				clearInterval(interval)
				progressBar.style.width = "100%"
				progressBar.innerText = "Selesai"
				progressBar.classList.add("done")

				// 6. Grafik DoS - Perbaikan utama di sini
				if (result.dos_timeline && result.dos_timeline.length) {
					// Tunggu DOM update selesai
					setTimeout(() => {
						createDosChart(result.dos_timeline)
					}, 100)
				}

			} catch (err) {
				console.error("Error during scan:", err)
				document.getElementById("scan-result").innerHTML =
					"Gagal menjalankan scan."
				clearInterval(interval)
				progressBar.style.width = "100%"
				progressBar.innerText = "Error"
				progressBar.style.backgroundColor = "#dc3545"
			}
		})

	// Toggle ZAP list
	window.toggleZapList = function (id) {
		const el = document.getElementById(id)
		if (el) el.style.display = el.style.display === "none" ? "block" : "none"
	}
})