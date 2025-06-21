const express = require("express")
const router = express.Router()
const { spawn } = require("child_process")
const path = require("path")
const db = require("../config/db")

// GET dashboard tanpa hasil uji (kosong sampai user submit)
router.get("/dashboard", (req, res) => {
	res.render("dashboard", {
		xss_results: [],
		sqli_results: [],
		tech: [],
		cves: [],
		zap_alerts: [],
		dos_summary: "",
	})
})

// POST /test/scan-all: Jalankan pengujian dan kirim JSON ke frontend
router.post("/scan-all", async (req, res) => {
	const {
		url,
		dos_enabled,
		requests_num,
		duration,
		packet_size,
		cookie_header,
	} = req.body
	const userId = req.session?.userId || 1
	const resultLogs = []

	try {
		const scanPath = path.join(__dirname, "../utils/scan_all.py")
		const args = [scanPath, url]

		if (dos_enabled === "true" || dos_enabled === true) {
			args.push("--dos_enabled")
			args.push(`--requests_num=${requests_num || 100}`)
			args.push(`--duration=${duration || 10}`)
			args.push(`--packet_size=${packet_size || 1024}`)
		}

		const process = spawn("python3", args)
		let stdout = ""
		let stderr = ""

		process.stdout.on("data", (data) => (stdout += data))
		process.stderr.on("data", (data) => (stderr += data))

		process.on("close", async () => {
			if (stderr) {
				console.error(stderr)
			}
			if (!stdout || !stdout.trim().startsWith("{")) {
				console.error("Output Python tidak valid:", stdout)
				return res
					.status(500)
					.json({ error: "Scan gagal atau output tidak valid." })
			}
			try {
				const parsed = JSON.parse(stdout)

				// filter & urutkan hasil ZAP
				const riskLevel = { Low: 1, Medium: 2, High: 3 }
				if (Array.isArray(parsed.zap_alerts)) {
					parsed.zap_alerts = parsed.zap_alerts
						.filter((a) => ["Low", "Medium", "High"].includes(a.risk))
						.sort((a, b) => riskLevel[b.risk] - riskLevel[a.risk])
				}

				await db.query(
					"INSERT INTO test_results (user_id, test_type, target_url, request_payload, result, summary) VALUES (?, ?, ?, ?, ?, ?)",
					[
						userId,
						"scan-all",
						url,
						JSON.stringify(req.body),
						JSON.stringify(parsed),
						"Hasil pengujian keamanan",
					],
				)

				res.json({
					xss_results: parsed.xss_results,
					sqli_results: parsed.sqli_results,
					tech: parsed.tech,
					cves: parsed.cves,
					zap_alerts: parsed.zap_alerts,
					dos_summary: parsed.dos_summary,
				})
			} catch (e) {
				console.error("Gagal parsing hasil JSON:", e.message)
				res.status(500).json({ error: "Gagal parsing hasil JSON." })
			}
		})
	} catch (err) {
		console.error(err)
		res.status(500).send("Terjadi kesalahan saat menjalankan pengujian.")
	}
})

module.exports = router
