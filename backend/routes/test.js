const express = require("express")
const router = express.Router()
const { spawn } = require("child_process")
const path = require("path")

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
router.post("/scan-all", (req, res) => {
	const {
		url,
		dos_enabled,
		requests_num,
		duration,
		packet_size,
		connections_per_page,
		dos_method,
	} = req.body

	const scanPath = path.join(__dirname, "../utils/scan_all.py")
	const args = [scanPath, url]

	if (dos_enabled) {
		args.push("--dos_enabled")
		args.push(`--requests_num=${requests_num || 100}`)
		args.push(`--duration=${duration || 10}`)
		args.push(`--packet_size=${packet_size || 1024}`)
		args.push(`--connections_per_page=${connections_per_page || 100}`)
		args.push(`--dos_method=${dos_method || "slowloris"}`)
	}

	const process = spawn("python3", args)
	let stdout = ""
	let stderr = ""

	process.stdout.on("data", (data) => (stdout += data))
	process.stderr.on("data", (data) => (stderr += data))

	process.on("close", async (code) => {
		if (stderr) {
			console.error("Python stderr:", stderr)
		}

		try {
			const firstBrace = stdout.indexOf("{")
			const lastBrace = stdout.lastIndexOf("}")
			let jsonStr = ""
			if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
				jsonStr = stdout.slice(firstBrace, lastBrace + 1)
			}
			if (!jsonStr || jsonStr.trim() === "") {
				return res.status(500).json({
					error: "Scan berhasil tapi tidak dapat memparse hasil JSON",
					debug: {
						stdout_preview: stdout.substring(0, 500),
						stderr: stderr,
					},
				})
			}
			let parsed
			try {
				parsed = JSON.parse(jsonStr)
			} catch (parseError) {
				return res.status(500).json({
					error: "Format JSON hasil scan tidak valid",
					debug: {
						parse_error: parseError.message,
						json_preview: jsonStr.substring(0, 200),
					},
				})
			}
			res.json(parsed)
		} catch (e) {
			res.status(500).json({
				error: "Terjadi kesalahan dalam memproses hasil scan",
				debug: {
					error_message: e.message,
					stdout_preview: stdout.substring(0, 300),
				},
			})
		}
	})

	process.on("error", (err) => {
		console.error("Process error:", err)
		res.status(500).json({
			error: "Gagal menjalankan script Python",
			debug: { process_error: err.message },
		})
	})
})

router.get("/page-size", async (req, res) => {
	const url = req.query.url
	if (!url) return res.json({ size: null })
	try {
		const fetch = require("node-fetch")
		const response = await fetch(url, { method: "HEAD" })
		let size = response.headers.get("content-length")
		if (!size) {
			// fallback: GET and measure length
			const body = await (await fetch(url)).arrayBuffer()
			size = body.byteLength
		}
		res.json({ size: Number(size) })
	} catch (e) {
		res.json({ size: null })
	}
})

module.exports = router
