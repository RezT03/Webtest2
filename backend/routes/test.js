const express = require("express")
const router = express.Router()
const { spawn } = require("child_process")
const path = require("path")
const fs = require("fs")
const os = require("os")

// --- KONFIGURASI LIMIT ---
// Tingkatkan limit body parser untuk menerima JSON hasil scan yang besar
router.use(express.json({ limit: '50mb' }));
router.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- HELPER: Deteksi Command Python ---
const getPythonCommand = () => {
    return process.platform === "win32" ? "python" : "python3"
}

// --- POST /test/scan-all ---
router.post("/scan-all", (req, res) => {
	const {
		url,
		tests = [], 
		nmap_enabled,
		nmap_ports,
		nmap_specific_ports,
		nmap_show_os,
		nmap_show_service,
		ratelimit_level,
		cookie,
	} = req.body || {}

	if (!url) return res.status(400).json({ error: "url is required" })

	const scanPath = path.join(__dirname, "../utils/scan_all.py")
    
    // Cek apakah file script ada
    if (!fs.existsSync(scanPath)) {
        return res.status(500).json({ error: `Script not found at ${scanPath}` });
    }

	const args = [scanPath, url]

	// Mapping Frontend Checkboxes -> Python Arguments
	if (Array.isArray(tests)) {
		if (tests.includes("tech")) args.push("--tech_enabled")
		if (tests.includes("xss_sqli")) args.push("--xss_enabled")
		if (tests.includes("zap")) args.push("--zap_enabled")
		if (tests.includes("ssl")) args.push("--ssl_enabled")
		if (tests.includes("nmap") || nmap_enabled) args.push("--nmap_enabled")
	}

    // Args lain
	if (nmap_ports) args.push("--nmap_ports", nmap_ports)
	if (nmap_specific_ports) args.push("--nmap_specific_ports", nmap_specific_ports)
	if (nmap_show_os) args.push("--nmap_show_os")
	if (nmap_show_service) args.push("--nmap_show_service")
	
    // Pastikan ratelimit_level dikirim sebagai string angka
    if (ratelimit_level && parseInt(ratelimit_level) > 0) {
        args.push("--ratelimit_level", String(ratelimit_level))
    }

	if (cookie) args.push("--cookie", cookie)

    // Spawn Process
    const pythonCmd = getPythonCommand();
	const py = spawn(pythonCmd, args)

	let outputData = ""
	let errorData = ""

	py.stdout.on("data", (chunk) => { outputData += chunk.toString() })
	py.stderr.on("data", (chunk) => { 
        // Log stderr tapi jangan panik dulu, karena logging python kita arahkan ke sini
        errorData += chunk.toString()
        console.error("[Scan Log]:", chunk.toString()) 
    })

    py.on("error", (err) => {
        console.error("Failed to spawn python:", err);
        if (!res.headersSent) {
            res.status(500).json({ error: "Gagal menjalankan Python. Pastikan Python terinstall.", details: err.message });
        }
    });

	py.on("close", (code) => {
        if (res.headersSent) return;

		if (code !== 0) {
			console.error(`Scan process exited with code ${code}`)
		}
        
		try {
            // Cari JSON valid terakhir (untuk menghindari log kotor di stdout jika ada)
            const jsonStart = outputData.indexOf('{');
            const jsonEnd = outputData.lastIndexOf('}');
            
            if (jsonStart !== -1 && jsonEnd !== -1) {
                const jsonString = outputData.substring(jsonStart, jsonEnd + 1);
                const result = JSON.parse(jsonString);
                res.json(result);
            } else {
                throw new Error("No valid JSON found in output");
            }
		} catch (e) {
			res.status(500).json({ 
                error: "Gagal memproses hasil scan", 
                details: e.message,
                raw_output_preview: outputData.substring(0, 200) + "...",
                stderr_log: errorData 
            })
		}
	})
})

// --- POST /test/generate-report ---
router.post("/generate-report", (req, res) => {
    const scanResult = req.body; 

    if (!scanResult) {
        return res.status(400).json({ error: "No scan data provided" });
    }

    const scriptPath = path.join(__dirname, "../utils/pdfExport.py");
    if (!fs.existsSync(scriptPath)) {
        return res.status(500).json({ error: `PDF Script not found at ${scriptPath}` });
    }
    
    // Gunakan spawn dan pipe data via STDIN untuk data besar
    const pythonCmd = getPythonCommand();
    const py = spawn(pythonCmd, [scriptPath]);

    let outputData = "";
    let errorData = "";

    // Kirim data JSON ke Python via Stdin
    try {
        py.stdin.write(JSON.stringify(scanResult));
        py.stdin.end();
    } catch (writeErr) {
        console.error("Failed to write to python stdin:", writeErr);
        if (!res.headersSent) res.status(500).json({ error: "Failed to send data to PDF generator" });
        return;
    }

    py.stdout.on("data", (chunk) => { outputData += chunk.toString() });
    py.stderr.on("data", (chunk) => { 
        errorData += chunk.toString();
        // Jangan log semua ke console server jika terlalu bising, cukup saat error
    });

    py.on("error", (err) => {
        console.error("Failed to spawn PDF generator:", err);
        if (!res.headersSent) res.status(500).json({ error: "Gagal menjalankan PDF Generator", details: err.message });
    });

    py.on("close", (code) => {
        if (res.headersSent) return;

        if (code !== 0) {
            console.error(`PDF Generation exited with code ${code}`);
            console.error("PDF Stderr:", errorData);
             return res.status(500).json({ 
                error: "PDF Generation Failed", 
                stderr: errorData 
            });
        }

        try {
            // Parse output JSON dari Python ({ status: 'success', download_url: ... })
            // Cari JSON valid pertama/terakhir
            const jsonStart = outputData.indexOf('{');
            const jsonEnd = outputData.lastIndexOf('}');
            
            if (jsonStart !== -1 && jsonEnd !== -1) {
                const jsonString = outputData.substring(jsonStart, jsonEnd + 1);
                const response = JSON.parse(jsonString);
                res.json(response);
            } else {
                throw new Error("No JSON response from script");
            }
        } catch (e) {
            console.error("JSON Parse Error (PDF):", e);
            res.status(500).json({ 
                error: "Invalid response from PDF generator", 
                raw_output: outputData,
                stderr: errorData
            });
        }
    });
});

module.exports = router