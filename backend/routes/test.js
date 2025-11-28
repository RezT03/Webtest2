const express = require("express");
const router = express.Router();
const { spawn } = require("child_process");
const path = require("path");

// POST /test/scan-all
router.post("/scan-all", (req, res) => {
    const {
        url,
        tests = [], // Array checkbox: ['tech', 'xss_sqli', 'zap', 'ssl', 'nmap', 'ratelimit']
        nmap_enabled,
        nmap_ports,
        nmap_specific_ports,
        nmap_show_os,
        nmap_show_service,
        ratelimit_level,
        cookie
    } = req.body || {};

    if (!url) return res.status(400).json({ error: "url is required" });

    const scanPath = path.join(__dirname, "../utils/scan_all.py");
    const args = [scanPath, url];

    // Mapping Frontend Checkboxes -> Python Arguments
    if (Array.isArray(tests)) {
        if (tests.includes("tech")) args.push("--tech_enabled");
        if (tests.includes("xss_sqli")) args.push("--xss_enabled");
        if (tests.includes("zap")) args.push("--zap_enabled");
        
        // FIX 1: Tambahkan SSL flag
        if (tests.includes("ssl")) args.push("--ssl_enabled");

        // Nmap
        if (tests.includes("nmap") || nmap_enabled) {
            args.push("--nmap_enabled");
            if (nmap_ports) args.push("--nmap_ports", String(nmap_ports));
            if (nmap_specific_ports) args.push("--nmap_specific_ports", String(nmap_specific_ports));
            if (nmap_show_os) args.push("--nmap_show_os");
            if (nmap_show_service) args.push("--nmap_show_service");
        }
        
        // FIX 2: Rate Limit hanya dikirim jika checkbox dicentang
        if (tests.includes("ratelimit")) {
            const lvl = ratelimit_level || "1";
            args.push("--ratelimit_level", String(lvl));
        }
    }

    if (cookie) args.push("--cookie", String(cookie));

    // Debug: Cek argumen di console server
    console.log("Executing Python:", args.join(" "));

    const pythonBin = process.platform === "win32" ? "python" : "python3";
    const py = spawn(pythonBin, args);

    let stdoutChunks = [];
    let stderrChunks = [];

    py.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    py.stderr.on("data", (chunk) => stderrChunks.push(chunk));

    py.on("close", (code) => {
        const stdout = Buffer.concat(stdoutChunks).toString('utf8');
        const stderr = Buffer.concat(stderrChunks).toString('utf8');

        if (stderr) console.error("Python stderr:", stderr);

        function extractJson(s) {
            if (!s) return null;
            s = s.trim();
            const firstIdx = s.indexOf('{');
            const lastIdx = s.lastIndexOf('}');
            if (firstIdx === -1 || lastIdx === -1 || lastIdx <= firstIdx) return null;
            try { return JSON.parse(s.substring(firstIdx, lastIdx + 1)); } 
            catch (e) { return null; }
        }

        const parsed = extractJson(stdout);

        if (!parsed) {
            console.error(`Scan failed parsing. Stdout length: ${stdout.length}`);
            if (!res.headersSent) {
                return res.status(500).json({
                    error: "Scan finished but JSON not found or invalid",
                    debug: { 
                        stdout_preview: stdout.slice(0, 1000) + "\n...[TRUNCATED]...\n" + stdout.slice(-1000), 
                        stderr_preview: stderr.slice(-2000) 
                    },
                });
            }
            return;
        }
        
        if (!res.headersSent) return res.json(parsed);
    });

    py.on("error", (err) => {
        if (!res.headersSent) res.status(500).json({ error: "Failed to start Python process" });
    });
});

module.exports = router;