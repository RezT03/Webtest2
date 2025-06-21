const express = require("express")
const router = express.Router()
const path = require("path")
const { spawn } = require("child_process")

router.get('/dashboard', (req, res) => {
  res.render('dashboard', {
    xss_results: [],
    sqli_results: [],
    tech: [],
    cves: [],
    zap_alerts: [],
    dos_summary: ''
  });
});



module.exports = router
