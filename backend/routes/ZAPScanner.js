const express = require('express')
const router = express.Router()
const { execPython } = require('../utils/execPython')
let scanProgress = 0 

router.post('/scan-all', async (req, res) => {
  const { url, requests_num, duration, packet_size, cookie_header, dos_enabled } = req.body
  scanProgress = 0
  try {
    scanProgress = 10
    const result = await execPython('scan_all.py', [
      url,
      requests_num || '0',
      duration || '0',
      packet_size || '0',
      cookie_header || '',
      dos_enabled === 'on' ? '1' : '0'
    ])

    scanProgress = 100
    res.redirect('/dashboard')
  } catch (err) {
    console.error('❌ Error menjalankan pengujian:', err)
    res.status(500).send('Gagal menjalankan pengujian')
  }
})

// Endpoint status progress
router.get('/progress', (req, res) => {
  res.json({ progress: scanProgress })
})

module.exports = router