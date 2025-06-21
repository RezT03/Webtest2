const express = require('express')
const router = express.Router()
const db = require('../config/db')

router.get('/', async (req, res) => {
  const userId = req.session.userId
  if (!userId) return res.redirect('/login')

  const [tests] = await db.query('SELECT * FROM test_results WHERE user_id = ?', [userId])
  const [cves] = await db.query('SELECT * FROM tech_cve_results WHERE user_id = ?', [userId])

  res.render('history', { tests, cves })
})

module.exports = router