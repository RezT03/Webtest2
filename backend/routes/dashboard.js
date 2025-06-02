const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('dashboard');
});

module.exports = router