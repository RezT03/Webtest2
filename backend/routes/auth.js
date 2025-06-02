const express = require('express');
const router = express.Router();
const db = require('../config/db');
const bcrypt = require('bcryptjs');

router.get('/', (req, res) => {
    console.log('Root path accessed');
    res.redirect('/');
});

router.get('/login', (req, res) => {
    console.log('Login path accessed');
    res.render('login');
});

router.post('/login', async (req, res) => {
    res.render('login');
  const { username, password } = req.body;
  const [user] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
  if (user.length > 0 && await bcrypt.compare(password, user[0].password_hash)) {
    req.session.userId = user[0].id;
    res.redirect('/dashboard')
  } else {
    res.send('Login gagal')
  }
});

router.get('/register', (req, res) => {
  res.render('register');
});

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await db.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
  res.redirect('/login');
});
module.exports = router