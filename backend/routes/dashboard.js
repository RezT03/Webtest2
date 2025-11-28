const express = require("express")
const router = express.Router()

router.get("/dashboard", (req, res) => {
	res.render("dashboard") // atau kirim data awal kosong: res.render('dashboard', {})
})

module.exports = router
