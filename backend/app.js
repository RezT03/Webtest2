const express = require("express")
const path = require("path")
const bodyParser = require("body-parser")
const session = require("express-session")
require("dotenv").config()
const cors = require("cors")

const authRoutes = require("./routes/auth")
const dashboardRoutes = require("./routes/dashboard")
const testRoutes = require("./routes/test")
const historyRoutes = require("./routes/history")

const app = express()
app.use(cors())

console.log("Starting server...")

app.use(express.static(path.join(__dirname, "../frontend/public")))
console.log("Static middleware set")

app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "../frontend/views"))
console.log("View engine configured")

// Middleware
app.use(express.json({ limit: "50mb" }))
app.use(express.urlencoded({ limit: "50mb", extended: true }))

// Serve static files
app.use(express.static(path.join(__dirname, "public")))

// Optional: Explicit route untuk downloads
app.use(
	"/static/downloads",
	express.static(path.join(__dirname, "public/static/downloads")),
)

// Routes
app.use("/test", require("./routes/test"))
app.use("/", dashboardRoutes)
app.get("/", (req, res) => {
	res.redirect("/dashboard")
})
app.use("/dashboard", dashboardRoutes)
app.use("/test", testRoutes)
app.use("/history", historyRoutes)
console.log("All routes configured")

// Error handler
app.use((err, req, res, next) => {
	console.error("Express error:", err)
	res.status(500).json({ error: err.message })
})

const PORT = process.env.PORT || 3001
app
	.listen(PORT, () => {
		console.log(`Server running on port ${PORT}`)
	})
	.setTimeout(600000)

module.exports = app
