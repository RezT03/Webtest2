const express = require("express")
const path = require("path")
const bodyParser = require("body-parser")
const session = require("express-session")
require("dotenv").config()

const authRoutes = require("./routes/auth")
const dashboardRoutes = require("./routes/dashboard")
const testRoutes = require("./routes/test")
const historyRoutes = require("./routes/history")

const app = express()

console.log('Starting server...');

app.use(express.static(path.join(__dirname, '../frontend/public')));
console.log('Static middleware set');

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, '../frontend/views'));
console.log('View engine configured');

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(
	session({
		secret: "websecsecret",
		resave: false,
		saveUninitialized: true,
	}),
)

//DEV.BYPASS.LOGIN
app.use((req, res, next) => {
  req.session.userId = 1; 
  next();
});
//DEL.ON.PROD

app.use("/", authRoutes)
app.use("/dashboard", dashboardRoutes)
app.use("/test", testRoutes)
app.use("/history", historyRoutes)
console.log('All routes configured');

app.listen(3001, () => {
    console.log("Server running on http://localhost:3001");
})

module.exports = app
