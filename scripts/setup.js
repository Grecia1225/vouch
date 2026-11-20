// Creates server/.env from the example if it does not exist yet
const fs = require("fs");
const path = require("path");
const dest = path.join(__dirname, "../server/.env");
const src = path.join(__dirname, "../server/.env.example");
if (!fs.existsSync(dest)) {
  fs.copyFileSync(src, dest);
  console.log("Created server/.env (edit MONGO_URI / JWT_SECRET if needed)");
} else {
  console.log("server/.env already exists, leaving it unchanged");
}
