const crypto = require("crypto");
const sha256Hex = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");
const isSha256Hex = (s) => typeof s === "string" && /^[a-f0-9]{64}$/i.test(s);
module.exports = { sha256Hex, isSha256Hex };
