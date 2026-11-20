const jwt = require("jsonwebtoken");
const { jwtSecret } = require("../config");

module.exports = function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Login required" });
  try {
    req.user = { id: jwt.verify(token, jwtSecret).id };
    next();
  } catch {
    res.status(401).json({ error: "Session expired, please log in again" });
  }
};
