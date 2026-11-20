const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { jwtSecret } = require("../config");
const { audit } = require("../services/audit");
const lockout = require("../services/lockout");

// Compared against when the email is unknown, so response time does not reveal which emails exist
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);

const sign = (user) => jwt.sign({ id: user._id.toString() }, jwtSecret, { expiresIn: "7d" });
const publicUser = (u) => ({ id: u._id, name: u.name, email: u.email });

router.post("/register", async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password are required" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: "Email already registered" });
    const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 10) });
    audit("register", user._id);
    res.status(201).json({ token: sign(user), user: publicUser(user) });
  } catch (e) { next(e); }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const user = email ? await User.findOne({ email: String(email).toLowerCase() }) : null;

    if (user && lockout.isLocked(user)) {
      audit("login_blocked", user._id);
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockout.minutesLeft(user)} minute(s).` });
    }
    const ok = await bcrypt.compare(password || "", user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) {
      if (user) {
        const upd = lockout.afterFailure(user);
        await User.updateOne({ _id: user._id }, { failedLogins: upd.failedLogins, lockedUntil: upd.lockedUntil });
        audit(upd.locked ? "lockout" : "login_failed", user._id);
      } else audit("login_failed", null, { reason: "unknown email" });
      return res.status(401).json({ error: "Invalid email or password" });
    }
    await User.updateOne({ _id: user._id }, lockout.afterSuccess());
    audit("login", user._id);
    res.json({ token: sign(user), user: publicUser(user) });
  } catch (e) { next(e); }
});

module.exports = router;
