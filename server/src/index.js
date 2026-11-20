const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cfg = require("./config");
const { connectDB } = require("./db");

const app = express();
app.use(helmet());
app.use(cors({ origin: cfg.clientUrl }));
app.use(express.json());
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: "Too many attempts, try again later" } }));
app.use("/api/verify", rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: "Too many requests, slow down" } }));

app.get("/api/health", (_req, res) => res.json({ ok: true, contract: cfg.contractAddress || null, network: cfg.network }));
app.use("/api/config", require("./routes/config"));
app.use("/api/auth", require("./routes/auth"));
app.use("/api/docs", require("./routes/docs"));
app.use("/api/verify", require("./routes/verify"));
app.use("/api/p", rateLimit({ windowMs: 60 * 1000, max: 40, message: { error: "Too many requests, slow down" } }), require("./routes/public"));
app.use("/api/stego", rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: "Too many requests, slow down" } }), require("./routes/stego"));
app.use("/api/metadata", rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: "Too many requests, slow down" } }), require("./routes/metadata"));

app.use((err, _req, res, _next) => {
  console.error(err);
  const msg = err.code === "LIMIT_FILE_SIZE" ? "File too large (max 10 MB)" : err.message || "Server error";
  res.status(err.code === "LIMIT_FILE_SIZE" ? 413 : err.status || 500).json({ error: msg });
});

connectDB()
  .then(() => app.listen(cfg.port, () => console.log(`Vouch API on http://localhost:${cfg.port}`)))
  .catch((e) => { console.error("Failed to start:", e.message); process.exit(1); });
