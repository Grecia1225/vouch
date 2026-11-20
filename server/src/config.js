try { require("dotenv").config(); } catch (_) { /* dotenv optional: env vars can come from the shell */ }
const fs = require("fs");
const path = require("path");

let deployed = {};
try {
  deployed = JSON.parse(fs.readFileSync(path.join(__dirname, "../deployment.json"), "utf8"));
} catch (_) { /* not deployed yet */ }

module.exports = {
  port: process.env.PORT || 5000,
  mongoUri: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/vouch",
  jwtSecret: process.env.JWT_SECRET || "dev_secret_change_me",
  clientUrl: process.env.CLIENT_URL || "http://localhost:5173",
  rpcUrl: process.env.RPC_URL || "http://127.0.0.1:8545",
  privateKey: process.env.PRIVATE_KEY,
  contractAddress: process.env.CONTRACT_ADDRESS || deployed.address,
  network: deployed.network || "unknown",
  maxFileBytes: 10 * 1024 * 1024,
  publicRpcUrl: process.env.PUBLIC_RPC_URL || (/127\.0\.0\.1|localhost/.test(process.env.RPC_URL || "http://127.0.0.1:8545") ? process.env.RPC_URL || "http://127.0.0.1:8545" : ""),
  explorerTxUrl: process.env.EXPLORER_TX_URL || "",
  refSecret: process.env.REF_SECRET || process.env.JWT_SECRET || "dev_secret_change_me", // keys the per-document on-chain references
  allowPrivateUrls: process.env.ALLOW_PRIVATE_URLS === "true", // dev only: lets links point at localhost
};
