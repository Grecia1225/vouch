const router = require("express").Router();
const cfg = require("../config");

// Public settings the web app needs for independent verification and explorer links.
// Never put a private RPC key here: use PUBLIC_RPC_URL for a key-free endpoint.
router.get("/", (_req, res) =>
  res.json({ contract: cfg.contractAddress || null, network: cfg.network, rpcUrl: cfg.publicRpcUrl, explorerTxUrl: cfg.explorerTxUrl })
);

module.exports = router;
