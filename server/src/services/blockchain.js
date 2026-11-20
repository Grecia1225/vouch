const { ethers } = require("ethers");
const cfg = require("../config");

const ABI = [
  "function notarize(bytes32 docHash, string uploaderRef)",
  "function notarizeVersion(bytes32 docHash, bytes32 previousHash, string uploaderRef)",
  "function previousOf(bytes32 docHash) view returns (bytes32)",
  "function verify(bytes32 docHash) view returns (bool exists, string uploaderRef, uint64 timestamp, address notarizedBy)",
  "function totalNotarized() view returns (uint256)",
];

let contract;
function getContract() {
  if (contract) return contract;
  if (!cfg.contractAddress) throw new Error("Contract not deployed. Run the deploy script first.");
  if (!cfg.privateKey) throw new Error("PRIVATE_KEY missing in server/.env");
  const provider = new ethers.JsonRpcProvider(cfg.rpcUrl);
  const wallet = new ethers.Wallet(cfg.privateKey, provider);
  contract = new ethers.Contract(cfg.contractAddress, ABI, wallet);
  return contract;
}

/** Write a SHA-256 hex digest to the chain. Returns tx details + on-chain timestamp. */
async function notarize(hashHex, uploaderRef, previousHex) {
  const c = getContract();
  const tx = previousHex
    ? await c.notarizeVersion("0x" + hashHex, "0x" + previousHex, uploaderRef)
    : await c.notarize("0x" + hashHex, uploaderRef);
  const receipt = await tx.wait();
  const rec = await lookup(hashHex);
  return { txHash: receipt.hash, blockNumber: receipt.blockNumber, timestamp: rec.timestamp };
}

/** Read-only lookup; free and trustless. */
async function lookup(hashHex) {
  const r = await getContract().verify("0x" + hashHex);
  if (!r.exists) return { exists: false };
  return { exists: true, uploaderRef: r.uploaderRef, timestamp: Number(r.timestamp), notarizedBy: r.notarizedBy };
}

/** Version chain, newest first. Read straight from the contract. */
async function history(hashHex, max = 25) {
  const c = getContract();
  const out = [];
  let cur = hashHex.toLowerCase();
  for (let i = 0; i < max && cur; i++) {
    const r = await c.verify("0x" + cur);
    if (!r.exists) break;
    out.push({ hash: cur, timestamp: Number(r.timestamp) });
    const prev = await c.previousOf("0x" + cur);
    cur = /^0x0+$/.test(prev) ? null : prev.slice(2).toLowerCase();
  }
  return out;
}

module.exports = { notarize, lookup, history };
