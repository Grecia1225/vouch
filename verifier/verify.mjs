#!/usr/bin/env node
/**
 * Vouch independent verifier (command line, zero dependencies, Node 18+).
 * Hashes a file locally and reads the blockchain directly. The Vouch server is never contacted.
 *
 *   node verify.mjs <file> --rpc <url> --contract <0x...>
 *   node verify.mjs --hash <sha256hex> --rpc <url> --contract <0x...>
 *
 * RPC_URL and CONTRACT_ADDRESS environment variables work as defaults.
 * Exit codes: 0 registered, 1 not registered, 2 error.
 */
import { readFile } from "node:fs/promises";
import { getChainId, isAddress, isHash, readHistory, readOwner, sha256Hex } from "./vouchChain.mjs";

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const rpcUrl = opt("--rpc") || process.env.RPC_URL;
const contract = opt("--contract") || process.env.CONTRACT_ADDRESS;
const hashArg = opt("--hash");
const file = args.find((a, i) => !a.startsWith("--") && !(args[i - 1] || "").startsWith("--"));

function fail(msg) { console.error("Error: " + msg); process.exit(2); }
if (!rpcUrl || !isAddress(contract) || (!file && !hashArg)) {
  console.error("Usage: node verify.mjs <file> | --hash <sha256> --rpc <url> --contract <0x...>");
  process.exit(2);
}

try {
  const hash = hashArg ? hashArg.toLowerCase() : await sha256Hex(new Uint8Array(await readFile(file)));
  if (!isHash(hash)) fail("that is not a valid SHA-256 hash");
  const chainId = await getChainId(rpcUrl);
  const owner = await readOwner(rpcUrl, contract);
  const history = await readHistory(rpcUrl, contract, hash);

  console.log(`SHA-256     ${hash}${file ? "  (computed locally from " + file + ")" : ""}`);
  console.log(`Network     chain id ${chainId}`);
  console.log(`Contract    ${contract}  (writer: ${owner})`);
  if (!history.length) {
    console.log("\nRESULT: NO RECORD. This exact file was never registered, or it has been changed since.");
    process.exit(1);
  }
  const r = history[0];
  console.log(`\nRESULT: REGISTERED`);
  console.log(`Registered  ${new Date(r.timestamp * 1000).toUTCString()}`);
  console.log(`Uploader    ${r.uploaderRef} (opaque reference)`);
  console.log(`Written by  ${r.notarizedBy}${r.notarizedBy.toLowerCase() === owner.toLowerCase() ? "" : "  (not the contract owner!)"}`);
  if (history.length > 1) {
    console.log(`\nVersion history (newest first):`);
    history.forEach((h, i) => console.log(`  ${i === 0 ? "-> " : "   "}${h.hash}  ${new Date(h.timestamp * 1000).toISOString()}`));
  }
  process.exit(0);
} catch (e) {
  fail(e.message);
}
