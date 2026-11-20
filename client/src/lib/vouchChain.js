/**
 * Vouch independent verifier library. ZERO dependencies.
 * Reads the Vouch contract directly over JSON-RPC, so a result never depends on the Vouch server.
 * Includes its own Keccak-256 (needed to compute function selectors) so it can be audited in one file.
 */

// ---------------------------------------------------------------- Keccak-256 (not NIST SHA-3: padding byte is 0x01)
const M = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn,
  0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an, 0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const rotl = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M);

function keccakF(A) {
  for (let round = 0; round < 24; round++) {
    const C = [0, 1, 2, 3, 4].map((x) => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]);
    const D = [0, 1, 2, 3, 4].map((x) => C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1));
    for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROT[x][y]);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & M) & B[((x + 2) % 5) + 5 * y]);
    A[0] ^= RC[round];
  }
}

export function keccak256(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const rate = 136;
  const padded = new Uint8Array(data.length + (rate - (data.length % rate)));
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
      A[i] ^= lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = A[i];
    for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

// ---------------------------------------------------------------- helpers
export const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const hexToBytes = (h) => {
  const s = h.replace(/^0x/, "");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};
export const isHash = (s) => typeof s === "string" && /^[a-f0-9]{64}$/i.test(s);
export const isAddress = (s) => typeof s === "string" && /^0x[a-fA-F0-9]{40}$/.test(s);
export const selector = (sig) => bytesToHex(keccak256(sig).slice(0, 4));

/** SHA-256 of the exact bytes (uses the platform's WebCrypto: browsers and Node 18+). */
export async function sha256Hex(bytes) {
  return bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes)));
}

// ---------------------------------------------------------------- JSON-RPC
export async function rpc(url, method, params, fetchFn = globalThis.fetch) {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC endpoint answered HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || "RPC error");
  return body.result;
}

async function call(rpcUrl, contract, data, fetchFn) {
  const result = await rpc(rpcUrl, "eth_call", [{ to: contract, data }, "latest"], fetchFn);
  if (!result || result === "0x") throw new Error("No contract answered at that address. Check the contract address and network.");
  return result.replace(/^0x/, "");
}
const word = (hex, i) => hex.slice(i * 64, i * 64 + 64);

export async function getChainId(rpcUrl, fetchFn) {
  return parseInt(await rpc(rpcUrl, "eth_chainId", [], fetchFn), 16);
}

/** verify(bytes32) -> {exists, uploaderRef, timestamp, notarizedBy} */
export async function readRecord(rpcUrl, contract, hashHex, fetchFn) {
  if (!isHash(hashHex)) throw new Error("Not a valid SHA-256 hash");
  const out = await call(rpcUrl, contract, "0x" + selector("verify(bytes32)") + hashHex.toLowerCase(), fetchFn);
  const exists = BigInt("0x" + word(out, 0)) === 1n;
  const strPos = Number(BigInt("0x" + word(out, 1))) * 2;
  const timestamp = Number(BigInt("0x" + word(out, 2)));
  const notarizedBy = "0x" + word(out, 3).slice(24);
  const len = Number(BigInt("0x" + out.slice(strPos, strPos + 64)));
  const uploaderRef = new TextDecoder().decode(hexToBytes(out.slice(strPos + 64, strPos + 64 + len * 2)));
  return exists ? { exists, uploaderRef, timestamp, notarizedBy } : { exists: false };
}

/** previousOf(bytes32) -> previous version hash or null */
export async function readPrevious(rpcUrl, contract, hashHex, fetchFn) {
  const out = await call(rpcUrl, contract, "0x" + selector("previousOf(bytes32)") + hashHex.toLowerCase(), fetchFn);
  const w = word(out, 0);
  return /^0+$/.test(w) ? null : w;
}

/** owner() -> the address allowed to write records */
export async function readOwner(rpcUrl, contract, fetchFn) {
  return "0x" + word(await call(rpcUrl, contract, "0x" + selector("owner()"), fetchFn), 0).slice(24);
}

/** Walks the version chain newest -> oldest. */
export async function readHistory(rpcUrl, contract, hashHex, fetchFn, max = 25) {
  const chain = [];
  let cur = hashHex.toLowerCase();
  for (let i = 0; i < max && cur; i++) {
    const rec = await readRecord(rpcUrl, contract, cur, fetchFn);
    if (!rec.exists) break;
    chain.push({ hash: cur, ...rec });
    cur = await readPrevious(rpcUrl, contract, cur, fetchFn);
  }
  return chain;
}
