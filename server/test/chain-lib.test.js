const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs");
const path = require("path");

const libPromise = import("../../verifier/vouchChain.mjs");
const hex = (n, w = 64) => n.toString(16).padStart(w, "0");
const strWord = (s) => { const b = Buffer.from(s); return hex(b.length) + b.toString("hex").padEnd(Math.ceil(b.length / 32) * 64, "0"); };

test("keccak256 matches published test vectors", async () => {
  const { keccak256, bytesToHex, selector } = await libPromise;
  assert.strictEqual(bytesToHex(keccak256("")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.strictEqual(bytesToHex(keccak256("abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  assert.strictEqual(selector("transfer(address,uint256)"), "a9059cbb"); // the famous ERC-20 selector
  assert.strictEqual(bytesToHex(keccak256("a".repeat(136))).length, 64); // exactly one block of input
  assert.strictEqual(bytesToHex(keccak256("a".repeat(135))).length, 64); // padding edge case
});

test("sha256Hex agrees with node's crypto", async () => {
  const { sha256Hex } = await libPromise;
  assert.strictEqual(await sha256Hex(new TextEncoder().encode("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("client copy of the verifier library is identical to the canonical one", () => {
  const a = fs.readFileSync(path.join(__dirname, "../../verifier/vouchChain.mjs"), "utf8");
  const b = fs.readFileSync(path.join(__dirname, "../../client/src/lib/vouchChain.js"), "utf8");
  assert.strictEqual(a, b, "run: cp verifier/vouchChain.mjs client/src/lib/vouchChain.js");
});

test("reads records, version history and owner through a mock JSON-RPC node", async () => {
  const lib = await libPromise;
  const V1 = "11".repeat(32), V2 = "22".repeat(32), UNKNOWN = "33".repeat(32);
  const OWNER = "ab".repeat(20), WRITER = OWNER;
  const sel = { verify: lib.selector("verify(bytes32)"), previous: lib.selector("previousOf(bytes32)"), owner: lib.selector("owner()") };
  const db = {
    [V1]: { ts: 1700000000, ref: "user-1", prev: "0".repeat(64) },
    [V2]: { ts: 1700000500, ref: "user-1", prev: V1 },
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      let result;
      if (method === "eth_chainId") result = "0x13882";
      else if (method === "eth_call") {
        const data = params[0].data.slice(2);
        const s = data.slice(0, 8), arg = data.slice(8);
        if (s === sel.owner) result = "0x" + "0".repeat(24) + OWNER;
        else if (s === sel.previous) result = "0x" + (db[arg] ? db[arg].prev : "0".repeat(64));
        else if (s === sel.verify) {
          const r = db[arg];
          // ABI: bool, offset(0x80), uint64, address, then the string
          result = "0x" + hex(r ? 1 : 0) + hex(128) + hex(r ? r.ts : 0) + "0".repeat(24) + WRITER + strWord(r ? r.ref : "");
        }
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const contract = "0x" + "cd".repeat(20);
  try {
    assert.strictEqual(await lib.getChainId(url), 80002);
    assert.strictEqual(await lib.readOwner(url, contract), "0x" + OWNER);
    const rec = await lib.readRecord(url, contract, V2);
    assert.deepStrictEqual(rec, { exists: true, uploaderRef: "user-1", timestamp: 1700000500, notarizedBy: "0x" + WRITER });
    assert.deepStrictEqual(await lib.readRecord(url, contract, UNKNOWN), { exists: false });
    assert.strictEqual(await lib.readPrevious(url, contract, V2), V1);
    assert.strictEqual(await lib.readPrevious(url, contract, V1), null);
    const hist = await lib.readHistory(url, contract, V2);
    assert.deepStrictEqual(hist.map((h) => h.hash), [V2, V1]);
    await assert.rejects(() => lib.readRecord(url, contract, "nothex"), /valid SHA-256/);
  } finally {
    server.close();
  }
});
