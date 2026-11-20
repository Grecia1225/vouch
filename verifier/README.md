# Vouch independent verifier

Checks a file against the blockchain **without trusting the Vouch server**.

```
node verify.mjs contract.pdf --rpc https://rpc-amoy.polygon.technology --contract 0xYourContract
node verify.mjs --hash <sha256> --rpc <url> --contract 0x...
```

- Needs only Node 18+ (no `npm install`). One small library file, `vouchChain.mjs`, which you can read and audit.
- It hashes the file itself (SHA-256) and calls the contract's public `verify`, `previousOf` and `owner` functions over JSON-RPC.
- `client/src/lib/vouchChain.js` is an identical copy used by the web page "Verify independently". A test keeps them in sync.
- Registered means the exact bytes existed at the recorded time. It does not prove who wrote the file or that its content is true.
