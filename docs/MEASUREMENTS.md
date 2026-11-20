# Measurements for your report

## 1. Hashing and tamper detection (no blockchain needed)
```
node server/scripts/measure-hash.js 2000
```
Writes `measurements/hash-results.md/json`: SHA-256 speed by file size, avalanche effect (about 128 of 256 bits flip when one bit changes), and tamper-detection rate for five kinds of modification. A reference run is already in `measurements/hash-results.md` (generated on a small cloud machine; quote your own numbers from your laptop).

## 2. On-chain cost and latency
```
cd contracts
npm run measure                 # in-process network: exact gas, timings not meaningful
npm run measure:amoy            # real network: confirmation time and gas price (costs a little test POL)
N=50 POL_PRICE_USD=0.20 npm run measure:amoy
```
Writes `measurements/chain-<network>.md/json`: gas for `notarize` and `notarizeVersion`, confirmation time (mean and p95), read latency for `verify`, and the cost in POL.

## 3. What to say about the results
- Cost per document is constant: only 32 bytes are stored, whatever the file size.
- Verification reads are free.
- Tamper detection is 100% in the test because SHA-256 changes completely on any modification; a collision is computationally infeasible. State that this is an empirical check, not a proof.
- Testnet gas is free. If you quote a dollar figure, label it a mainnet estimate and state the POL price you used.

## 4. Suggested table for the report
| Metric | Value | How measured |
|---|---|---|
| Hash time, 10 MB file | see hash-results.md | `measure-hash.js` |
| Bits changed per 1-bit edit | about 128 of 256 | `measure-hash.js` |
| Tamper detection | 100% of N modifications | `measure-hash.js` |
| Gas per notarize | fill from chain results | `measure-chain.js` |
| Confirmation time on Amoy | fill from chain results | `measure-chain.js --network amoy` |
| Verification cost | 0 (read call) | contract design |
