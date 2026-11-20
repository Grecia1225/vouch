# Deploying the contract to Polygon Amoy (public testnet)

Why: records become visible to anyone on a public block explorer, which is much stronger evidence than a local chain.

Facts (checked October 2026; confirm in Polygon's docs if a step fails): Amoy chain ID **80002**, gas token **POL**, explorer https://amoy.polygonscan.com, faucet https://faucet.polygon.technology (others exist, e.g. Alchemy and Quicknode faucets with daily limits). Public RPCs include https://polygon-amoy.drpc.org (listed in Polygon's docs) and https://rpc-amoy.polygon.technology. Public RPCs are rate limited.

## 1. Create a wallet used only for testing
1. Install MetaMask. Create a **new** account that has never held real money.
2. Add the network: name Polygon Amoy, RPC URL as above, chain ID 80002, symbol POL, explorer https://amoy.polygonscan.com.
3. Export that account's private key (MetaMask: account details, show private key). Treat it as a secret. **Never use a wallet that holds real funds.**

## 2. Get test POL
Paste your address into the faucet and claim. It can take a minute.

## 3. Configure
In `contracts/.env`:
```
AMOY_RPC_URL=https://polygon-amoy.drpc.org
PRIVATE_KEY=0xYOUR_TEST_WALLET_KEY
```
Check the balance: `cd contracts && npm run balance`

## 4. Deploy
```
cd contracts
npx hardhat test
npx hardhat run scripts/deploy.js --network amoy
```
The script prints the contract address and explorer link, and writes `contracts/deployments/amoy.json` and `server/deployment.json`.

## 5. Point the server at Amoy
In `server/.env`:
```
RPC_URL=https://polygon-amoy.drpc.org
PRIVATE_KEY=0xYOUR_TEST_WALLET_KEY      # same wallet: it pays gas
CONTRACT_ADDRESS=0x...                  # from the deploy output
PUBLIC_RPC_URL=https://polygon-amoy.drpc.org   # key-free URL shown to browsers
EXPLORER_TX_URL=https://amoy.polygonscan.com/tx/
```
Restart the server. Dashboard transaction hashes now link to the explorer, and the *Independent check* page is prefilled.

## 6. Publish the source on the explorer (optional, impressive)
Run `npm run flatten` in `contracts/` to produce `Vouch.flat.sol`. On the contract's page on amoy.polygonscan.com use **Verify and Publish**, choose single file, and paste it. Use the compiler version and settings from `contracts/artifacts/build-info/*.json` (solcVersion and `input.settings`). The explorer's form changes over time, so follow its current instructions.

## 7. Show it works
1. Notarize a file in the app and click the transaction hash.
2. Run `node verifier/verify.mjs yourfile.pdf --rpc https://polygon-amoy.drpc.org --contract 0x...` from any machine.
3. Run `npm run measure:amoy` in `contracts/` to collect gas and confirmation times for your report.

## Troubleshooting
| Symptom | Fix |
|---|---|
| `Deployer wallet has no funds` | Claim from the faucet, wait, run `npm run balance` |
| `could not detect network` or timeouts | Try another public RPC; they rate-limit |
| `chain id mismatch` | Make sure the RPC is Amoy (80002) |
| `nonce too low` / `replacement underpriced` | Wait a minute and retry; do not run two deploys at once |
| Server says `Contract not deployed` | Set `CONTRACT_ADDRESS` or run the deploy script, then restart |
| Testnet suddenly empty | Testnets can be reset or retired. Redeploy, or move to a production network |
