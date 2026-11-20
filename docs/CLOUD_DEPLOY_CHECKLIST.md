# Cloud deployment checklist (Render API + Vercel/Netlify frontend)

Prepared on this machine. The Git repo is initialised at `vouch-app/` with a clean
commit of the source; secrets and generated files are ignored by `.gitignore`.

## Already verified locally

- `npm install` and `npm run setup` complete.
- `npm test`: 9 contract tests pass; 62 server tests pass (60 pass, 2 platform skips).
- `npm run build --prefix client` produces `client/dist`.
- `render.yaml`, `client/vercel.json`, `netlify.toml`, `server/Dockerfile` and
  `docs/DEPLOYMENT.md` are present and consistent with the deployment options below.

## Steps you still need to do

1. **Create a remote.** On GitHub/GitLab, create an empty repository, then from
   `vouch-app/` run:
   ```
   git remote add origin <your-repo-url>
   git push -u origin HEAD
   ```
   Check `git status` first: no `.env`, `deployment.json`, `contracts/deployments/`,
   `node_modules`, `dist`, `artifacts` or `cache` should be tracked.

2. **Blockchain.** A cloud API cannot reach a Hardhat node on your laptop.
   Deploy the contract to Polygon Amoy first (see `AMOY_GUIDE.md`) using a
   dedicated test wallet with free test POL. Save the contract address.

3. **Database.** Create a MongoDB Atlas free cluster, add a database user,
   allow the deploy host's IPs (or `0.0.0.0/0` for a short demo), and copy the
   connection string.

4. **Render API.** Create a Blueprint from `render.yaml` (or a Docker web
   service with root `server/` and Dockerfile `server/Dockerfile`). Set:
   - `MONGO_URI` = Atlas connection string
   - `JWT_SECRET` = long random string (Render can generate it)
   - `CLIENT_URL` = the exact frontend HTTPS origin, once known
   - `RPC_URL` = Amoy RPC (e.g. `https://polygon-amoy.drpc.org`)
   - `PUBLIC_RPC_URL` = key-free Amoy RPC for browser-side independent checks
   - `PRIVATE_KEY` = the **test-only** relayer wallet key
   - `CONTRACT_ADDRESS` = address from step 2
   - `EXPLORER_TX_URL` = `https://amoy.polygonscan.com/tx/`
   Confirm `GET https://<your-api>/api/health` returns the contract address.

5. **Frontend (Vercel or Netlify).** Import the repo with root directory `client/`,
   build command `npm run build`, output directory `dist`. Set the **build-time**
   variable:
   ```
   VITE_API_BASE=https://<your-api>/api
   ```
   `client/vercel.json` (Vercel) and `netlify.toml` (Netlify) already handle SPA
   route refreshes.

6. **Connect them.** Set the API's `CLIENT_URL` to the frontend origin exactly
   (no trailing slash) and redeploy the API. This controls CORS and the share
   links embedded in certificate QR codes.

7. **Smoke test.** Register, notarize a small file, open the certificate, scan
   its QR, verify AUTHENTIC, then verify a modified copy (TAMPERED). On a phone,
   check camera/microphone/location permissions (they require HTTPS).

## Security reminders

- Never reuse the Hardhat test key or a wallet holding real funds.
- Keep `ALLOW_PRIVATE_URLS=false` (the default in `render.yaml`).
- `JWT_SECRET` and `PRIVATE_KEY` must stay in the host's secret store, never in Git.
- After the demo, run `node server/scripts/verify-audit.js --anchor` with the
  deployed configuration to anchor the audit-log head on-chain.
