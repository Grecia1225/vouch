# Deployment guide

Not tested on a real host from the build environment: follow the steps and report any error. Free tiers sleep when idle, so open the site a minute before a demo.

## Option A: Docker on your laptop or a VPS
Needs Docker. The chain is external (deploy to Amoy first, see `AMOY_GUIDE.md`).
```
cp .env.docker.example .env.docker      # fill in secrets
docker compose up --build
```
Open http://localhost:8080. nginx serves the app and proxies `/api` to the server. For a VPS, put HTTPS in front (Caddy or nginx with Let's Encrypt) and set `CLIENT_URL` to the https address, because camera, microphone and location only work on HTTPS.

## Option B: free cloud tiers
1. **Database:** create a MongoDB Atlas free cluster. Add a database user, allow network access from anywhere (or the host's IPs), copy the connection string as `MONGO_URI`.
2. **API (Render):** New, Blueprint, point at your repo (uses `render.yaml`), or create a Docker web service with root `server/`. Set the environment variables listed in the file. Note the API URL, for example `https://vouch-api.onrender.com`.
3. **Frontend (Vercel or Netlify):** import the repo, root directory `client/`, build `npm run build`, output `dist`. Set the build variable `VITE_API_BASE=https://vouch-api.onrender.com/api`. `client/vercel.json` handles page refreshes.
4. **Connect them:** set the API's `CLIENT_URL` to the frontend's exact https origin (it is used for CORS and for certificate QR links). Redeploy the API.
5. **Smoke test:** `GET <api>/api/health` shows the contract address; register, notarize a file, open the certificate, scan its QR.

## Environment variables
| Variable | Purpose |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `JWT_SECRET` | Long random string; changing it logs everyone out |
| `CLIENT_URL` | Exact frontend origin (CORS and QR links) |
| `RPC_URL` | Server's RPC endpoint (may contain a private key from your provider) |
| `PUBLIC_RPC_URL` | Key-free RPC shown to browsers for independent checks |
| `PRIVATE_KEY` | Relayer wallet. Test wallet only |
| `CONTRACT_ADDRESS` | Deployed contract (or ship `deployment.json`) |
| `EXPLORER_TX_URL` | Transaction link prefix |
| `ALLOW_PRIVATE_URLS` | Keep `false` in any deployment |

## Hardening checklist before sharing a public link
- [ ] Strong `JWT_SECRET`, HTTPS everywhere
- [ ] Relayer wallet holds only test funds
- [ ] `ALLOW_PRIVATE_URLS=false`
- [ ] MongoDB not open to the world without a password
- [ ] Run `node server/scripts/verify-audit.js --anchor` after the demo to anchor the audit log head on-chain
