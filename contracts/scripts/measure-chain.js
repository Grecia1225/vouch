/**
 * On-chain measurements: gas per operation, confirmation time, read latency, estimated cost.
 *   npx hardhat run scripts/measure-chain.js                 (in-process network: gas is exact, timings are not meaningful)
 *   N=20 npx hardhat run scripts/measure-chain.js --network amoy   (real network: costs a little test POL)
 * Optional: POL_PRICE_USD=0.20 to convert gas to dollars (testnet tokens are free; this is for a mainnet estimate).
 * Writes ../measurements/chain-<network>.json and .md
 */
const hre = require("hardhat");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const rand = () => "0x" + crypto.randomBytes(32).toString("hex");
const stat = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  return { mean: +mean.toFixed(1), min: s[0], p95: s[Math.min(s.length - 1, Math.ceil(s.length * 0.95) - 1)], max: s[s.length - 1] };
};

async function main() {
  const { ethers } = hre;
  const N = Number(process.env.N) || (hre.network.name === "hardhat" ? 100 : 20);
  const [signer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  const Vouch = await ethers.getContractFactory("Vouch");
  const vouch = await Vouch.deploy();
  await vouch.waitForDeployment();
  const deployGas = Number((await vouch.deploymentTransaction().wait()).gasUsed);
  console.log(`Measuring on ${hre.network.name} (chain id ${net.chainId}), ${N} transactions per operation...`);

  const notarizeRows = [], versionRows = [], hashes = [];
  for (let i = 0; i < N; i++) {
    const h = rand(); hashes.push(h);
    const t0 = Date.now();
    const rc = await (await vouch.notarize(h, "user-" + crypto.randomBytes(12).toString("hex"))).wait();
    notarizeRows.push({ gas: Number(rc.gasUsed), ms: Date.now() - t0 });
    process.stdout.write(".");
  }
  for (let i = 0; i < N; i++) {
    const t0 = Date.now();
    const rc = await (await vouch.notarizeVersion(rand(), hashes[i], "user-" + crypto.randomBytes(12).toString("hex"))).wait();
    versionRows.push({ gas: Number(rc.gasUsed), ms: Date.now() - t0 });
    process.stdout.write("+");
  }
  const readMs = [];
  for (let i = 0; i < 50; i++) {
    const t0 = performance.now();
    await vouch.verify(hashes[i % hashes.length]);
    readMs.push(performance.now() - t0);
  }
  console.log();

  const fee = await ethers.provider.getFeeData();
  const gasPriceGwei = fee.gasPrice ? Number(ethers.formatUnits(fee.gasPrice, "gwei")) : null;
  const polPrice = Number(process.env.POL_PRICE_USD) || null;
  const cost = (gas) => (gasPriceGwei ? +((gas * gasPriceGwei) / 1e9).toFixed(8) : null); // in native token
  const nGas = stat(notarizeRows.map((r) => r.gas)), vGas = stat(versionRows.map((r) => r.gas));

  const result = {
    generatedAt: new Date().toISOString(), network: hre.network.name, chainId: Number(net.chainId), transactionsPerOperation: N,
    gasPriceGwei, polPriceUsd: polPrice,
    deployGas,
    notarize: { gas: nGas, confirmMs: stat(notarizeRows.map((r) => r.ms)), nativeTokenCostMean: cost(nGas.mean) },
    notarizeVersion: { gas: vGas, confirmMs: stat(versionRows.map((r) => r.ms)), nativeTokenCostMean: cost(vGas.mean) },
    verifyReadMs: stat(readMs.map((x) => +x.toFixed(2))),
  };
  const usd = (c) => (c !== null && polPrice ? ` (about $${(c * polPrice).toFixed(6)})` : "");
  const md = `# On-chain measurements: ${result.network} (chain id ${result.chainId})

Generated ${result.generatedAt}. ${N} transactions per operation. Gas price used: ${gasPriceGwei ?? "n/a"} gwei.
${result.network === "hardhat" ? "\n> In-process test network: gas figures are exact, but confirmation times are NOT meaningful. Run with --network amoy for real timings.\n" : ""}
| Operation | Gas (mean) | Gas (min / p95 / max) | Confirmation ms (mean / p95) | Cost in native token |
|---|---|---|---|---|
| notarize | ${nGas.mean} | ${nGas.min} / ${nGas.p95} / ${nGas.max} | ${result.notarize.confirmMs.mean} / ${result.notarize.confirmMs.p95} | ${result.notarize.nativeTokenCostMean ?? "n/a"}${usd(result.notarize.nativeTokenCostMean)} |
| notarizeVersion | ${vGas.mean} | ${vGas.min} / ${vGas.p95} / ${vGas.max} | ${result.notarizeVersion.confirmMs.mean} / ${result.notarizeVersion.confirmMs.p95} | ${result.notarizeVersion.nativeTokenCostMean ?? "n/a"}${usd(result.notarizeVersion.nativeTokenCostMean)} |

Contract deployment: ${deployGas} gas. Verification (\`verify\` read call, no gas, no fee): mean ${result.verifyReadMs.mean} ms, p95 ${result.verifyReadMs.p95} ms.

Reading these numbers: a document costs one small transaction regardless of its size, because only a 32-byte hash is stored. Reads are free, so anyone can verify at no cost.
`;
  const dir = path.join(__dirname, "../../measurements");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `chain-${result.network}.json`), JSON.stringify(result, null, 2));
  fs.writeFileSync(path.join(dir, `chain-${result.network}.md`), md);
  console.log("\n" + md);
}

main().catch((e) => { console.error(e); process.exit(1); });
