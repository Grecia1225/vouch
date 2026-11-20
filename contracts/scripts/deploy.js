const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

const EXPLORERS = { amoy: "https://amoy.polygonscan.com" };

async function main() {
  const { ethers } = hre;
  const [deployer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Network   ${hre.network.name} (chain id ${net.chainId})`);
  console.log(`Deployer  ${deployer.address}`);
  console.log(`Balance   ${ethers.formatEther(balance)}`);
  if (balance === 0n) throw new Error("Deployer wallet has no funds. On Amoy, get test POL from the faucet first (see docs/AMOY_GUIDE.md).");

  const Vouch = await ethers.getContractFactory("Vouch");
  const vouch = await Vouch.deploy();
  const deployTx = vouch.deploymentTransaction();
  await vouch.waitForDeployment();
  const receipt = await deployTx.wait();
  const address = await vouch.getAddress();

  console.log(`\nVouch deployed to ${address}`);
  console.log(`Gas used  ${receipt.gasUsed} | block ${receipt.blockNumber} | tx ${deployTx.hash}`);
  const explorer = EXPLORERS[hre.network.name];
  if (explorer) console.log(`Explorer  ${explorer}/address/${address}`);

  const info = { network: hre.network.name, chainId: Number(net.chainId), address, deployer: deployer.address, txHash: deployTx.hash, blockNumber: receipt.blockNumber, deployedAt: new Date().toISOString() };
  fs.mkdirSync(path.join(__dirname, "../deployments"), { recursive: true });
  fs.writeFileSync(path.join(__dirname, `../deployments/${hre.network.name}.json`), JSON.stringify(info, null, 2));
  // The backend reads this file to find the contract
  fs.writeFileSync(path.join(__dirname, "../../server/deployment.json"), JSON.stringify({ network: hre.network.name, address }, null, 2));
  console.log("\nSaved contracts/deployments/" + hre.network.name + ".json and server/deployment.json");
  if (explorer) {
    console.log("\nAdd to server/.env:");
    console.log(`  CONTRACT_ADDRESS=${address}`);
    console.log(`  EXPLORER_TX_URL=${explorer}/tx/`);
  }
}

main().catch((e) => { console.error(e.message); process.exit(1); });
