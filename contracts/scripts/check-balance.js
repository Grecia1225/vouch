// Prints the deployer address and balance, so you know the faucet worked before deploying.
//   npx hardhat run scripts/check-balance.js --network amoy
const hre = require("hardhat");
(async () => {
  const [s] = await hre.ethers.getSigners();
  const net = await hre.ethers.provider.getNetwork();
  const bal = await hre.ethers.provider.getBalance(s.address);
  console.log(`${hre.network.name} (chain id ${net.chainId})\n${s.address}\nbalance: ${hre.ethers.formatEther(bal)}`);
})().catch((e) => { console.error(e.message); process.exit(1); });
