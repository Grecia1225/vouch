require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const { AMOY_RPC_URL, PRIVATE_KEY } = process.env;

module.exports = {
  solidity: "0.8.24",
  networks: {
    localhost: { url: "http://127.0.0.1:8545" },
    // Polygon Amoy testnet (only enabled when env vars are set)
    ...(AMOY_RPC_URL && PRIVATE_KEY
      ? { amoy: { url: AMOY_RPC_URL, accounts: [PRIVATE_KEY], chainId: 80002 } }
      : {}),
  },
};
