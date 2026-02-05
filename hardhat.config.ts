import * as fs from "fs";
import { ethers } from "ethers";
import { HardhatUserConfig } from "hardhat/config";

import "@openzeppelin/hardhat-upgrades";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-toolbox";

const getMnemonic = () => {
  try {
    return fs.readFileSync(".mnemonic").toString().trim();
  } catch {
    // this is a dummy mnemonic, never use it for anything.
    return "arrive furnace echo arch airport scrap glow gold brief food torch senior winner myself mutual";
  }
};

const mnemonic: string = process.env.MNEMONIC ? process.env.MNEMONIC : ethers.Mnemonic.entropyToPhrase(ethers.randomBytes(32));

const chainIds = {
  hardhat: 31337,
  testnet: 37373,
  mainnet: 17771,
};

const config: HardhatUserConfig = {
  solidity: "0.8.25",
  defaultNetwork: "mainnet",
  networks: {
    hardhat: {
      accounts: {
        count: 100,
        mnemonic,
        accountsBalance: "1000000000000000000000000000"
      },
      chainId: chainIds.hardhat,
      allowUnlimitedContractSize: true,
      hardfork: "istanbul",
      minGasPrice: 0
    },
    testnet: {
      url: "https://rpc-testnet.bit.diamonds",
      accounts: {
        mnemonic: getMnemonic(),
        path: "m/44'/60'/0'/0",
        initialIndex: 0,
        count: 20,
        passphrase: "",
      },
      gasPrice: 1000000000,
    },
    mainnet: {
      url: "https://rpc.bit.diamonds",
      chainId: 17771,
      accounts: {
        mnemonic: getMnemonic(),
        path: "m/44'/60'/0'/0",
        initialIndex: 0,
        count: 20,
        passphrase: "",
      },
      gasPrice: 1000000000,
    },
  },
  etherscan: {
    apiKey: "123",
    customChains: [
      {
        network: "testnet",
        chainId: 37373,
        urls: {
            apiURL: "http://62.171.133.46:4000/api",
            browserURL: "http://62.171.133.46:4000",
        },
      },
      {
        network: "mainnet",
        chainId: 17771,
        urls: {
            apiURL: "https://explorer.bit.diamonds/api",
            browserURL: "https://explorer.bit.diamonds",
        },
      },
    ],
  },
};

export default config;