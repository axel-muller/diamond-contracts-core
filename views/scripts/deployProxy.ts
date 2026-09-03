import { ethers } from "hardhat";
import { deployProxy, verifyContract } from "../utils/deployment";

async function deploy() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying from: ", deployer.address);

  const args = [
    deployer.address, // Initial Owner
    '0x1100000000000000000000000000000000000001', // Staking
    '0x1000000000000000000000000000000000000001', // ValidatorSet
    '0x4000000000000000000000000000000000000001', // TxPermisson
    '0xDA0da0da0Da0Da0Da0DA00DA0da0da0DA0DA0dA0' // DAO
  ]

  // Deploy the DMDAggregator contract using a proxy for upgradeability
  const dao = await deployProxy("DMDAggregatorUpgradeable", args);

  await dao.waitForDeployment();

  console.log("DMDAggregator deployed at: ", await dao.getAddress());

  console.log("Verifying DMDAggregator contract...");

  await verifyContract(dao, args, 60);

  console.log("Done.");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
deploy().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
