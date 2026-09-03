import fs from "fs";
import hre from "hardhat";
import { ethers } from "hardhat";
import { getInitializerData } from "@openzeppelin/hardhat-upgrades/dist/utils";

const aggregatorProxyAddress = "0x9990000000000000000000000000000000000000";
const aggregatorImplementationAddress = "0x9999000000000000000000000000000000000000";

interface ContractSpec {
    balance: string,
    constructor: string
}

async function compileProxy() {
    const [deployer] = await ethers.getSigners();
    const proxyFactory = await hre.ethers.getContractFactory("TransparentUpgradeableProxy");

    const dmdAggregatorFactory = await hre.ethers.getContractFactory("DMDAggregatorUpgradeable");

    let spec: { [id: string]: ContractSpec; } = {};

    spec[aggregatorImplementationAddress] = {
        balance: "0",
        constructor: (await dmdAggregatorFactory.getDeployTransaction()).data
    };

    let aggregatorInitArgs: any[] = [
        deployer.address, // Initial Owner
        '0x1100000000000000000000000000000000000001', // Staking
        '0x1000000000000000000000000000000000000001', // ValidatorSet
        '0x4000000000000000000000000000000000000001', // TxPermisson
        '0xDA0da0da0Da0Da0Da0DA00DA0da0da0DA0DA0dA0' // DAO
    ];

    console.log("Initializer Arguments:", aggregatorInitArgs);
    const initializerData = getInitializerData(dmdAggregatorFactory.interface, aggregatorInitArgs, 'initialize');

    let proxyDeployTX = await proxyFactory.getDeployTransaction(aggregatorImplementationAddress, aggregatorProxyAddress, initializerData);
    spec[aggregatorProxyAddress] = {
        balance: "0",
        constructor: proxyDeployTX.data
    };

    if (!fs.existsSync("out")) {
        fs.mkdirSync("out");
    }

    fs.writeFileSync("out/spec_aggregatorUpgradeable.json", JSON.stringify(spec));
    console.log("Upgradeable chainspec generated.");
}

compileProxy();