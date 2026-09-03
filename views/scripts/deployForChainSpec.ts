import fs from "fs";
import { ethers } from "hardhat";

interface ContractSpec {
    balance: string,
    constructor: string
}

async function deployForChainspec() {
    const [deployer] = await ethers.getSigners();
    const dmdAggregatorFactory = await ethers.getContractFactory("DMDAggregator");
    
    const initialOwner = deployer.address;
    const staking = '0x1100000000000000000000000000000000000001'; // Staking
    const validatorSet = '0x1000000000000000000000000000000000000001'; // ValidatorSet
    const txPermisson = '0x4000000000000000000000000000000000000001'; // TxPermisson
    const dao = '0xDA0da0da0Da0Da0Da0DA00DA0da0da0DA0DA0dA0'; // DAO

    let spec: { [id: string]: ContractSpec; } = {};

    const aggregatorAddress = "0x9990000000000000000000000000000000000000";
    spec[aggregatorAddress] = {
        balance: "0",
        constructor: (await dmdAggregatorFactory.getDeployTransaction(initialOwner, staking, validatorSet, txPermisson, dao)).data
    };

    if (!fs.existsSync("out")) {
        fs.mkdirSync("out");
    }

    fs.writeFileSync("out/spec_aggregator.json", JSON.stringify(spec));
    console.log("Chainspec generated.");
}

deployForChainspec();