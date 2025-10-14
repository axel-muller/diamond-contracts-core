import { ethers } from "hardhat";
import { aggregatorSol } from "../typechain-types/contracts";


async function runTest() {



    //let address = "0x9990000000000000000000000000000000000000";
    // let address2 = "0x00c795312dAE2FBC3D3D8b157bdBe7eEABE6AB40";

    let address2 = "0x0069D35CDA1e5e2571E7C1bF5F406f7198a148Dc";
    
    let contractFactory = await ethers.getContractFactory("DMDAggregator");

    let connected = contractFactory.connect(ethers);

    let connectedContract = connected.attach(address2) as aggregatorSol.DMDAggregator;

    
    let user = "0x99E83775db0f147c9DEfc3C09CD8F52F4F0c5F53";
     
    try {
        // 1. GET ALL POOLS
        console.log("📊 POOLS DATA");
        console.log("-".repeat(80));
        const pools = await connectedContract.getAllPools();
        console.log("Active Pools:", pools.stActivePools);
        console.log("Inactive Pools:", pools.stInActivePools);
        console.log("Pools To Be Elected:", pools.stPoolsToBeElected);
        console.log("Validators Mining Addresses:", pools.vsValidatorsMiningAddresses);
        console.log("Validators Staking Addresses:", pools.vsValidatorsStakingAddresses);
        console.log("Pending Validators Mining:", pools.vsPendingValidatorsMiningAddresses);
        console.log("Pending Validators Staking:", pools.vsPendingValidatorsStakingAddresses);
        console.log("\n");

        // 2. GET GLOBALS
        console.log("🌍 GLOBAL DATA");
        console.log("-".repeat(80));
        const globals = await connectedContract.getGlobals();
        console.log("Delta Pot:", ethers.formatEther(globals.deltaPot), "ETH");
        console.log("Reinsert Pot:", ethers.formatEther(globals.reinsertPot), "ETH");
        console.log("Keygen Round:", globals.keygenRound.toString());
        console.log("Staking Epoch:", globals.stakingEpoch.toString());
        console.log("Minimum Gas Price:", globals.minimumGasPrice.toString());
        console.log("Candidate Min Stake:", ethers.formatEther(globals.candidateMinStake), "ETH");
        console.log("Delegator Min Stake:", ethers.formatEther(globals.delegatorMinStake), "ETH");
        console.log("Staking Epoch Start Time:", new Date(Number(globals.stakingEpochStartTime) * 1000).toISOString());
        console.log("Staking Epoch Start Block:", globals.stakingEpochStartBlock.toString());
        console.log("Stake/Withdraw Allowed:", globals.areStakeAndWithdrawAllowed);
        console.log("Fixed Epoch End Time:", new Date(Number(globals.stakingFixedEpochEndTime) * 1000).toISOString());
        console.log("Fixed Epoch Duration:", globals.stakingFixedEpochDuration.toString(), "seconds");
        console.log("Withdraw Disallow Period:", globals.stakingWithdrawDisallowPeriod.toString(), "seconds");
        console.log("\n");

        // 3. GET POOLS DATA (for active pools if any exist)
        if (pools.stActivePools.length > 0) {
            console.log("📋 DETAILED POOLS DATA");
            console.log("-".repeat(80));
            console.log("pools:");
            console.table(pools.stActivePools);
            const poolsData = await connectedContract.getPoolsData(pools.stActivePools);
            poolsData.forEach((pool, idx) => {
                console.log(`\nPool ${idx + 1}:`);
                console.log("  Mining Address:", pool.miningAddress);
                console.log("  Available Since:", pool.availableSince.toString());
                console.log("  Public Key:", pool.publicKey);
                console.log("  Delegators Count:", pool.delegators.length);
                console.log("  Delegators:", pool.delegators);
                console.log("  Keygen Mode:", pool.keygenMode);
                console.log("  Total Staked:", ethers.formatEther(pool.stakedAmountTotal), "ETH");
                console.log("  Is Faulty:", pool.isFaultyValidator);
                console.log("  Validator Score:", pool.validatorScore.toString());
                console.log("  Connectivity Score:", pool.connectivityScore.toString());
            });
            console.log("\n");
        }

        // 4. GET USER STAKES (for the signer address on all active pools)
        if (pools.stActivePools.length > 0) {
            console.log("💰 USER STAKES (for current signer)");
            console.log("-".repeat(80));
            const userStakes = await connectedContract.getUserStakes(user, pools.stActivePools);
            userStakes.forEach((stake, idx) => {
                console.log(`Pool ${idx + 1} (${stake.pool}):`);
                console.log("  My Staked Amount:", ethers.formatEther(stake.myStakedAmount), "ETH");
                console.log("  Total Staked:", ethers.formatEther(stake.stakedAmountTotal), "ETH");
            });
            console.log("\n");
        }

        // 5. GET USER ORDERED WITHDRAWS
        if (pools.stActivePools.length > 0) {
            console.log("📤 USER ORDERED WITHDRAWS (for current signer)");
            console.log("-".repeat(80));
            const orderedWithdraws = await connectedContract.getUserOrderedWithdraws(user, pools.stActivePools);
            orderedWithdraws.forEach((withdraw, idx) => {
                if (withdraw.orderedAmount > 0n) {
                    console.log(`Pool ${idx + 1} (${withdraw.pool}):`);
                    console.log("  Ordered Amount:", ethers.formatEther(withdraw.orderedAmount), "ETH");
                    console.log("  Withdraw Epoch:", withdraw.withdrawEpoch.toString());
                }
            });
            console.log("\n");
        }

        // 6. GET DELEGATIONS DATA (for first active pool if exists)
        if (pools.stActivePools.length > 0) {
            const firstPool = pools.stActivePools[0];
            console.log("👥 DELEGATIONS DATA (for first active pool)");
            console.log("-".repeat(80));
            const poolsData = await connectedContract.getPoolsData([firstPool]);
            if (poolsData[0].delegators.length > 0) {
                const [delegatesData, ownStake, candidateStake] = await connectedContract.getDelegationsData(
                    poolsData[0].delegators,
                    firstPool
                );
                console.log("Pool:", firstPool);
                console.log("Own Stake:", ethers.formatEther(ownStake), "ETH");
                console.log("Candidate Stake:", ethers.formatEther(candidateStake), "ETH");
                console.log("\nDelegators:");
                delegatesData.forEach((delegate, idx) => {
                    console.log(`  ${idx + 1}. ${delegate.delegator}: ${ethers.formatEther(delegate.delegatedAmount)} ETH`);
                });
            }
            console.log("\n");
        }

        // 7. GET NODE OPERATOR DATA (for first active pool)
        if (pools.stActivePools.length > 0) {
            console.log("⚙️  NODE OPERATOR DATA (for first active pool)");
            console.log("-".repeat(80));
            const [operator, share] = await connectedContract.getNodeOperatorData(pools.stActivePools[0]);
            console.log("Pool:", pools.stActivePools[0]);
            console.log("Operator:", operator);
            console.log("Share:", share.toString());
            console.log("\n");
        }

        // 8. GET WITHDRAWABLE AMOUNTS (for signer on first active pool)
        if (pools.stActivePools.length > 0) {
            console.log("💸 WITHDRAWABLE AMOUNTS (for current signer on first pool)");
            console.log("-".repeat(80));
            const [maxWithdraw, maxWithdrawOrder] = await connectedContract.getWithdrawableAmounts(
                pools.stActivePools[0],
                user
            );
            console.log("Pool:", pools.stActivePools[0]);
            console.log("Max Withdraw Amount:", ethers.formatEther(maxWithdraw), "ETH");
            console.log("Max Withdraw Order Amount:", ethers.formatEther(maxWithdrawOrder), "ETH");
            console.log("\n");
        }

        // 9. GET DAO GLOBALS
        console.log("🏛️  DAO GLOBALS");
        console.log("-".repeat(80));
        const daoGlobals = await connectedContract.getDaoGlobals();
        console.log("Create Proposal Fee:", ethers.formatEther(daoGlobals.createProposalFee), "ETH");
        console.log("DAO Phase:", daoGlobals.daoPhase);
        console.log("DAO Phase Count:", daoGlobals.daoPhaseCount.toString());
        console.log("DAO Pot Balance:", ethers.formatEther(daoGlobals.daoPotBalance), "ETH");
        console.log("\n");

        // 10. GET ACTIVE PROPOSALS
        console.log("📜 ACTIVE PROPOSALS");
        console.log("-".repeat(80));
        const activeProposals = await connectedContract.getActiveProposals();
        if (activeProposals.length === 0) {
            console.log("No active proposals");
        } else {
            activeProposals.forEach((proposalDetail, idx) => {
                console.log(`\nProposal ${idx + 1}:`);
                console.log("  ID:", idx.toString());
                console.log("  Proposer:", proposalDetail.proposal.proposer);
                console.log("  Title:", proposalDetail.proposal.title);
                console.log("  Description:", proposalDetail.proposal.description);
                console.log("  Type:", proposalDetail.proposal.proposalType);
                console.log("  State:", proposalDetail.proposal.state);
                console.log("  Voters Count:", proposalDetail.votersCount.toString());
                console.log("  Total DAO Stake:", ethers.formatEther(proposalDetail.totalDaoStake), "ETH");
                console.log("  Voting Result - For:", ethers.formatEther(proposalDetail.votingResult.countYes), "ETH");
                console.log("  Voting Result - Against:", ethers.formatEther(proposalDetail.votingResult.countNo), "ETH");
            });
        }
        console.log("\n");

        // 11. GET HISTORIC PROPOSALS
        console.log("📚 HISTORIC PROPOSALS");
        console.log("-".repeat(80));
        const historicProposals = await connectedContract.getHistoricProposals();
        console.log(`Total Historic Proposals: ${historicProposals.length}`);
        if (historicProposals.length > 0) {
            console.log("\nShowing first 5 proposals:");
            historicProposals.slice(0, 5).forEach((proposalDetail, idx) => {
                console.log(`\n  Proposal ${idx + 1}:`);
                console.log("    ID:", idx.toString());
                console.log("    Title:", proposalDetail.proposal.title);
                console.log("    State:", proposalDetail.proposal.state);
                console.log("    DAO Phase:", proposalDetail.proposal.daoPhaseCount.toString());
            });
        }
        console.log("\n");

        console.log("=".repeat(80));
        console.log("✅ All data fetched successfully!");
        
    } catch (error) {
        console.error("\n❌ Error:", error);
    }



}


runTest();