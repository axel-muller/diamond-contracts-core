import { ethers, network, upgrades } from "hardhat";
import { expect } from "chai";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import * as _ from "lodash";
import fp from "lodash/fp";

import {
    BlockRewardHbbftMock,
    ValidatorSetHbbftMock,
    StakingHbbftMock,
    RandomHbbft,
    KeyGenHistory,
    CertifierHbbft,
    TxPermissionHbbft,
} from "../src/types";

describe.skip("MaliciousReportSystem", async () => {
    describe('BlockRewardHbbft', () => {
        it('should not reward banned validators', async () => {
            const {
                blockRewardContract,
                validatorSetContract,
                stakingContract,
            } = await helpers.loadFixture(deployContractsFixture);

            for (const _staking of initialStakingAddresses) {
                const pool = await ethers.getSigner(_staking);

                await stakingContract.connect(pool).stake(pool.address, { value: candidateMinStake });
                expect(await stakingContract.stakeAmountTotal(pool.address)).to.be.eq(candidateMinStake);
            }

            await callReward(blockRewardContract, true);
            await callReward(blockRewardContract, true);

            const fixedEpochEndTime = await stakingHbbft.stakingFixedEpochEndTime();
            await helpers.time.increaseTo(fixedEpochEndTime + 1n);
            await helpers.mine(1);

            const deltaPotValue = ethers.parseEther('10');
            await blockRewardContract.addToDeltaPot({ value: deltaPotValue });
            expect(await blockRewardContract.deltaPot()).to.be.eq(deltaPotValue);

            const now = (await ethers.provider.getBlock('latest'))!.timestamp;

            for (const validator of initialValidators) {
                await validatorSetContract.setBannedUntil(validator, now + 3600);
                expect(await validatorSetContract.isValidatorBanned(validator)).to.be.true;
            }

            const systemSigner = await impersonateAcc(SystemAccountAddress);
            await expect(blockRewardContract.connect(systemSigner).reward(true))
                .to.emit(blockRewardContract, "CoinsRewarded")
                .withArgs(0n);
            await helpers.stopImpersonatingAccount(SystemAccountAddress);
        });
    });

    describe('StakingHbbft', () => {
        it("shouldn't allow withdrawing from a banned pool", async () => {
            const { stakingHbbft, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: stakeAmount });
            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: stakeAmount });

            await validatorSetHbbft.setBannedUntil(initialValidators[1], '0xffffffffffffffff');

            const maxAllowedForPool = await stakingHbbft.maxWithdrawOrderAllowed(pool.address, pool.address);
            await expect(stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount))
                .to.be.revertedWithCustomError(stakingHbbft, "MaxAllowedWithdrawExceeded")
                .withArgs(maxAllowedForPool, stakeAmount);

            const maxAllowedForDelegator = await stakingHbbft.maxWithdrawOrderAllowed(pool.address, delegatorAddress.address);
            await expect(stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount))
                .to.be.revertedWithCustomError(stakingHbbft, "MaxAllowedWithdrawExceeded")
                .withArgs(maxAllowedForDelegator, stakeAmount);

            await validatorSetHbbft.setBannedUntil(initialValidators[1], 0n);
            await stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount);
            await stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount);
        });

        it('should fail for a banned validator', async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });

            const systemSigner = await impersonateAcc(SystemAccountAddress);
            await validatorSetHbbft.connect(systemSigner).removeMaliciousValidators([initialValidators[1]]);

            await expect(stakingHbbft.connect(delegatorAddress).stake(
                pool.address,
                { value: delegatorMinStake }
            )).to.be.revertedWithCustomError(stakingHbbft, "PoolMiningBanned")
                .withArgs(pool.address);

            await helpers.stopImpersonatingAccount(systemSigner.address);
        });
    });

    describe('ValidatorSetHbbft', async  () => {
        describe('setBanDuration', async () => {
            it("should restrict calling to contract owner", async () => {
                const { validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

                const caller = accounts[5];

                await expect(validatorSetHbbft.connect(caller).setBanDuration(0n))
                    .to.be.revertedWithCustomError(validatorSetHbbft, "OwnableUnauthorizedAccount")
                    .withArgs(caller.address);
            });

            it("should set ban duration", async () => {
                const { validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);
                const newValue = 150n;

                await expect(validatorSetHbbft.connect(owner).setBanDuration(newValue))
                    .to.emit(validatorSetHbbft, "SetBanDuration")
                    .withArgs(newValue);

                expect(await validatorSetHbbft.banDuration()).to.equal(newValue);
            });
        });

        describe('reportMalicious', async () => {
            let validatorSetHbbftContract: ValidatorSetHbbftMock;

            beforeEach(async () => {
                const { validatorSetHbbft, stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

                validatorSetHbbftContract = validatorSetHbbft;

                // fill validators pool
                const additionalValidators = accountAddresses.slice(7, 52 + 1); // accounts[7...32]
                const additionalStakingAddresses = accountAddresses.slice(53, 99 + 1); // accounts[33...59]

                expect(additionalValidators).to.be.lengthOf(46);
                expect(additionalStakingAddresses).to.be.lengthOf(46);

                await network.provider.send("evm_setIntervalMining", [8]);

                for (let i = 0; i < additionalValidators.length; i++) {
                    let stakingAddress = await ethers.getSigner(additionalStakingAddresses[i]);
                    let miningAddress = await ethers.getSigner(additionalValidators[i]);

                    await stakingHbbft.connect(stakingAddress).addPool(
                        miningAddress.address,
                        ethers.zeroPadBytes("0x00", 64),
                        ethers.zeroPadBytes("0x00", 16),
                        { value: MIN_STAKE }
                    );
                    await announceAvailability(validatorSetHbbftContract, miningAddress.address);

                }
                await validatorSetHbbftContract.setBlockRewardContract(accounts[4].address);
                await validatorSetHbbftContract.connect(accounts[4]).newValidatorSet();
                await validatorSetHbbftContract.connect(accounts[4]).finalizeChange();

                // after epoch was finalized successfully, validator set length is healthy
                expect(await validatorSetHbbft.getValidators()).to.be.lengthOf(25);
            });

            it("Should be able to increase max amount of active validators", async () => {
                await validatorSetHbbftContract.setMaxValidators(30);

                await validatorSetHbbftContract.setBlockRewardContract(accounts[4].address);
                await validatorSetHbbftContract.connect(accounts[4]).newValidatorSet();
                await validatorSetHbbftContract.connect(accounts[4]).finalizeChange();

                // after epoch was finalized successfully, validator set length is healthy
                expect(await validatorSetHbbftContract.getValidators()).to.be.lengthOf(30);
            })

            it("Should be able to report a malicious validator", async () => {
                let reportBlock = (await ethers.provider.getBlockNumber()) - 1;
                let maliciousMiningAddress = (await validatorSetHbbftContract.getValidators())[0];

                let reportingMiningAddress = await ethers.getSigner((await validatorSetHbbftContract.getValidators())[1])
                await validatorSetHbbftContract.connect(reportingMiningAddress).reportMalicious(
                    maliciousMiningAddress,
                    reportBlock,
                    EmptyBytes,
                );

                const reportsForBlock = await validatorSetHbbftContract.maliceReportedForBlock(maliciousMiningAddress, reportBlock);

                expect(reportsForBlock[0]).to.be.eq(reportingMiningAddress.address);
            })

            it("Shouldn't be able to report a malicious validator in a future block", async () => {
                const reportBlock = await ethers.provider.getBlockNumber() + 10;
                const validators = await validatorSetHbbftContract.getValidators();
                const maliciousMiningAddress = validators[0];
                const reporter = await ethers.getSigner(validators[1]);

                await validatorSetHbbftContract.connect(reporter).reportMalicious(
                    maliciousMiningAddress,
                    reportBlock,
                    EmptyBytes,
                );

                expect(await validatorSetHbbftContract.maliceReportedForBlock(maliciousMiningAddress, reportBlock)).to.be.empty;
            })

            it("Should ban validator after 17 reports", async () => {
                let currentValidatorSet = await validatorSetHbbftContract.getValidators()
                let reportBlock = (await ethers.provider.getBlockNumber()) - 1;
                let maliciousMiningAddress = (await validatorSetHbbftContract.getValidators())[0];

                for (let i = 1; i < currentValidatorSet.length; i++) {
                    let reportingMiningAddress = await ethers.getSigner(currentValidatorSet[i])
                    await validatorSetHbbftContract.connect(reportingMiningAddress).reportMalicious(
                        maliciousMiningAddress,
                        reportBlock,
                        EmptyBytes,
                    );
                }

                expect(await validatorSetHbbftContract.maliceReportedForBlock(maliciousMiningAddress, reportBlock)).to.be.lengthOf(17);
                expect(await validatorSetHbbftContract.isValidatorBanned(maliciousMiningAddress)).to.be.true;
            })

            it("Validator should get banned if spamming reports (50*maxValidators)", async () => {
                let currentValidatorSet = await validatorSetHbbftContract.getValidators()
                let reportBlock = (await ethers.provider.getBlockNumber()) - 1;
                let reportingMiningAddress = await ethers.getSigner((await validatorSetHbbftContract.getValidators())[0])

                for (let i = 1; i < 54; i++) {
                    for (let j = 1; j < currentValidatorSet.length; j++) {
                        let maliciousMiningAddress = currentValidatorSet[j]
                        await validatorSetHbbftContract.connect(reportingMiningAddress).reportMalicious(
                            maliciousMiningAddress,
                            reportBlock - i,
                            EmptyBytes,
                        );
                    }
                }

                expect(await validatorSetHbbftContract.isValidatorBanned(reportingMiningAddress.address)).to.be.true;
            })
        });

        describe('removeMaliciousValidators', async () => {
            it("should restrict calling to system address", async () => {
                const { validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

                await expect(validatorSetHbbft.connect(owner).removeMaliciousValidators([ethers.ZeroAddress]))
                    .to.be.revertedWithCustomError(validatorSetHbbft, "Unauthorized");
            });

            it("should call by system address", async () => {
                const { validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

                const systemSigner = await impersonateAcc(SystemAccountAddress);
                expect(await validatorSetHbbft.connect(systemSigner).removeMaliciousValidators(
                    [initialValidators[1]]
                ));

                await helpers.stopImpersonatingAccount(systemSigner.address);
            });
        });
    });

    describe('TxPermissionHbbft', async () => {
        it("should allow reportMalicious if callable", async function () {
            const { txPermission, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const gasPrice = await txPermission.minimumGasPrice();
            const reporter = await ethers.getSigner(initialValidators[0]);
            const malicious = initialValidators[1];

            const latestBlock = await helpers.time.latestBlock();

            const calldata = validatorSetHbbft.interface.encodeFunctionData(
                "reportMalicious",
                [
                    malicious,
                    latestBlock - 1,
                    EmptyBytes,
                ]
            );

            const result = await txPermission.allowedTxTypes(
                reporter.address,
                await validatorSetHbbft.getAddress(),
                0n,
                gasPrice,
                ethers.hexlify(calldata),
            );

            expect(result.typesMask).to.equal(AllowedTxTypeMask.Call);
            expect(result.cache).to.be.false;
        });

        it("should allow reportMalicious if callable with data length <= 64", async function () {
            const { txPermission, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const gasPrice = await txPermission.minimumGasPrice();
            const reporter = await ethers.getSigner(initialValidators[0]);
            const malicious = initialValidators[1];

            const latestBlock = await helpers.time.latestBlock();

            const calldata = validatorSetHbbft.interface.encodeFunctionData(
                'reportMalicious',
                [
                    malicious,
                    latestBlock - 1,
                    EmptyBytes
                ]
            );

            const slicedCalldata = calldata.slice(0, calldata.length - 128);

            const result = await txPermission.allowedTxTypes(
                reporter.address,
                await validatorSetHbbft.getAddress(),
                0n,
                gasPrice,
                ethers.hexlify(slicedCalldata),
            );

            expect(result.typesMask).to.equal(AllowedTxTypeMask.Call);
            expect(result.cache).to.be.false;
        });

        it("should not allow reportMalicious if not callable", async function () {
            const { txPermission, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const gasPrice = await txPermission.minimumGasPrice();

            // If reporter is not validator, reportMalicious is not callable, that means tx is not allowed
            const reporter = await ethers.getSigner(initialStakingAddresses[0]);
            const malicious = initialValidators[1];

            const latestBlock = await helpers.time.latestBlock();

            const calldata = validatorSetHbbft.interface.encodeFunctionData(
                'reportMalicious',
                [
                    malicious,
                    latestBlock - 1,
                    EmptyBytes
                ]
            );

            const result = await txPermission.allowedTxTypes(
                reporter.address,
                await validatorSetHbbft.getAddress(),
                0,
                gasPrice,
                ethers.hexlify(calldata),
            );

            expect(result.typesMask).to.equal(AllowedTxTypeMask.None);
            expect(result.cache).to.be.false;
        });
    });
});
