import { ethers, network, upgrades } from "hardhat";
import { expect } from "chai";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import * as helpers from "@nomicfoundation/hardhat-network-helpers";
import fp from "lodash/fp";

import {
    BlockRewardHbbftMock,
    RandomHbbft,
    ValidatorSetHbbftMock,
    StakingHbbftMock,
    KeyGenHistory,
} from "../src/types";

import { getNValidatorsPartNAcks } from "./testhelpers/data";
import { getSigner } from "@openzeppelin/hardhat-upgrades/dist/utils";

//consts
const SystemAccountAddress = '0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE';
const ZeroPublicKey = ethers.zeroPadBytes("0x00", 64);
const ZeroIpAddress = ethers.zeroPadBytes("0x00", 16);

describe('StakingHbbft', () => {
    let owner: HardhatEthersSigner;
    let candidateMiningAddress: HardhatEthersSigner;
    let candidateStakingAddress: HardhatEthersSigner;
    let accounts: HardhatEthersSigner[];

    let initialValidators: string[];
    let initialStakingAddresses: string[];
    let initialValidatorsPubKeys: string[];
    let initialValidatorsPubKeysSplit: string[];
    let initialValidatorsIpAddresses: string[];

    const minStake = ethers.parseEther('1');
    const maxStake = ethers.parseEther('100000');

    // the reward for the first epoch.
    const epochReward = ethers.parseEther('1');

    // one epoch in 1 day.
    const stakingFixedEpochDuration = 86400n;

    // the transition time window is 1 hour.
    const stakingTransitionTimeframeLength = 3600n;
    const stakingWithdrawDisallowPeriod = 1n;

    // the amount the deltaPot gets filled up.
    // this is 60-times more, since the deltaPot get's
    // drained each step by 60 by default.
    const deltaPotFillupValue = epochReward * 60n;

    const validatorInactivityThreshold = 365n * 86400n // 1 year

    async function impersonateAcc(accAddress: string) {
        await helpers.impersonateAccount(accAddress);

        await owner.sendTransaction({
            to: accAddress,
            value: ethers.parseEther('10'),
        });

        return await ethers.getSigner(accAddress);
    }

    async function deployContractsFixture() {
        const stubAddress = owner.address;

        const ConnectivityTrackerFactory = await ethers.getContractFactory("ConnectivityTrackerHbbftMock");
        const connectivityTracker = await ConnectivityTrackerFactory.deploy();
        await connectivityTracker.waitForDeployment();

        // Deploy ValidatorSet contract
        const ValidatorSetFactory = await ethers.getContractFactory("ValidatorSetHbbftMock");
        const validatorSetHbbftProxy = await upgrades.deployProxy(
            ValidatorSetFactory,
            [
                owner.address,
                stubAddress,                  // _blockRewardContract
                stubAddress,                  // _randomContract
                stubAddress,                  // _stakingContract
                stubAddress,                  // _keyGenHistoryContract
                validatorInactivityThreshold, // _validatorInactivityThreshold
                initialValidators,            // _initialMiningAddresses
                initialStakingAddresses,      // _initialStakingAddresses
            ],
            { initializer: 'initialize' }
        );

        await validatorSetHbbftProxy.waitForDeployment();

        // Deploy BlockRewardHbbft contract
        const BlockRewardHbbftFactory = await ethers.getContractFactory("BlockRewardHbbftMock");
        const blockRewardHbbftProxy = await upgrades.deployProxy(
            BlockRewardHbbftFactory,
            [
                owner.address,
                await validatorSetHbbftProxy.getAddress(),
                await connectivityTracker.getAddress(),
            ],
            { initializer: 'initialize' }
        );

        await blockRewardHbbftProxy.waitForDeployment();

        await validatorSetHbbftProxy.setBlockRewardContract(await blockRewardHbbftProxy.getAddress());

        const RandomHbbftFactory = await ethers.getContractFactory("RandomHbbft");
        const randomHbbftProxy = await upgrades.deployProxy(
            RandomHbbftFactory,
            [
                owner.address,
                await validatorSetHbbftProxy.getAddress()
            ],
            { initializer: 'initialize' }
        );

        await randomHbbftProxy.waitForDeployment();

        //without that, the Time is 0,
        //meaning a lot of checks that expect time to have some value deliver incorrect results.
        // await increaseTime(1);

        const { parts, acks } = getNValidatorsPartNAcks(initialValidators.length);

        const KeyGenFactory = await ethers.getContractFactory("KeyGenHistory");
        const keyGenHistoryProxy = await upgrades.deployProxy(
            KeyGenFactory,
            [
                owner.address,
                await validatorSetHbbftProxy.getAddress(),
                initialValidators,
                parts,
                acks
            ],
            { initializer: 'initialize' }
        );

        await keyGenHistoryProxy.waitForDeployment();

        let stakingParams = {
            _validatorSetContract: await validatorSetHbbftProxy.getAddress(),
            _initialStakingAddresses: initialStakingAddresses,
            _delegatorMinStake: minStake,
            _candidateMinStake: minStake,
            _maxStake: maxStake,
            _stakingFixedEpochDuration: stakingFixedEpochDuration,
            _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
            _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
        };

        // The following private keys belong to the accounts 1-3, fixed by using the "--mnemonic" option when starting ganache.
        // const initialValidatorsPrivKeys = ["0x272b8400a202c08e23641b53368d603e5fec5c13ea2f438bce291f7be63a02a7", "0xa8ea110ffc8fe68a069c8a460ad6b9698b09e21ad5503285f633b3ad79076cf7", "0x5da461ff1378256f69cb9a9d0a8b370c97c460acbe88f5d897cb17209f891ffc"];
        // Public keys corresponding to the three private keys above.
        initialValidatorsPubKeys = [
            '0x52be8f332b0404dff35dd0b2ba44993a9d3dc8e770b9ce19a849dff948f1e14c57e7c8219d522c1a4cce775adbee5330f222520f0afdabfdb4a4501ceeb8dcee',
            '0x99edf3f524a6f73e7f5d561d0030fc6bcc3e4bd33971715617de7791e12d9bdf6258fa65b74e7161bbbf7ab36161260f56f68336a6f65599dc37e7f2e397f845',
            '0xa255fd7ad199f0ee814ee00cce44ef2b1fa1b52eead5d8013ed85eade03034ae4c246658946c2e1d7ded96394a1247fb4d093c32474317ae388e8d25692a0f56'
        ];

        initialValidatorsPubKeysSplit = fp.flatMap((x: string) => [x.substring(0, 66), '0x' + x.substring(66, 130)])
            (initialValidatorsPubKeys);

        // The IP addresses are irrelevant for these unit test, just initialize them to 0.
        initialValidatorsIpAddresses = Array(initialValidators.length).fill(ZeroIpAddress);

        const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
        const stakingHbbftProxy = await upgrades.deployProxy(
            StakingHbbftFactory,
            [
                owner.address,
                stakingParams,
                initialValidatorsPubKeysSplit, // _publicKeys
                initialValidatorsIpAddresses // _internetAddresses
            ],
            { initializer: 'initialize' }
        );

        await stakingHbbftProxy.waitForDeployment();

        await validatorSetHbbftProxy.setRandomContract(await randomHbbftProxy.getAddress());
        await validatorSetHbbftProxy.setStakingContract(await stakingHbbftProxy.getAddress());
        await validatorSetHbbftProxy.setKeyGenHistoryContract(await keyGenHistoryProxy.getAddress());

        const validatorSetHbbft = ValidatorSetFactory.attach(
            await validatorSetHbbftProxy.getAddress()
        ) as ValidatorSetHbbftMock;

        const stakingHbbft = StakingHbbftFactory.attach(
            await stakingHbbftProxy.getAddress()
        ) as StakingHbbftMock;

        const blockRewardHbbft = BlockRewardHbbftFactory.attach(
            await blockRewardHbbftProxy.getAddress()
        ) as BlockRewardHbbftMock;

        const delegatorMinStake = await stakingHbbft.delegatorMinStake();
        const candidateMinStake = await stakingHbbft.candidateMinStake();

        const randomHbbft = RandomHbbftFactory.attach(await randomHbbftProxy.getAddress()) as RandomHbbft;
        const keyGenHistory = KeyGenFactory.attach(await keyGenHistoryProxy.getAddress()) as KeyGenHistory;

        return {
            validatorSetHbbft,
            stakingHbbft,
            blockRewardHbbft,
            randomHbbft,
            keyGenHistory,
            candidateMinStake,
            delegatorMinStake
        };
    }

    beforeEach(async () => {
        [owner, ...accounts] = await ethers.getSigners();

        const accountAddresses = accounts.map(item => item.address);

        initialValidators = accountAddresses.slice(1, 3 + 1); // accounts[1...3]
        initialStakingAddresses = accountAddresses.slice(4, 6 + 1); // accounts[4...6]

        expect(initialStakingAddresses).to.be.lengthOf(3);
        expect(initialStakingAddresses[0]).to.not.be.equal(ethers.ZeroAddress);
        expect(initialStakingAddresses[1]).to.not.be.equal(ethers.ZeroAddress);
        expect(initialStakingAddresses[2]).to.not.be.equal(ethers.ZeroAddress);
    });

    describe('addPool()', async () => {
        let candidateMiningAddress: HardhatEthersSigner;
        let candidateStakingAddress: HardhatEthersSigner;

        beforeEach(async () => {
            candidateMiningAddress = accounts[7];
            candidateStakingAddress = accounts[8];
        });

        it('should set the corresponding public keys', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            for (let i = 0; i < initialStakingAddresses.length; i++) {
                expect(await stakingHbbft.getPoolPublicKey(initialStakingAddresses[i]))
                    .to.be.equal(initialValidatorsPubKeys[i]);
            }
        });

        it('should set the corresponding IP addresses', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            for (let i = 0; i < initialStakingAddresses.length; i++) {
                let ip_result = (await stakingHbbft.getPoolInternetAddress(initialStakingAddresses[i]));
                expect(ip_result[0]).to.be.equal(initialValidatorsIpAddresses[i]);
            }
        });

        it('should create a new pool', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.isPoolActive(candidateStakingAddress.address)).to.be.false;

            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            );

            expect(await stakingHbbft.isPoolActive(candidateStakingAddress.address)).to.be.true;
        });

        it('should fail if created with overstaked pool', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.isPoolActive(candidateStakingAddress.address)).to.be.false;

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: maxStake + minStake }
            )).to.be.revertedWith('stake limit has been exceeded');
        });

        it('should fail if mining address is 0', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                ethers.ZeroAddress,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address can't be 0");
        });

        it('should fail if mining address is equal to staking', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateStakingAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address cannot be the same as the staking one");
        });

        it('should fail if the pool with the same mining/staking address is already existing', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const candidateMiningAddress2 = accounts[9];
            const candidateStakingAddress2 = accounts[10];

            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            );

            await expect(stakingHbbft.connect(candidateStakingAddress2).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address already used as a mining one");

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress2.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Staking address already used as a staking one");

            await expect(stakingHbbft.connect(candidateMiningAddress2).addPool(
                candidateStakingAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address already used as a staking one");

            await expect(stakingHbbft.connect(candidateMiningAddress).addPool(
                candidateStakingAddress2.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Staking address already used as a mining one");

            await expect(stakingHbbft.connect(candidateMiningAddress2).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address already used as a mining one");

            await expect(stakingHbbft.connect(candidateMiningAddress).addPool(
                candidateMiningAddress2.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Staking address already used as a mining one");

            await expect(stakingHbbft.connect(candidateStakingAddress2).addPool(
                candidateStakingAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Mining address already used as a staking one");

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateStakingAddress2.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("Staking address already used as a staking one");

            expect(await stakingHbbft.connect(candidateStakingAddress2).addPool(
                candidateMiningAddress2.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            ));
        });

        it('should fail if gasPrice is 0', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { gasPrice: 0, value: minStake }
            )).to.be.revertedWith("GasPrice is 0");
        });

        it('should fail if staking amount is 0', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: 0n }
            )).to.be.revertedWith("Stake: stakingAmount is 0");
        });

        it('should fail if stacking time is inside disallowed range', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake },
            )).to.be.revertedWith("Stake: disallowed period");

            await helpers.time.increase(2);

            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake },
            );
        });

        it('should fail if staking amount is less than CANDIDATE_MIN_STAKE', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake / 2n }
            )).to.be.revertedWith("Stake: candidateStake less than candidateMinStake");
        });

        it('stake amount should be increased', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const amount = minStake * 2n;
            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: amount }
            );

            expect(await stakingHbbft.stakeAmount(candidateStakingAddress.address, candidateStakingAddress.address)).to.equal(amount);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(candidateStakingAddress.address, candidateStakingAddress.address)).to.equal(amount);
            expect(await stakingHbbft.stakeAmountTotal(candidateStakingAddress.address)).to.equal(amount);
        });

        it('should be able to add more than one pool', async () => {
            const { stakingHbbft, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const candidate1MiningAddress = candidateMiningAddress;
            const candidate1StakingAddress = candidateStakingAddress;
            const candidate2MiningAddress = accounts[9];
            const candidate2StakingAddress = accounts[10];

            const amount1 = minStake * 2n;
            const amount2 = minStake * 3n;

            // Add two new pools
            expect(await stakingHbbft.isPoolActive(candidate1StakingAddress.address)).to.be.false;
            expect(await stakingHbbft.isPoolActive(candidate2StakingAddress.address)).to.be.false;

            await stakingHbbft.connect(candidate1StakingAddress).addPool(
                candidate1MiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: amount1 }
            );

            await stakingHbbft.connect(candidate2StakingAddress).addPool(
                candidate2MiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: amount2 }
            );

            expect(await stakingHbbft.isPoolActive(candidate1StakingAddress.address)).to.be.true;
            expect(await stakingHbbft.isPoolActive(candidate2StakingAddress.address)).to.be.true;

            // Check indexes in the `poolsToBeElected` list
            expect(await stakingHbbft.poolToBeElectedIndex(candidate1StakingAddress.address)).to.equal(0n);
            expect(await stakingHbbft.poolToBeElectedIndex(candidate2StakingAddress.address)).to.equal(1n);

            // Check pools' existence
            const validators = await validatorSetHbbft.getValidators();

            expect(await stakingHbbft.getPools()).to.be.deep.equal([
                await validatorSetHbbft.stakingByMiningAddress(validators[0]),
                await validatorSetHbbft.stakingByMiningAddress(validators[1]),
                await validatorSetHbbft.stakingByMiningAddress(validators[2]),
                candidate1StakingAddress.address,
                candidate2StakingAddress.address
            ]);
        });

        it("shouldn't allow adding more than MAX_CANDIDATES pools", async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const maxCandidates = await stakingHbbft.getMaxCandidates();

            for (let i = initialValidators.length; i < maxCandidates; ++i) {
                // Add a new pool
                await stakingHbbft.addPoolActiveMock(ethers.Wallet.createRandom().address);
            }

            // Try to add a new pool outside of max limit, max limit is 100 in mock contract.
            await expect(stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            )).to.be.revertedWith("MAX_CANDIDATES pools exceeded");

            expect(await stakingHbbft.isPoolActive(candidateStakingAddress.address)).to.be.false;
        });

        it('should remove added pool from the list of inactive pools', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.addPoolInactiveMock(candidateStakingAddress.address);
            expect(await stakingHbbft.getPoolsInactive()).to.be.deep.equal([candidateStakingAddress.address]);

            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            );

            expect(await stakingHbbft.isPoolActive(candidateStakingAddress.address)).to.be.true;
            expect(await stakingHbbft.getPoolsInactive()).to.be.empty;
        });
    });

    describe('contract balance', async () => {
        before(async () => {
            candidateMiningAddress = accounts[7];
            candidateStakingAddress = accounts[8];
        });

        it('cannot be increased by sending native coins', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(owner.sendTransaction({ to: await stakingHbbft.getAddress(), value: 1n }))
                .to.be.revertedWith("Not payable");

            await owner.sendTransaction({ to: accounts[1].address, value: 1n });
            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.be.equal(0n);
        });

        it('can be increased by sending coins to payable functions', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.be.equal(0n);
            await stakingHbbft.connect(candidateStakingAddress).addPool(
                candidateMiningAddress.address,
                ZeroPublicKey,
                ZeroIpAddress,
                { value: minStake }
            );

            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.to.be.equal(minStake);

            await stakingHbbft.connect(candidateStakingAddress).stake(
                candidateStakingAddress.address,
                { value: minStake }
            );

            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.be.equal(minStake * 2n);
        });
    });

    describe('incrementStakingEpoch()', async () => {
        let stakingContract: StakingHbbftMock;
        let validatorSetContract: HardhatEthersSigner;

        beforeEach(async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            stakingContract = stakingHbbft;
            validatorSetContract = accounts[7];

            await stakingHbbft.setValidatorMockSetAddress(await validatorSetContract.getAddress());
        });

        it('should increment if called by the ValidatorSet', async () => {
            expect(await stakingContract.stakingEpoch()).to.be.equal(0n);
            await stakingContract.connect(validatorSetContract).incrementStakingEpoch();

            expect(await stakingContract.stakingEpoch()).to.be.equal(1n);
        });

        it('can only be called by ValidatorSet contract', async () => {
            await expect(stakingContract.connect(accounts[8]).incrementStakingEpoch())
                .to.be.revertedWith("Only ValidatorSet");
        });
    });


    describe('initialize()', async () => {
        const validatorSetContract = '0x1000000000000000000000000000000000000001';

        beforeEach(async () => {
            // The following private keys belong to the accounts 1-3, fixed by using the "--mnemonic" option when starting ganache.
            // const initialValidatorsPrivKeys = ["0x272b8400a202c08e23641b53368d603e5fec5c13ea2f438bce291f7be63a02a7", "0xa8ea110ffc8fe68a069c8a460ad6b9698b09e21ad5503285f633b3ad79076cf7", "0x5da461ff1378256f69cb9a9d0a8b370c97c460acbe88f5d897cb17209f891ffc"];
            // Public keys corresponding to the three private keys above.
            initialValidatorsPubKeys = [
                '0x52be8f332b0404dff35dd0b2ba44993a9d3dc8e770b9ce19a849dff948f1e14c57e7c8219d522c1a4cce775adbee5330f222520f0afdabfdb4a4501ceeb8dcee',
                '0x99edf3f524a6f73e7f5d561d0030fc6bcc3e4bd33971715617de7791e12d9bdf6258fa65b74e7161bbbf7ab36161260f56f68336a6f65599dc37e7f2e397f845',
                '0xa255fd7ad199f0ee814ee00cce44ef2b1fa1b52eead5d8013ed85eade03034ae4c246658946c2e1d7ded96394a1247fb4d093c32474317ae388e8d25692a0f56'
            ];

            initialValidatorsPubKeysSplit = fp.flatMap((x: string) => [x.substring(0, 66), '0x' + x.substring(66, 130)])
                (initialValidatorsPubKeys);

            // The IP addresses are irrelevant for these unit test, just initialize them to 0.
            initialValidatorsIpAddresses = [
                ZeroIpAddress,
                ZeroIpAddress,
                ZeroIpAddress
            ];
        });

        it('should initialize successfully', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            const stakingHbbft = await upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            );

            await stakingHbbft.waitForDeployment();

            expect(await stakingHbbft.stakingFixedEpochDuration()).to.be.equal(stakingFixedEpochDuration);
            expect(await stakingHbbft.stakingWithdrawDisallowPeriod()).to.be.equal(stakingWithdrawDisallowPeriod);
            expect(await stakingHbbft.validatorSetContract()).to.be.equal(validatorSetContract)

            for (const stakingAddress of initialStakingAddresses) {
                expect(await stakingHbbft.isPoolActive(stakingAddress)).to.be.true;
                expect(await stakingHbbft.getPools()).to.include(stakingAddress);
                expect(await stakingHbbft.getPoolsToBeRemoved()).to.include(stakingAddress);
            }

            expect(await stakingHbbft.getPools()).to.be.deep.equal(initialStakingAddresses);
            expect(await stakingHbbft.delegatorMinStake()).to.be.equal(ethers.parseEther('1'));
            expect(await stakingHbbft.candidateMinStake()).to.be.equal(ethers.parseEther('1'))
        });

        it('should fail if owner = address(0)', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    ethers.ZeroAddress,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("Owner address cannot be 0");
        });

        it('should fail if ValidatorSet contract address is zero', async () => {
            let stakingParams = {
                _validatorSetContract: ethers.ZeroAddress,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("ValidatorSet can't be 0");
        });

        it('should fail if delegatorMinStake is zero', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: 0,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("DelegatorMinStake is 0");
        });

        it('should fail if candidateMinStake is zero', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: 0,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("CandidateMinStake is 0");
        });

        it('should fail if already initialized', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            const stakingHbbft = await upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            );

            await stakingHbbft.waitForDeployment();

            await expect(stakingHbbft.initialize(
                owner.address,
                stakingParams,
                initialValidatorsPubKeysSplit, // _publicKeys
                initialValidatorsIpAddresses // _internetAddresses
            )).to.be.revertedWith("Initializable: contract is already initialized");
        });

        it('should fail if stakingEpochDuration is 0', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: 0,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("FixedEpochDuration is 0");
        });

        it('should fail if stakingstakingEpochStartBlockWithdrawDisallowPeriod is 0', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: 0n
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("WithdrawDisallowPeriod is 0");
        });

        it('should fail if stakingWithdrawDisallowPeriod >= stakingEpochDuration', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: 120954n
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("FixedEpochDuration must be longer than withdrawDisallowPeriod");
        });

        it('should fail if some staking address is 0', async () => {
            initialStakingAddresses[0] = ethers.ZeroAddress;

            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingTransitionTimeframeLength,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("InitialStakingAddresses can't be 0");
        });

        it('should fail if timewindow is 0', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: 0,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("The transition timeframe must be longer than 0");
        });

        it('should fail if transition timewindow is smaller than the staking time window', async () => {
            let stakingParams = {
                _validatorSetContract: validatorSetContract,
                _initialStakingAddresses: initialStakingAddresses,
                _delegatorMinStake: minStake,
                _candidateMinStake: minStake,
                _maxStake: maxStake,
                _stakingFixedEpochDuration: stakingFixedEpochDuration,
                _stakingTransitionTimeframeLength: stakingFixedEpochDuration,
                _stakingWithdrawDisallowPeriod: stakingWithdrawDisallowPeriod
            };

            const StakingHbbftFactory = await ethers.getContractFactory("StakingHbbftMock");
            await expect(upgrades.deployProxy(
                StakingHbbftFactory,
                [
                    owner.address,
                    stakingParams,
                    initialValidatorsPubKeysSplit, // _publicKeys
                    initialValidatorsIpAddresses // _internetAddresses
                ],
                { initializer: 'initialize' }
            )).to.be.revertedWith("The transition timeframe must be shorter then the epoch duration");
        });
    });

    describe('moveStake()', async () => {
        let delegatorAddress: HardhatEthersSigner;
        let stakingContract: StakingHbbftMock;
        const stakeAmount = minStake * 2n;

        beforeEach(async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            delegatorAddress = accounts[7];
            stakingContract = stakingHbbft;

            // Place stakes
            await stakingContract.connect(await ethers.getSigner(initialStakingAddresses[0])).stake(initialStakingAddresses[0], { value: stakeAmount });
            await stakingContract.connect(await ethers.getSigner(initialStakingAddresses[1])).stake(initialStakingAddresses[1], { value: stakeAmount });
            await stakingContract.connect(delegatorAddress).stake(initialStakingAddresses[0], { value: stakeAmount });
        });

        it('should move entire stake', async () => {
            // we can move the stake, since the staking address is not part of the active validator set,
            // since we never did never a time travel.
            // If we do, the stakingAddresses are blocked to withdraw without an orderwithdraw.
            expect(await stakingContract.stakeAmount(initialStakingAddresses[0], delegatorAddress.address)).to.be.equal(stakeAmount);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);

            await stakingContract.connect(delegatorAddress).moveStake(initialStakingAddresses[0], initialStakingAddresses[1], stakeAmount);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[0], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(stakeAmount);
        });

        it('should move part of the stake', async () => {
            expect(await stakingContract.stakeAmount(initialStakingAddresses[0], delegatorAddress.address)).to.be.equal(stakeAmount);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);

            await stakingContract.connect(delegatorAddress).moveStake(initialStakingAddresses[0], initialStakingAddresses[1], minStake);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[0], delegatorAddress.address)).to.be.equal(minStake);
            expect(await stakingContract.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(minStake);
        });

        it('should move part of the stake', async () => {
            await stakingContract.connect(delegatorAddress).stake(initialStakingAddresses[1], { value: stakeAmount });

            const sourcePool = initialStakingAddresses[0];
            const targetPool = initialStakingAddresses[1];

            expect(await stakingContract.stakeAmount(sourcePool, delegatorAddress.address)).to.be.equal(stakeAmount);
            expect(await stakingContract.stakeAmount(targetPool, delegatorAddress.address)).to.be.equal(stakeAmount);

            const moveAmount = minStake / 2n;
            expect(moveAmount).to.be.below(await stakingContract.delegatorMinStake());

            await stakingContract.connect(delegatorAddress).moveStake(sourcePool, targetPool, moveAmount);
            expect(await stakingContract.stakeAmount(sourcePool, delegatorAddress.address)).to.be.equal(stakeAmount - moveAmount);
            expect(await stakingContract.stakeAmount(targetPool, delegatorAddress.address)).to.be.equal(stakeAmount + moveAmount);
        });

        it('should fail for zero gas price', async () => {
            await expect(stakingContract.connect(delegatorAddress).moveStake(
                initialStakingAddresses[0],
                initialStakingAddresses[1],
                stakeAmount,
                { gasPrice: 0 }
            )).to.be.revertedWith("GasPrice is 0");
        });

        it('should fail if the source and destination addresses are the same', async () => {
            await expect(stakingContract.connect(delegatorAddress).moveStake(
                initialStakingAddresses[0],
                initialStakingAddresses[0],
                stakeAmount
            )).to.be.revertedWith("MoveStake: src and dst pool is the same");
        });

        it('should fail if the staker tries to move more than they have', async () => {
            await expect(stakingContract.connect(delegatorAddress).moveStake(
                initialStakingAddresses[0],
                initialStakingAddresses[1],
                stakeAmount * 2n
            )).to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");
        });

        it('should fail if the staker tries to overstake by moving stake.', async () => {
            // stake source pool and target pool to the max.
            // then move 1 from source to target - that should be the drop on the hot stone.
            const sourcePool = initialStakingAddresses[0];
            const targetPool = initialStakingAddresses[1];

            let currentSourceStake = await stakingContract.stakeAmountTotal(sourcePool);
            const totalStakeableSource = maxStake - currentSourceStake;
            await stakingContract.connect(delegatorAddress).stake(sourcePool, { value: totalStakeableSource });

            let currentTargetStake = await stakingContract.stakeAmountTotal(targetPool);
            const totalStakeableTarget = maxStake - currentTargetStake;
            await stakingContract.connect(delegatorAddress).stake(targetPool, { value: totalStakeableTarget });
            // source is at max stake now, now tip it over.
            await expect(stakingContract.connect(delegatorAddress).moveStake(
                sourcePool,
                targetPool,
                1n
            )).to.be.revertedWith("stake limit has been exceeded");
        });
    });

    describe('stake()', async () => {
        let delegatorAddress: HardhatEthersSigner;

        beforeEach(async () => {
            delegatorAddress = accounts[7];
        });

        it('should be zero initially', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], initialStakingAddresses[1])).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
        });

        it('should place a stake', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });

            expect(await stakingHbbft.stakeAmount(pool.address, pool.address)).to.be.equal(candidateMinStake);

            await expect(stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake }))
                .to.emit(stakingHbbft, "PlacedStake")
                .withArgs(
                    pool.address,
                    delegatorAddress.address,
                    0n,
                    delegatorMinStake
                );

            expect(await stakingHbbft.stakeAmount(pool.address, delegatorAddress.address)).to.be.equal(delegatorMinStake);
            expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.equal(candidateMinStake + delegatorMinStake);
        });

        it('should fail for zero gas price', async () => {
            const { stakingHbbft, candidateMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await expect(stakingHbbft.connect(pool).stake(
                pool.address,
                { value: candidateMinStake, gasPrice: 0 }
            )).to.be.revertedWith("GasPrice is 0");
        });

        it('should fail for a zero staking pool address', async () => {
            const { stakingHbbft, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(delegatorAddress).stake(ethers.ZeroAddress, { value: delegatorMinStake }))
                .to.be.revertedWith("Stake: stakingAddress is 0");
        });

        it('should fail for a non-existing pool', async () => {
            const { stakingHbbft, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(delegatorAddress).stake(accounts[10].address, { value: delegatorMinStake }))
                .to.be.revertedWith("Pool does not exist. miningAddress for that staking address is 0");
        });

        it('should fail for a zero amount', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.connect(delegatorAddress).stake(initialStakingAddresses[1], { value: 0 }))
                .to.be.revertedWith("Stake: stakingAmount is 0");
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
            await validatorSetHbbft.setSystemAddress(owner.address);
            await validatorSetHbbft.connect(owner).removeMaliciousValidators([initialValidators[1]]);

            await expect(stakingHbbft.connect(delegatorAddress).stake(
                pool.address,
                { value: delegatorMinStake }
            )).to.be.revertedWith("Stake: Mining address is banned");
        });

        it('should only success in the allowed staking window', async () => {
            const { stakingHbbft, candidateMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await expect(stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake }))
                .to.be.revertedWith("Stake: disallowed period");
        });

        it('should fail if a candidate stakes less than CANDIDATE_MIN_STAKE', async () => {
            const { stakingHbbft, candidateMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            const halfOfCandidateMinStake = candidateMinStake / 2n;
            await expect(stakingHbbft.connect(pool).stake(
                pool.address,
                { value: halfOfCandidateMinStake }
            )).to.be.revertedWith("Stake: candidateStake less than candidateMinStake");
        });

        it('should fail if a delegator stakes less than DELEGATOR_MIN_STAKE', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            const halfOfDelegatorMinStake = delegatorMinStake / 2n;

            await expect(stakingHbbft.connect(delegatorAddress).stake(
                pool.address,
                { value: halfOfDelegatorMinStake }
            )).to.be.revertedWith("Stake: delegatorStake is less than delegatorMinStake");
        });

        it('should fail if a delegator stakes more than maxStake', async () => {
            const { stakingHbbft, candidateMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            await expect(stakingHbbft.connect(delegatorAddress).stake(
                pool.address,
                { value: maxStake + 1n }
            )).to.be.revertedWith("stake limit has been exceeded");
        });

        it('should fail if a delegator stakes into an empty pool', async () => {
            const { stakingHbbft, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            expect(await stakingHbbft.stakeAmount(pool.address, pool.address)).to.be.equal(0n);
            await expect(stakingHbbft.connect(delegatorAddress).stake(
                pool.address,
                { value: delegatorMinStake }
            )).to.be.revertedWith("Stake: can't delegate in empty pool");
        });

        it('should increase a stake amount', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, delegatorAddress.address)).to.be.equal(0n);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, delegatorAddress.address)).to.be.equal(delegatorMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, delegatorAddress.address)).to.be.equal(delegatorMinStake * 2n);
        });

        it('should increase the stakeAmountByCurrentEpoch', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(pool.address, delegatorAddress.address)).to.be.equal(0n);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(pool.address, delegatorAddress.address)).to.be.equal(delegatorMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(pool.address, delegatorAddress.address)).to.be.equal(delegatorMinStake * 2n);
        });

        it('should increase a total stake amount', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.equal(candidateMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.equal(candidateMinStake + delegatorMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.equal(candidateMinStake + delegatorMinStake * 2n);
        });

        it('should add a delegator to the pool', async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.poolDelegators(pool.address)).to.be.empty;

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });

            expect(await stakingHbbft.poolDelegators(pool.address)).to.be.deep.equal([delegatorAddress.address]);
        });

        it("should update pool's likelihood", async () => {
            const { stakingHbbft, candidateMinStake, delegatorMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            let likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods).to.be.empty;
            expect(likelihoodInfo.sum).to.be.equal(0n);

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods[0]).to.be.equal(candidateMinStake);
            expect(likelihoodInfo.sum).to.be.equal(candidateMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods[0]).to.be.equal(candidateMinStake + delegatorMinStake);
            expect(likelihoodInfo.sum).to.be.equal(candidateMinStake + delegatorMinStake);

            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: delegatorMinStake });
            likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods[0]).to.be.equal(candidateMinStake + delegatorMinStake * 2n);
            expect(likelihoodInfo.sum).to.be.equal(candidateMinStake + delegatorMinStake * 2n);
        });

        it('should decrease the balance of the staker and increase the balance of the Staking contract', async () => {
            const { stakingHbbft, candidateMinStake } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.be.equal(0n);

            const initialBalance = await ethers.provider.getBalance(pool.address);
            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });

            expect(await ethers.provider.getBalance(pool.address)).to.be.below(initialBalance - candidateMinStake);
            expect(await ethers.provider.getBalance(await stakingHbbft.getAddress())).to.be.equal(candidateMinStake);
        });

        it('should not create stake snapshot on epoch 0', async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake,
            } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);
            const mining = initialValidators[1];
            const delegator = accounts[11];

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, pool.address)).to.be.equal(candidateMinStake);

            let stakingEpoch = await stakingHbbft.stakingEpoch();
            expect(stakingEpoch).to.equal(0n);

            await stakingHbbft.connect(delegator).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, delegator.address)).to.be.equal(delegatorMinStake);
            expect(await stakingHbbft.getDelegatorStakeSnapshot(pool.address, delegator.address, stakingEpoch))
                .to.be.equal(0n);
            expect(await stakingHbbft.getStakeSnapshotLastEpoch(pool.address, delegator.address))
                .to.be.equal(0n);

            expect(await validatorSetHbbft.isValidatorOrPending(mining)).to.be.true;

            await stakingHbbft.connect(delegator).stake(pool.address, { value: delegatorMinStake * 2n });
            expect(await stakingHbbft.stakeAmount(pool.address, delegator.address)).to.be.equal(delegatorMinStake * 3n);
            expect(await stakingHbbft.getDelegatorStakeSnapshot(pool.address, delegator.address, stakingEpoch))
                .to.be.equal(0n);
            expect(await stakingHbbft.getStakeSnapshotLastEpoch(pool.address, delegator.address))
                .to.be.equal(0n);
        });

        it('should create stake snapshot if staking on an active validator', async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                blockRewardHbbft,
                candidateMinStake,
                delegatorMinStake,
            } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);
            const mining = initialValidators[1];
            const delegator = accounts[11];

            await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, pool.address)).to.be.equal(candidateMinStake);

            let stakingEpoch = await stakingHbbft.stakingEpoch();
            await stakingHbbft.connect(delegator).stake(pool.address, { value: delegatorMinStake });
            expect(await stakingHbbft.stakeAmount(pool.address, delegator.address)).to.be.equal(delegatorMinStake);
            expect(await stakingHbbft.getDelegatorStakeSnapshot(pool.address, delegator.address, stakingEpoch))
                .to.be.equal(0n);
            expect(await stakingHbbft.getStakeSnapshotLastEpoch(pool.address, delegator.address))
                .to.be.equal(0n);

            await callReward(blockRewardHbbft, true);

            expect(await validatorSetHbbft.isValidatorOrPending(mining)).to.be.true;
            expect(await stakingHbbft.stakingEpoch()).to.be.gt(0n);

            stakingEpoch = await stakingHbbft.stakingEpoch();
            await stakingHbbft.connect(delegator).stake(pool.address, { value: delegatorMinStake * 2n });
            expect(await stakingHbbft.stakeAmount(pool.address, delegator.address)).to.be.equal(delegatorMinStake * 3n);
            expect(await stakingHbbft.getDelegatorStakeSnapshot(pool.address, delegator.address, stakingEpoch))
                .to.be.equal(delegatorMinStake);
            expect(await stakingHbbft.getStakeSnapshotLastEpoch(pool.address, delegator.address))
                .to.be.equal(stakingEpoch);
        });
    });

    describe('removePool()', async () => {
        it('should remove a pool', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.getPools()).to.be.deep.equal(initialStakingAddresses);

            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await stakingHbbft.connect(accounts[7]).removePool(initialStakingAddresses[0]);

            expect(await stakingHbbft.getPools()).to.be.deep.equal([
                initialStakingAddresses[2],
                initialStakingAddresses[1]
            ]);

            expect(await stakingHbbft.getPoolsInactive()).to.be.empty;
        });

        it('can only be called by the ValidatorSetHbbft contract', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await expect(stakingHbbft.connect(accounts[8]).removePool(initialStakingAddresses[0]))
                .to.be.revertedWith("Only ValidatorSet");
        });

        it("shouldn't fail when removing a nonexistent pool", async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.getPools()).to.be.deep.equal(initialStakingAddresses);

            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await stakingHbbft.connect(accounts[7]).removePool(accounts[10].address);

            expect(await stakingHbbft.getPools()).to.be.deep.equal(initialStakingAddresses);
        });

        it('should add/remove a pool to/from the utility lists', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            // The first validator places stake for themselves
            expect(await stakingHbbft.getPoolsToBeElected()).to.be.lengthOf(0);
            expect(await stakingHbbft.getPoolsToBeRemoved()).to.be.deep.equal(initialStakingAddresses);

            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[0])).stake(
                initialStakingAddresses[0],
                { value: minStake }
            );

            expect(await stakingHbbft.stakeAmountTotal(initialStakingAddresses[0])).to.be.equal(minStake);
            expect(await stakingHbbft.getPoolsToBeElected()).to.be.deep.equal([initialStakingAddresses[0]]);
            expect(await stakingHbbft.getPoolsToBeRemoved()).to.be.deep.equal([
                initialStakingAddresses[2],
                initialStakingAddresses[1]
            ]);

            // Remove the pool
            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await stakingHbbft.connect(accounts[7]).removePool(initialStakingAddresses[0]);
            expect(await stakingHbbft.getPoolsInactive()).to.be.deep.equal([initialStakingAddresses[0]]);

            await stakingHbbft.connect(accounts[7]).removePool(initialStakingAddresses[0]);
            expect(await stakingHbbft.getPoolsInactive()).to.be.deep.equal([initialStakingAddresses[0]]);

            await stakingHbbft.connect(accounts[7]).removePool(initialStakingAddresses[1]);
            expect(await stakingHbbft.getPoolsToBeRemoved()).to.be.deep.equal([initialStakingAddresses[2]]);
        });
    });

    describe('removeMyPool()', async () => {
        it('should fail for zero gas price', async () => {
            const { stakingHbbft, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await stakingHbbft.connect(accounts[7]).incrementStakingEpoch();
            await stakingHbbft.setValidatorMockSetAddress(await validatorSetHbbft.getAddress());
            await expect(stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[0])).removeMyPool({ gasPrice: 0n }))
                .to.be.rejectedWith("GasPrice is 0");
        });

        it('should fail for initial validator during the initial staking epoch', async () => {
            const { stakingHbbft, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.stakingEpoch()).to.be.equal(0n);
            expect(await validatorSetHbbft.isValidator(initialValidators[0])).to.be.true;
            expect(await validatorSetHbbft.miningByStakingAddress(initialStakingAddresses[0])).to.be.equal(initialValidators[0]);

            await expect(stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[0])).removeMyPool({}))
                .to.be.revertedWith("Can't remove pool during 1st staking epoch");

            await stakingHbbft.setValidatorMockSetAddress(accounts[7].address);
            await stakingHbbft.connect(accounts[7]).incrementStakingEpoch();
            await stakingHbbft.setValidatorMockSetAddress(await validatorSetHbbft.getAddress());

            await expect(stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[0])).removeMyPool({})).to.be.fulfilled
        });
    });

    describe('withdraw()', async () => {
        const stakeAmount = minStake * 2n;
        let delegatorAddress: HardhatEthersSigner;

        beforeEach(async () => {
            delegatorAddress = accounts[7];
        });

        it('should withdraw a stake', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], initialStakingAddresses[1])).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], initialStakingAddresses[1])).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);

            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[1])).stake(initialStakingAddresses[1], { value: stakeAmount });
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], initialStakingAddresses[1])).to.be.equal(stakeAmount);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], initialStakingAddresses[1])).to.be.equal(stakeAmount);

            await stakingHbbft.connect(delegatorAddress).stake(initialStakingAddresses[1], { value: stakeAmount });
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(stakeAmount);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(stakeAmount);
            expect(await stakingHbbft.stakeAmountTotal(initialStakingAddresses[1])).to.be.equal(stakeAmount * 2n);

            await expect(stakingHbbft.connect(delegatorAddress).withdraw(initialStakingAddresses[1], stakeAmount))
                .to.emit(stakingHbbft, "WithdrewStake")
                .withArgs(
                    initialStakingAddresses[1],
                    delegatorAddress.address,
                    0n,
                    stakeAmount
                );

            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmountTotal(initialStakingAddresses[1])).to.be.equal(stakeAmount);
        });

        it('should fail for zero gas price', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const staker = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(staker).stake(staker.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(staker).withdraw(
                staker.address,
                stakeAmount,
                { gasPrice: 0 }
            )).to.be.revertedWith("GasPrice is 0");
        });

        it('should fail for a zero pool address', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const staker = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(staker).stake(staker.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(staker).withdraw(ethers.ZeroAddress, stakeAmount))
                .to.be.revertedWith("Withdraw pool staking address must not be null");

            await stakingHbbft.connect(staker).withdraw(staker.address, stakeAmount);
        });

        it('should fail for a zero amount', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const staker = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(staker).stake(staker.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(staker).withdraw(staker.address, 0n))
                .to.be.revertedWith("amount to withdraw must not be 0");

            await stakingHbbft.connect(staker).withdraw(staker.address, stakeAmount);
        });

        it("shouldn't allow withdrawing from a banned pool", async () => {
            const { stakingHbbft, validatorSetHbbft } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: stakeAmount });
            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: stakeAmount });

            await validatorSetHbbft.setBannedUntil(initialValidators[1], '0xffffffffffffffff');
            await expect(stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount))
                .to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");
            await expect(stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount))
                .to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");

            await validatorSetHbbft.setBannedUntil(initialValidators[1], 0n);
            await stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount);
            await stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount);
        });

        it("shouldn't allow withdrawing during the stakingWithdrawDisallowPeriod", async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.stake(initialStakingAddresses[1], { from: initialStakingAddresses[1], value: stakeAmount });

            //await stakingHbbft.setCurrentBlockNumber(117000);
            //await validatorSetHbbft.setCurrentBlockNumber(117000);
            await expect(stakingHbbft.withdraw(
                initialStakingAddresses[1],
                stakeAmount,
                { from: initialStakingAddresses[1] }
            )).to.be.revertedWith("Stake: disallowed period");

            //await stakingHbbft.setCurrentBlockNumber(116000);
            //await validatorSetHbbft.setCurrentBlockNumber(116000);

            await stakingHbbft.withdraw(initialStakingAddresses[1], stakeAmount, { from: initialStakingAddresses[1] });
        });

        it('should fail if non-zero residue is less than CANDIDATE_MIN_STAKE', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const candidateMinStake = await stakingHbbft.candidateMinStake();
            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount - candidateMinStake + 1n))
                .to.be.revertedWith("newStake amount must be greater equal than the min stake.");

            await stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount - candidateMinStake);
            await stakingHbbft.connect(pool).withdraw(pool.address, candidateMinStake);
        });

        it('should fail if non-zero residue is less than DELEGATOR_MIN_STAKE', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const delegatorMinStake = await stakingHbbft.delegatorMinStake();
            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: stakeAmount });
            await stakingHbbft.connect(delegatorAddress).stake(pool.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount - delegatorMinStake + 1n))
                .to.be.revertedWith("newStake amount must be greater equal than the min stake.");
            await stakingHbbft.connect(delegatorAddress).withdraw(pool.address, stakeAmount - delegatorMinStake);
            await stakingHbbft.connect(delegatorAddress).withdraw(pool.address, delegatorMinStake);
        });

        it('should fail if withdraw more than staked', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const pool = await ethers.getSigner(initialStakingAddresses[1]);

            await stakingHbbft.connect(pool).stake(pool.address, { value: stakeAmount });
            await expect(stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount + 1n))
                .to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");
            await stakingHbbft.connect(pool).withdraw(pool.address, stakeAmount);
        });

        it('should fail if withdraw already ordered amount', async () => {
            const { stakingHbbft, validatorSetHbbft, blockRewardHbbft } = await helpers.loadFixture(deployContractsFixture);

            await validatorSetHbbft.setSystemAddress(owner.address);

            // Place a stake during the initial staking epoch
            expect(await stakingHbbft.stakingEpoch()).to.be.equal(0n);
            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[0])).stake(initialStakingAddresses[0], { value: stakeAmount });
            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[1])).stake(initialStakingAddresses[1], { value: stakeAmount });
            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[2])).stake(initialStakingAddresses[2], { value: stakeAmount });
            await stakingHbbft.connect(delegatorAddress).stake(initialStakingAddresses[1], { value: stakeAmount });

            // Finalize a new validator set and change staking epoch
            await validatorSetHbbft.setStakingContract(await stakingHbbft.getAddress());

            // Set BlockRewardContract
            await validatorSetHbbft.setBlockRewardContract(accounts[7].address);
            await validatorSetHbbft.connect(accounts[7]).newValidatorSet();
            await validatorSetHbbft.setBlockRewardContract(await blockRewardHbbft.getAddress());
            // (increases staking epoch)
            await timeTravelToTransition(blockRewardHbbft, stakingHbbft);
            await timeTravelToEndEpoch(blockRewardHbbft, stakingHbbft);

            expect(await stakingHbbft.stakingEpoch()).to.be.equal(1n);
            // Order withdrawal
            const orderedAmount = stakeAmount / 4n;
            await stakingHbbft.connect(delegatorAddress).orderWithdraw(initialStakingAddresses[1], orderedAmount);

            // The second validator removes their pool
            expect(await validatorSetHbbft.isValidator(initialValidators[1])).to.be.true;
            expect(await stakingHbbft.getPoolsInactive()).to.be.empty;

            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[1])).removeMyPool();
            expect(await stakingHbbft.getPoolsInactive()).to.be.deep.equal([initialStakingAddresses[1]]);

            // Finalize a new validator set, change staking epoch and enqueue pending validators
            await validatorSetHbbft.setBlockRewardContract(accounts[7].address);
            await validatorSetHbbft.connect(accounts[7]).newValidatorSet();
            await validatorSetHbbft.setBlockRewardContract(await blockRewardHbbft.getAddress());

            await timeTravelToTransition(blockRewardHbbft, stakingHbbft);
            await timeTravelToEndEpoch(blockRewardHbbft, stakingHbbft);

            expect(await stakingHbbft.stakingEpoch()).to.be.equal(2n);
            expect(await validatorSetHbbft.isValidator(initialValidators[1])).to.be.false;

            // Check withdrawal for a delegator
            const restOfAmount = stakeAmount * 3n / 4n;

            expect(await stakingHbbft.poolDelegators(initialStakingAddresses[1])).to.be.deep.equal([delegatorAddress.address]);
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(restOfAmount);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);

            await expect(stakingHbbft.connect(delegatorAddress).withdraw(initialStakingAddresses[1], stakeAmount))
                .to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");
            await expect(stakingHbbft.connect(delegatorAddress).withdraw(initialStakingAddresses[1], restOfAmount + 1n))
                .to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded");

            await stakingHbbft.connect(delegatorAddress).withdraw(initialStakingAddresses[1], restOfAmount);
            expect(await stakingHbbft.stakeAmountByCurrentEpoch(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingHbbft.stakeAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(0n);
            expect(await stakingHbbft.orderedWithdrawAmount(initialStakingAddresses[1], delegatorAddress.address)).to.be.equal(orderedAmount);
            expect(await stakingHbbft.poolDelegators(initialStakingAddresses[1])).to.be.empty;
            expect(await stakingHbbft.poolDelegatorsInactive(initialStakingAddresses[1])).to.be.deep.equal([delegatorAddress.address]);
        });

        it('should decrease likelihood', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            let likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.sum).to.be.equal(0n);

            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[1])).stake(initialStakingAddresses[1], { value: stakeAmount });

            likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods[0]).to.be.equal(stakeAmount);
            expect(likelihoodInfo.sum).to.be.equal(stakeAmount);

            await stakingHbbft.connect(await ethers.getSigner(initialStakingAddresses[1])).withdraw(initialStakingAddresses[1], stakeAmount / 2n);

            likelihoodInfo = await stakingHbbft.getPoolsLikelihood();
            expect(likelihoodInfo.likelihoods[0]).to.be.equal(stakeAmount / 2n);
            expect(likelihoodInfo.sum).to.be.equal(stakeAmount / 2n);
        });
    });

    describe('recoverAbandonedStakes()', async () => {
        let stakingPool: HardhatEthersSigner;
        let stakers: HardhatEthersSigner[];

        beforeEach(async () => {
            stakingPool = await ethers.getSigner(initialStakingAddresses[0]);

            stakers = accounts.slice(7, 15);
        });

        async function stake(
            stakingContract: StakingHbbftMock,
            poolAddress: string,
            amount: bigint,
            stakers: HardhatEthersSigner[]
        ) {
            for (let staker of stakers) {
                expect(await stakingContract.connect(staker).stake(poolAddress, { value: amount }));
            }
        }

        async function setValidatorInactive(
            stakingContract: StakingHbbftMock,
            validatorSetContract: ValidatorSetHbbftMock,
            poolAddress: string
        ) {
            const validator = await validatorSetContract.miningByStakingAddress(poolAddress);

            expect(await validatorSetContract.setValidatorAvailableSince(validator, 0));
            expect(await stakingContract.addPoolInactiveMock(poolAddress));

            const poolsInactive = await stakingContract.getPoolsInactive();

            expect(poolsInactive).to.include(poolAddress);
        }

        it("should revert with invalid gas price", async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.recoverAbandonedStakes({ gasPrice: 0n }))
                .to.be.revertedWith("GasPrice is 0");
        });

        it("should revert if there is no inactive pools", async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.recoverAbandonedStakes())
                .to.be.revertedWith("nothing to recover");
        });

        it("should revert if validator inactive, but not abandonded", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            const expectedTotalStakes = candidateMinStake + delegatorMinStake * BigInt(stakers.length);

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);

            expect(await stakingHbbft.stakeAmountTotal(stakingPool.address)).to.be.equal(expectedTotalStakes);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.false;

            await expect(stakingHbbft.recoverAbandonedStakes()).to.be.revertedWith("nothing to recover");
        });

        it("should recover abandoned stakes", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                blockRewardHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            await blockRewardHbbft.setGovernanceAddress(owner.address);

            const governanceAddress = await blockRewardHbbft.governancePotAddress();
            const reinsertAddress = await blockRewardHbbft.getAddress();

            expect(governanceAddress).to.equal(owner.address);

            const expectedTotalStakes = candidateMinStake + delegatorMinStake * BigInt(stakers.length);
            const caller = accounts[5];

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);
            expect(await stakingHbbft.stakeAmountTotal(stakingPool.address)).to.be.equal(expectedTotalStakes);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);
            await helpers.time.increase(validatorInactivityThreshold + 3600n);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.true;

            const expectedGovernanceShare = expectedTotalStakes / 2n;
            const expectedReinsertShare = expectedTotalStakes - expectedGovernanceShare;

            const tx = stakingHbbft.connect(caller).recoverAbandonedStakes();

            await expect(tx)
                .to.emit(stakingHbbft, "GatherAbandonedStakes")
                .withArgs(caller.address, stakingPool.address, expectedTotalStakes)
                .and
                .to.emit(stakingHbbft, "RecoverAbandonedStakes")
                .withArgs(caller.address, expectedReinsertShare, expectedGovernanceShare)

            await expect(tx).to.changeEtherBalances(
                [await stakingHbbft.getAddress(), reinsertAddress, governanceAddress],
                [-expectedTotalStakes, expectedReinsertShare, expectedGovernanceShare]
            );

            expect(await stakingHbbft.stakeAmountTotal(stakingPool.address)).to.be.equal(0);
        });

        it("should recover abandoned stakes, mark pool as abandoned and remove from inactive pools", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);

            await helpers.time.increase(validatorInactivityThreshold + 3600n);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.true;

            await expect(stakingHbbft.recoverAbandonedStakes())
                .to.emit(stakingHbbft, "RecoverAbandonedStakes");

            expect(await stakingHbbft.getPoolsInactive()).to.not.include(stakingPool.address);
            expect(await stakingHbbft.abandonedAndRemoved(stakingPool.address)).to.be.true;
        });

        it("should return maxWithdrawAllowed = 0 if pool was abandoned and removed", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);

            await helpers.time.increase(validatorInactivityThreshold + 3600n);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.true;

            await expect(stakingHbbft.recoverAbandonedStakes())
                .to.emit(stakingHbbft, "RecoverAbandonedStakes");

            expect(await stakingHbbft.abandonedAndRemoved(stakingPool.address)).to.be.true;

            for (let staker of stakers) {
                expect(await stakingHbbft.maxWithdrawAllowed(stakingPool.address, staker.address)).to.equal(0);
            }
        });

        it("should disallow staking to abandoned pool", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);

            await helpers.time.increase(validatorInactivityThreshold + 3600n);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.true;

            await expect(stakingHbbft.recoverAbandonedStakes())
                .to.emit(stakingHbbft, "RecoverAbandonedStakes");

            expect(await stakingHbbft.abandonedAndRemoved(stakingPool.address)).to.be.true;

            await expect(
                stakingHbbft.connect(stakers[0]).stake(stakingPool.address, { value: delegatorMinStake })
            ).to.be.revertedWith("Stake: pool abandoned")
        });

        it("should not allow stake withdrawal if pool was abandoned", async () => {
            const {
                stakingHbbft,
                validatorSetHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            await stake(stakingHbbft, stakingPool.address, candidateMinStake, [stakingPool])
            await stake(stakingHbbft, stakingPool.address, delegatorMinStake, stakers);

            await setValidatorInactive(stakingHbbft, validatorSetHbbft, stakingPool.address);

            await helpers.time.increase(validatorInactivityThreshold + 3600n);
            expect(await validatorSetHbbft.isValidatorAbandoned(stakingPool.address)).to.be.true;

            await expect(stakingHbbft.recoverAbandonedStakes())
                .to.emit(stakingHbbft, "RecoverAbandonedStakes");

            expect(await stakingHbbft.abandonedAndRemoved(stakingPool.address)).to.be.true;

            const staker = stakers[1];

            expect(await stakingHbbft.maxWithdrawAllowed(stakingPool.address, staker.address)).to.equal(0);

            await expect(
                stakingHbbft.connect(staker).withdraw(stakingPool.address, delegatorMinStake)
            ).to.be.revertedWith("Withdraw: maxWithdrawAllowed exceeded")
        });
    });

    describe.only('restake()', async () => {
        it('should allow calling only to BlockReward contract', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).restake(ethers.ZeroAddress, 0n))
                .to.be.revertedWith("Only BlockReward");
        });

        it('should do nothing if zero value provided', async () => {
            const { stakingHbbft, blockRewardHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = await impersonateAcc(await blockRewardHbbft.getAddress());

            await expect(stakingHbbft.connect(caller).restake(
                initialStakingAddresses[1],
                0n,
                { value: 0n }
            )).to.not.emit(stakingHbbft, "RestakeReward");
        });

        it.only('should restake all rewards to validator without delegators', async () => {
            const {
                stakingHbbft,
                blockRewardHbbft,
                validatorSetHbbft,
                candidateMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            const fixedEpochEndTime = await stakingHbbft.stakingFixedEpochEndTime();
            await helpers.time.increaseTo(fixedEpochEndTime + 1n);
            await helpers.mine(1);

            console.log("current time: ", (await ethers.provider.getBlock("latest"))?.timestamp);
            console.log("fixed epch  : ", fixedEpochEndTime)

            expect(await ethers.provider.getBalance(await blockRewardHbbft.getAddress())).to.be.equal(0n);

            for (let i = 0; i < initialStakingAddresses.length; ++i) {
                const pool = await ethers.getSigner(initialStakingAddresses[i]);

                await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });
                expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.eq(candidateMinStake);
            }

            const systemSigner = await impersonateAcc(SystemAccountAddress);

            await blockRewardHbbft.connect(systemSigner).reward(true);
            await blockRewardHbbft.connect(systemSigner).reward(true);

            await helpers.stopImpersonatingAccount(SystemAccountAddress);

            const deltaPotValue = ethers.parseEther('50');
            await blockRewardHbbft.addToDeltaPot({ value: deltaPotValue });
            expect(await blockRewardHbbft.deltaPot()).to.be.equal(deltaPotValue);
            console.log("delta pot balance: ", await blockRewardHbbft.deltaPot());

            const validators = await validatorSetHbbft.getValidators();
            const potsShares = await blockRewardHbbft.getPotsShares(validators.length);

            const validatorRewards = potsShares.totalRewards - potsShares.governancePotAmount;
            const poolReward = validatorRewards / BigInt(validators.length);

            console.log(potsShares);
            console.log("expected pool reward: ", poolReward)

            await callReward(blockRewardHbbft, true);

            for (let i = 0; i < initialStakingAddresses.length; ++i) {
                const pool = await ethers.getSigner(initialStakingAddresses[i]);

                expect(await stakingHbbft.stakeAmountTotal(pool.address)).to.be.eq(candidateMinStake + poolReward);
            }
        });
    });

    describe('setStakingTransitionTimeframeLength()', async () => {
        it('should allow calling only to contract owner', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).setStakingTransitionTimeframeLength(300n))
                .to.be.revertedWith("Ownable: caller is not the owner");
        });

        it('should set staking transition time frame length', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.setStakingTransitionTimeframeLength(300n);
            expect(await stakingHbbft.stakingTransitionTimeframeLength()).to.be.equal(300n);
        });

        it('should not set staking transition time frame length to low value', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.setStakingTransitionTimeframeLength(9n))
                .to.be.revertedWith("The transition timeframe must be longer than 10");
        });

        it('should not set staking transition time frame length to high value', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await expect(stakingHbbft.setStakingTransitionTimeframeLength(100000n))
                .to.be.revertedWith("The transition timeframe must be smaller than the epoch duration");
        });

    });

    describe('setStakingFixedEpochDuration()', async () => {
        it('should allow calling only to contract owner', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).setStakingFixedEpochDuration(600000n))
                .to.be.revertedWith("Ownable: caller is not the owner");
        });

        it('should set staking fixed epoch transition', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            await stakingHbbft.setStakingFixedEpochDuration(600000n);
            expect(await stakingHbbft.stakingFixedEpochDuration()).to.be.equal(600000n);
        });

        it('should not set staking transition time frame length to low value', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            let tranitionTimeFrame = await stakingHbbft.stakingTransitionTimeframeLength();
            await expect(stakingHbbft.setStakingFixedEpochDuration(tranitionTimeFrame))
                .to.be.revertedWith("The fixed epoch duration timeframe must be greater than the transition timeframe length");
        });
    });

    describe('setCandidateMinStake()', async () => {
        it('should allow calling only to contract owner', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).setCandidateMinStake(ethers.parseEther('10')))
                .to.be.revertedWith("Ownable: caller is not the owner");
        });

        it('should set candidate min stake', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const minStakeValue = ethers.parseEther('15')
            await stakingHbbft.setCandidateMinStake(minStakeValue);
            expect(await stakingHbbft.candidateMinStake()).to.be.equal(minStakeValue);
        });
    });

    describe('setDelegatorMinStake()', async () => {
        it('should allow calling only to contract owner', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).setDelegatorMinStake(ethers.parseEther('10')))
                .to.be.revertedWith("Ownable: caller is not the owner");
        });

        it('should set delegator min stake', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const minStakeValue = ethers.parseEther('15')
            await stakingHbbft.setDelegatorMinStake(minStakeValue);
            expect(await stakingHbbft.delegatorMinStake()).to.be.equal(minStakeValue);
        });
    });

    describe('snapshotPoolStakeAmounts()', async () => {
        it('should allow calling only by BlockReward contract', async () => {
            const { stakingHbbft } = await helpers.loadFixture(deployContractsFixture);

            const caller = accounts[5];
            await expect(stakingHbbft.connect(caller).snapshotPoolStakeAmounts(0n, initialStakingAddresses[1]))
                .to.be.revertedWith("Only BlockReward");
        });

        it('should create validator stake snapshot after epoch close', async () => {
            const {
                stakingHbbft,
                blockRewardHbbft,
                candidateMinStake,
                delegatorMinStake
            } = await helpers.loadFixture(deployContractsFixture);

            const delegator = accounts[10];

            let stakingEpoch = await stakingHbbft.stakingEpoch();
            for (let i = 0; i < initialStakingAddresses.length; ++i) {
                const pool = await ethers.getSigner(initialStakingAddresses[i]);
                const stakeAmount = BigInt(i + 1) * delegatorMinStake;

                await stakingHbbft.connect(pool).stake(pool.address, { value: candidateMinStake });

                await stakingHbbft.connect(delegator).stake(pool, { value: stakeAmount });
                expect(await stakingHbbft.stakeAmountTotal(pool)).to.be.equal(candidateMinStake + stakeAmount);
                expect(await stakingHbbft.snapshotPoolTotalStakeAmount(stakingEpoch, pool)).to.be.eq(0n);
                expect(await stakingHbbft.snapshotPoolValidatorStakeAmount(stakingEpoch, pool.address)).to.be.eq(0n);
            }

            await callReward(blockRewardHbbft, true);
            stakingEpoch = await stakingHbbft.stakingEpoch();

            for (let i = 0; i < initialStakingAddresses.length; ++i) {
                const pool = await ethers.getSigner(initialStakingAddresses[i]);
                const stakeAmount = BigInt(i + 1) * delegatorMinStake;

                expect(await stakingHbbft.stakeAmountTotal(pool)).to.be.equal(candidateMinStake + stakeAmount);
                expect(await stakingHbbft.snapshotPoolTotalStakeAmount(stakingEpoch, pool)).to.be.eq(candidateMinStake + stakeAmount);
                expect(await stakingHbbft.getPoolValidatorStakeAmount(stakingEpoch, pool.address)).to.be.eq(candidateMinStake);
            }
        });
    });

    async function callReward(blockRewardContract: BlockRewardHbbftMock, isEpochEndBlock: boolean) {
        const systemSigner = await impersonateAcc(SystemAccountAddress);

        const tx = await blockRewardContract.connect(systemSigner).reward(isEpochEndBlock);
        const receipt = await tx.wait();

        await helpers.stopImpersonatingAccount(SystemAccountAddress);

        if (receipt!.logs.length > 0) {
            // Emulate minting native coins
            const event = blockRewardContract.interface.parseLog(receipt!.logs[0]);

            expect(event!.name).to.be.equal("CoinsRewarded");

            const totalReward = event!.args.rewards;
            await blockRewardContract.connect(owner).sendCoins({ value: totalReward });
        }
    }

    // time travels forward to the beginning of the next transition,
    // and simulate a block mining (calling reward())
    async function timeTravelToTransition(
        blockRewardContract: BlockRewardHbbftMock,
        stakingContract: StakingHbbftMock
    ) {
        let startTimeOfNextPhaseTransition = await stakingContract.startTimeOfNextPhaseTransition();

        await helpers.time.increaseTo(startTimeOfNextPhaseTransition);
        await callReward(blockRewardContract, false);
    }

    async function timeTravelToEndEpoch(
        blockRewardContract: BlockRewardHbbftMock,
        stakingContract: StakingHbbftMock
    ) {
        const tsBeforeTimeTravel = await helpers.time.latest();
        const endTimeOfCurrentEpoch = await stakingContract.stakingFixedEpochEndTime();
        // console.log('tsBefore:', tsBeforeTimeTravel.toString());
        // console.log('endTimeOfCurrentEpoch:', endTimeOfCurrentEpoch.toString());

        if (endTimeOfCurrentEpoch < tsBeforeTimeTravel) {
            console.error('Trying to timetravel back in time !!');
        }

        await helpers.time.increaseTo(endTimeOfCurrentEpoch);
        await callReward(blockRewardContract, true);
    }
});

function shuffle(a: number[]) {
    var j, x, i;
    for (i = a.length - 1; i > 0; i--) {
        j = Math.floor(Math.random() * (i + 1));
        x = a[i];
        a[i] = a[j];
        a[j] = x;
    }
    return a;
}

