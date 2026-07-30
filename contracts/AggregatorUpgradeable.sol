// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import { IKeyGenHistory } from "diamond-contracts-core/interfaces/IKeyGenHistory.sol";

import { IBlockRewardHbbft } from "./interfaces/IBlockRewardHbbft.sol";
import { IStakingHbbftExtended } from "./interfaces/IStakingHbbftExtended.sol";
import { ITxPermission } from "./interfaces/ITxPermission.sol";
import { IValidatorSetHbbftExtended } from "./interfaces/IValidatorSetHbbftExtended.sol";

contract DMDAggregatorUpgradeable is Initializable, OwnableUpgradeable {
    bytes32 private constant DMD_AGGREGATOR_NAMESPACE =
        keccak256(abi.encode(uint256(keccak256("dmdaggregator.storage")) - 1)) & ~bytes32(uint256(0xff));

    struct DMDAggregatorStorage {
        IStakingHbbftExtended st;
        ITxPermission tp;
        IKeyGenHistory kh;
        IBlockRewardHbbft br;
        IValidatorSetHbbftExtended vs;
    }

    function _getStorage() private pure returns (DMDAggregatorStorage storage s) {
        bytes32 slot = DMD_AGGREGATOR_NAMESPACE;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevents initialization of implementation contract
        _disableInitializers();
    }

    function initialize(address contractOwner, address _st, address _vs, address _tp) external initializer {
        __Ownable_init(contractOwner);
        DMDAggregatorStorage storage s = _getStorage();

        s.st = IStakingHbbftExtended(_st);
        s.tp = ITxPermission(_tp);
        s.vs = IValidatorSetHbbftExtended(_vs);
        s.kh = IKeyGenHistory(s.vs.keyGenHistoryContract());
        s.br = IBlockRewardHbbft(s.vs.blockRewardContract());
    }

    struct Pools {
        address[] stActivePools;
        address[] stInActivePools;
        address[] stPoolsToBeElected;
        address[] vsValidatorsMiningAddresses;
        address[] vsValidatorsStakingAddresses;
        address[] vsPendingValidatorsMiningAddresses;
        address[] vsPendingValidatorsStakingAddresses;
    }

    struct GlobalsData {
        uint256 deltaPot;
        uint256 reinsertPot;
        uint256 keygenRound;
        uint256 stakingEpoch;
        uint256 minimumGasPrice;
        uint256 candidateMinStake;
        uint256 delegatorMinStake;
        uint256 stakingEpochStartTime;
        uint256 stakingEpochStartBlock;
        bool areStakeAndWithdrawAllowed;
        uint256 stakingFixedEpochEndTime;
        uint256 stakingFixedEpochDuration;
        uint256 stakingWithdrawDisallowPeriod;
    }

    struct PoolData {
        address miningAddress;
        uint256 availableSince;
        bytes publicKey;
        address[] delegators;
        IValidatorSetHbbftExtended.KeyGenMode keygenMode;
        uint256 stakedAmountTotal;
    }

    struct StakeData {
        address pool;
        uint256 myStakedAmount;
        uint256 stakedAmountTotal;
    }

    struct OrderedWithdrawData {
        address pool;
        uint256 orderedAmount;
        uint256 withdrawEpoch;
    }

    struct DelegateData {
        address delegator;
        uint256 delegatedAmount;
    }

    enum ProposalState {
        Created,
        Canceled,
        Active,
        VotingFinished,
        Accepted,
        Declined,
        Executed
    }

    enum ProposalType {
        Open,
        ContractUpgrade,
        EcosystemParameterChange
    }

    struct Proposal {
        address proposer;
        uint64 votingDaoEpoch;
        ProposalState state;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        string title;
        string description;
        string discussionUrl;
        uint256 daoPhaseCount;
        ProposalType proposalType;
    }

    // SETTERS
    function setStakingContract(address _st) external onlyOwner {
        _getStorage().st = IStakingHbbftExtended(_st);
    }

    function setValidatorsSetContract(address _vs) external onlyOwner {
        _getStorage().vs = IValidatorSetHbbftExtended(_vs);
    }

    function setTxPermissionContract(address _tp) external onlyOwner {
        _getStorage().tp = ITxPermission(_tp);
    }

    function setKeygenHistoryContract(address _kh) external onlyOwner {
        _getStorage().kh = IKeyGenHistory(_kh);
    }

    function setBlockRewardContract(address _br) external onlyOwner {
        _getStorage().br = IBlockRewardHbbft(_br);
    }

    // GETTERS
    function getAllPools() external view returns (Pools memory pools) {
        DMDAggregatorStorage storage s = _getStorage();

        address[] memory vsValidatorsMiningAddresses = s.vs.getValidators();
        address[] memory vsPendingValidatorsMiningAddresses = s.vs.getPendingValidators();

        address[] memory vsValidatorsStakingAddresses = getStakingAddresses(vsValidatorsMiningAddresses);
        address[] memory vsPendingValidatorsStakingAddresses = getStakingAddresses(vsPendingValidatorsMiningAddresses);

        pools = Pools({
            stActivePools: s.st.getPools(),
            stInActivePools: s.st.getPoolsInactive(),
            stPoolsToBeElected: s.st.getPoolsToBeElected(),
            vsValidatorsMiningAddresses: vsValidatorsMiningAddresses,
            vsValidatorsStakingAddresses: vsValidatorsStakingAddresses,
            vsPendingValidatorsMiningAddresses: vsPendingValidatorsMiningAddresses,
            vsPendingValidatorsStakingAddresses: vsPendingValidatorsStakingAddresses
        });
    }

    function getPoolsData(address[] memory _sAs) external view returns (PoolData[] memory poolsData) {
        DMDAggregatorStorage storage s = _getStorage();
        poolsData = new PoolData[](_sAs.length);

        for (uint256 i = 0; i < _sAs.length; i++) {
            address miningAddress = s.vs.miningByStakingAddress(_sAs[i]);
            poolsData[i] = PoolData({
                miningAddress: miningAddress,
                availableSince: s.vs.validatorAvailableSince(miningAddress),
                publicKey: s.vs.getPublicKey(miningAddress),
                delegators: s.st.poolDelegators(_sAs[i]),
                keygenMode: s.vs.getPendingValidatorKeyGenerationMode(miningAddress),
                stakedAmountTotal: s.st.stakeAmountTotal(_sAs[i])
            });
        }
    }

    function getUserStakes(
        address _user,
        address[] calldata _pools
    ) external view returns (StakeData[] memory _stakesData) {
        DMDAggregatorStorage storage s = _getStorage();
        _stakesData = new StakeData[](_pools.length);

        for (uint256 i = 0; i < _pools.length; i++) {
            _stakesData[i] = StakeData({
                pool: _pools[i],
                myStakedAmount: s.st.stakeAmount(_pools[i], _user),
                stakedAmountTotal: s.st.stakeAmountTotal(_pools[i])
            });
        }
    }

    function getUserOrderedWithdraws(
        address _user,
        address[] calldata _pools
    ) external view returns (OrderedWithdrawData[] memory _stakesData) {
        DMDAggregatorStorage storage s = _getStorage();
        _stakesData = new OrderedWithdrawData[](_pools.length);

        for (uint256 i = 0; i < _pools.length; i++) {
            _stakesData[i] = OrderedWithdrawData({
                pool: _pools[i],
                orderedAmount: s.st.orderedWithdrawAmount(_pools[i], _user),
                withdrawEpoch: s.st.orderWithdrawEpoch(_pools[i], _user)
            });
        }
    }

    function getGlobals() external view returns (GlobalsData memory _globalsData) {
        DMDAggregatorStorage storage s = _getStorage();
        _globalsData = GlobalsData({
            deltaPot: s.br.deltaPot(),
            reinsertPot: s.br.reinsertPot(),
            keygenRound: s.kh.getCurrentKeyGenRound(),
            stakingEpoch: s.st.stakingEpoch(),
            minimumGasPrice: s.tp.minimumGasPrice(),
            candidateMinStake: s.st.candidateMinStake(),
            delegatorMinStake: s.st.delegatorMinStake(),
            stakingEpochStartTime: s.st.stakingEpochStartTime(),
            stakingEpochStartBlock: s.st.stakingEpochStartBlock(),
            areStakeAndWithdrawAllowed: true,
            stakingFixedEpochEndTime: s.st.stakingFixedEpochEndTime(),
            stakingFixedEpochDuration: s.st.stakingFixedEpochDuration(),
            stakingWithdrawDisallowPeriod: s.st.stakingWithdrawDisallowPeriod()
        });
    }

    function getDelegationsData(
        address[] memory delegators,
        address poolAddress
    ) external view returns (DelegateData[] memory _delegatesData, uint256 _ownStake, uint256 _candidateStake) {
        DMDAggregatorStorage storage s = _getStorage();
        _delegatesData = new DelegateData[](delegators.length);

        for (uint256 i; i < delegators.length; i++) {
            address delegatorAddress = delegators[i];
            uint256 delegatedAmount = s.st.stakeAmount(poolAddress, delegatorAddress);
            _delegatesData[i] = DelegateData({ delegator: delegatorAddress, delegatedAmount: delegatedAmount });
            if (poolAddress != delegatorAddress) _candidateStake += delegatedAmount;
        }

        _ownStake = s.st.stakeAmountTotal(poolAddress) - _candidateStake;
    }

    function getStakingAddresses(address[] memory miningAddresses) public view returns (address[] memory) {
        DMDAggregatorStorage storage s = _getStorage();
        address[] memory stakingAddresses = new address[](miningAddresses.length);

        for (uint256 i = 0; i < miningAddresses.length; i++) {
            stakingAddresses[i] = s.vs.stakingByMiningAddress(miningAddresses[i]);
        }

        return stakingAddresses;
    }
}
