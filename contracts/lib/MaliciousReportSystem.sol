// SPDX-License-Identifier: Apache 2.0
pragma solidity =0.8.25;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import { IStakingHbbft } from "../interfaces/IStakingHbbft.sol";

abstract contract MaliciousReportSystem is Initializable {
    struct MaliciousReportSystemStorage {
        /// @dev duration of ban in epochs
        uint256 _banDuration;

        IStakingHbbft _stakingContract;

        /// @dev Stores the validators that have reported the specific validator as malicious for the specified epoch.
        // slither-disable-next-line uninitialized-state
        mapping(address => mapping(uint256 => address[])) _maliceReportedForBlock;
        /// @dev How many times a given mining address was banned.
        mapping(address => uint256) _banCounter;
        /// @dev Returns the time when the ban will be lifted for the specified mining address.
        mapping(address => uint256) _bannedUntil;
        /// @dev Returns the timestamp after which the ban will be lifted for delegators
        /// of the specified pool (mining address).
        mapping(address => uint256) _bannedDelegatorsUntil;
        /// @dev The reason for the latest ban of the specified mining address. See the `_removeMaliciousValidator`
        /// internal function description for the list of possible reasons.
        mapping(address => bytes32) _banReason;
        /// @dev The number of times the specified validator (mining address) reported misbehaviors during the specified
        /// staking epoch. Used by the `reportMaliciousCallable` getter and `reportMalicious` function to determine
        /// whether a validator reported too often.
        mapping(address => mapping(uint256 => uint256)) _reportingCounter;
        /// @dev How many times all validators reported misbehaviors during the specified staking epoch.
        /// Used by the `reportMaliciousCallable` getter and `reportMalicious` function to determine
        /// whether a validator reported too often.
        mapping(uint256 => uint256) _reportingCounterTotal;
    }

    // keccak256(abi.encode(uint256(keccak256("storage.MaliciousReportSystem")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MaliciousReportStorageLocation =
        0x95a5ef17e6a70dd1c961162e69fa0559054f603f2947a86614b02eb10e321700;

    function _getMaliciousReportSystemStorage() private pure returns (MaliciousReportSystemStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := MaliciousReportStorageLocation
        }
    }

    /// @dev Emitted by the `reportMalicious` function to signal that a specified validator reported
    /// misbehavior by a specified malicious validator at a specified block number.
    /// @param reportingValidator The mining address of the reporting validator.
    /// @param maliciousValidator The mining address of the malicious validator.
    /// @param blockNumber The block number at which the `maliciousValidator` misbehaved.
    event ReportedMalicious(address reportingValidator, address maliciousValidator, uint256 blockNumber);

    event SetBanDuration(uint256 _value);

    function __MaliciousReportSystem_init(uint256 _badDuration, address _staking) internal onlyInitializing {
        __MaliciousReportSystem_init_unchained(_badDuration, _staking);
    }

    function __MaliciousReportSystem_init_unchained(uint256 _badDuration, address _staking) internal onlyInitializing {
        _setBanDuration(_badDuration);
        _setStakingHbbft(_staking);
    }

    function _setBanDuration(uint256 _banDuration) internal {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        $._banDuration = _banDuration;

        emit SetBanDuration(_banDuration);
    }

    function _setStakingHbbft(address _staking) internal {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        $._stakingContract = IStakingHbbft(_staking);
    }

    /// @dev Reports that the malicious validator misbehaved at the specified block.
    /// Called by the node of each honest validator after the specified validator misbehaved.
    /// See https://openethereum.github.io/Validator-Set.html#reporting-contract
    /// Can only be called when the `reportMaliciousCallable` getter returns `true`.
    /// @param _maliciousMiningAddress The mining address of the malicious validator.
    /// @param _blockNumber The block number where the misbehavior was observed.
    /// @param _validatorsLength Current validators count
    function _reportMalicious(
        address _maliciousMiningAddress,
        uint256 _blockNumber,
        uint256 _validatorsLength
    ) internal virtual {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        address reportingMiningAddress = msg.sender;

        _incrementReportingCounter(reportingMiningAddress);

        (bool callable, bool removeReportingValidator) = reportMaliciousCallable(
            reportingMiningAddress,
            _maliciousMiningAddress,
            _blockNumber,
            _validatorsLength
        );

        if (!callable) {
            if (removeReportingValidator) {
                // Reporting validator has been reporting too often, so
                // treat them as a malicious as well (spam)
                address[] memory miningAddresses = new address[](1);
                miningAddresses[0] = reportingMiningAddress;
                _removeMaliciousValidators(miningAddresses, "spam");
            }
            return;
        }

        address[] storage reportedValidators = $._maliceReportedForBlock[_maliciousMiningAddress][_blockNumber];

        reportedValidators.push(reportingMiningAddress);

        emit ReportedMalicious(reportingMiningAddress, _maliciousMiningAddress, _blockNumber);

        bool remove;

        if (_validatorsLength > 3) {
            // If more than 2/3 of validators reported about malicious validator
            // for the same `blockNumber`
            remove = reportedValidators.length * 3 > _validatorsLength * 2;
        } else {
            // If more than 1/2 of validators reported about malicious validator
            // for the same `blockNumber`
            remove = reportedValidators.length * 2 > _validatorsLength;
        }

        if (remove) {
            address[] memory miningAddresses = new address[](1);
            miningAddresses[0] = _maliciousMiningAddress;
            _removeMaliciousValidators(miningAddresses, "malicious");
        }
    }

    /// @dev Returns a boolean flag indicating whether delegators of the specified pool are currently banned.
    /// A validator pool can be banned when they misbehave (see the `_removeMaliciousValidator` function).
    /// @param _miningAddress The mining address of the pool.
    function areDelegatorsBanned(address _miningAddress) external view returns (bool) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        return block.timestamp <= $._bannedDelegatorsUntil[_miningAddress];
    }

    /// @dev Returns a boolean flag indicating whether the specified mining address is currently banned.
    /// A validator can be banned when they misbehave (see the `_removeMaliciousValidator` internal function).
    /// @param _miningAddress The mining address.
    function isValidatorBanned(address _miningAddress) public view returns (bool) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        return block.timestamp <= $._bannedUntil[_miningAddress];
    }

    /// @dev Returns an array of the validators (their mining addresses) which reported that the specified malicious
    /// validator misbehaved at the specified block.
    /// @param _miningAddress The mining address of malicious validator.
    /// @param _blockNumber The block number.
    function maliceReportedForBlock(
        address _miningAddress,
        uint256 _blockNumber
    ) external view returns (address[] memory) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        return $._maliceReportedForBlock[_miningAddress][_blockNumber];
    }

    /// @dev Returns whether the `reportMalicious` function can be called by the specified validator with the
    /// given parameters. Used by the `reportMalicious` function and `TxPermission` contract. Also, returns
    /// a boolean flag indicating whether the reporting validator should be removed as malicious due to
    /// excessive reporting during the current staking epoch.
    /// @param _reportingMiningAddress The mining address of the reporting validator which is calling
    /// the `reportMalicious` function.
    /// @param _maliciousMiningAddress The mining address of the malicious validator which is passed to
    /// the `reportMalicious` function.
    /// @param _blockNumber The block number which is passed to the `reportMalicious` function.
    /// @return callable `bool callable` - The boolean flag indicating whether the `reportMalicious` function
    /// can be called at the moment.
    /// @return removeReportingValidator `bool removeReportingValidator` - The boolean flag indicating whether
    /// the reporting validator should be removed as malicious due to excessive reporting. This flag is only used
    /// by the `reportMalicious` function.
    function reportMaliciousCallable(
        address _reportingMiningAddress,
        address _maliciousMiningAddress,
        uint256 _blockNumber,
        uint256 _validatorsCount
    ) public view returns (bool callable, bool removeReportingValidator) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        if (!isReportValidatorValid(_reportingMiningAddress)) return (false, false);
        if (!isReportValidatorValid(_maliciousMiningAddress)) return (false, false);

        if (_validatorsCount > 1) {
            uint256 currentStakingEpoch = $._stakingContract.stakingEpoch();
            uint256 reportsNumber = $._reportingCounter[_reportingMiningAddress][currentStakingEpoch];
            uint256 reportsTotalNumber = $._reportingCounterTotal[currentStakingEpoch];
            uint256 averageReportsNumberX10 = 0;

            if (reportsTotalNumber >= reportsNumber) {
                averageReportsNumberX10 = ((reportsTotalNumber - reportsNumber) * 10) / (_validatorsCount - 1);
            }

            if (reportsNumber > _validatorsCount * 50 && reportsNumber > averageReportsNumberX10) {
                return (false, true);
            }
        }

        uint256 currentBlock = block.number; // TODO: _getCurrentBlockNumber(); Make it time based here ?

        if (_blockNumber > currentBlock) return (false, false); // avoid reporting about future blocks

        uint256 ancientBlocksLimit = 100; //TODO: needs to be afjusted for HBBFT specifications i.e. time
        if (currentBlock > ancientBlocksLimit && _blockNumber < currentBlock - ancientBlocksLimit) {
            return (false, false); // avoid reporting about ancient blocks
        }

        address[] storage reportedValidators = $._maliceReportedForBlock[_maliciousMiningAddress][_blockNumber];

        // Don't allow reporting validator to report about the same misbehavior more than once
        uint256 length = reportedValidators.length;
        for (uint256 m = 0; m < length; m++) {
            if (reportedValidators[m] == _reportingMiningAddress) {
                return (false, false);
            }
        }

        return (true, false);
    }

    /// @dev Updates the total reporting counter (see the `reportingCounterTotal` public mapping) for the current
    /// staking epoch after the specified validator is removed as malicious. The `reportMaliciousCallable` getter
    /// uses this counter for reporting checks so it must be up-to-date. Called by the `_removeMaliciousValidators`
    /// internal function.
    /// @param _miningAddress The mining address of the removed malicious validator.
    function _clearReportingCounter(address _miningAddress) internal {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        uint256 currentStakingEpoch = $._stakingContract.stakingEpoch();
        uint256 total = $._reportingCounterTotal[currentStakingEpoch];
        uint256 counter = $._reportingCounter[_miningAddress][currentStakingEpoch];

        $._reportingCounter[_miningAddress][currentStakingEpoch] = 0;

        if (total >= counter) {
            $._reportingCounterTotal[currentStakingEpoch] -= counter;
        } else {
            $._reportingCounterTotal[currentStakingEpoch] = 0;
        }
    }

    /// @dev Increments the reporting counter for the specified validator and the current staking epoch.
    /// See the `reportingCounter` and `reportingCounterTotal` public mappings. Called by the `reportMalicious`
    /// function when the validator reports a misbehavior.
    /// @param _reportingMiningAddress The mining address of reporting validator.
    function _incrementReportingCounter(address _reportingMiningAddress) internal {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        if (!isReportValidatorValid(_reportingMiningAddress)) return;

        uint256 currentStakingEpoch = $._stakingContract.stakingEpoch();
        $._reportingCounter[_reportingMiningAddress][currentStakingEpoch]++;
        $._reportingCounterTotal[currentStakingEpoch]++;
    }

    /// @dev Removes the specified validator as malicious. Used by the `_removeMaliciousValidators` internal function.
    /// @param _miningAddress The removed validator mining address.
    /// @param _reason A short string of the reason why the mining address is treated as malicious:
    /// "inactive" - the validator has not been contributing to block creation for sigificant period of time.
    /// "spam" - the validator made a lot of `reportMalicious` callings compared with other validators.
    /// "malicious" - the validator was reported as malicious by other validators with the `reportMalicious` function.
    /// @return Returns `true` if the specified validator has been removed from the pending validator set.
    /// Otherwise returns `false` (if the specified validator has already been removed or cannot be removed).
    function _removeMaliciousValidator(address _miningAddress, bytes32 _reason) internal returns (bool) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        bool isBanned = isValidatorBanned(_miningAddress);
        // Ban the malicious validator for at least the next 12 staking epochs
        uint256 banUntil = _banUntil();

        $._banCounter[_miningAddress]++;
        $._bannedUntil[_miningAddress] = banUntil;
        $._banReason[_miningAddress] = _reason;

        if (isBanned) {
            // The validator is already banned
            return false;
        } else {
            $._bannedDelegatorsUntil[_miningAddress] = banUntil;
        }

        // Remove malicious validator from the `pools`
        // address stakingAddress = stakingByMiningAddress[_miningAddress];
        // stakingContract.removePool(stakingAddress);

        // If the validator set has only one validator, don't remove it.
        // uint256 length = _currentValidators.length;
        // if (length == 1) {
        //     return false;
        // }

        // for (uint256 i = 0; i < length; i++) {
        //     if (_currentValidators[i] == _miningAddress) {
        //         // Remove the malicious validator from `_pendingValidators`
        //         _currentValidators[i] = _currentValidators[length - 1];
        //         _currentValidators.pop();
        //         return true;
        //     }
        // }

        return false;
    }

    /// @dev Removes the specified validators as malicious from the pending validator set. Does nothing if
    /// the specified validators are already banned or don't exist in the pending validator set.
    /// @param _miningAddresses The mining addresses of the malicious validators.
    /// @param _reason A short string of the reason why the mining addresses are treated as malicious,
    /// see the `_removeMaliciousValidator` internal function description for possible values.
    function _removeMaliciousValidators(address[] memory _miningAddresses, bytes32 _reason) internal {
        for (uint256 i = 0; i < _miningAddresses.length; i++) {
            if (_removeMaliciousValidator(_miningAddresses[i], _reason)) {
                // From this moment `getPendingValidators()` returns the new validator set
                _clearReportingCounter(_miningAddresses[i]);
            }
        }
    }

    /// @dev Returns the future timestamp until which a validator is banned.
    /// Used by the `_removeMaliciousValidator` internal function.
    function _banUntil() internal view returns (uint256) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        uint256 currentTimestamp = block.timestamp;
        uint256 ticksUntilEnd = $._stakingContract.stakingFixedEpochEndTime() - currentTimestamp;
        // Ban for at least 12 full staking epochs:
        // currentTimestampt + stakingFixedEpochDuration + remainingEpochDuration.
        return currentTimestamp + ($._banDuration * $._stakingContract.stakingFixedEpochDuration()) + (ticksUntilEnd);
    }

    /// @dev Returns a boolean flag indicating whether the specified validator (mining address)
    /// is able to call the `reportMalicious` function or whether the specified validator (mining address)
    /// can be reported as malicious. This function also allows a validator to call the `reportMalicious`
    /// function several blocks after ceasing to be a validator. This is possible if a
    /// validator did not have the opportunity to call the `reportMalicious` function prior to the
    /// engine calling the `finalizeChange` function.
    /// @param _miningAddress The validator's mining address.
    function isReportValidatorValid(address _miningAddress) public view returns (bool) {
        MaliciousReportSystemStorage storage $ = _getMaliciousReportSystemStorage();

        // bool isValid = isValidator[_miningAddress] && !isValidatorBanned(_miningAddress);
        bool isValid = !isValidatorBanned(_miningAddress);
        if ($._stakingContract.stakingEpoch() == 0) {
            return isValid;
        }

        // TO DO: arbitrarily chosen period stakingFixedEpochDuration/5.
        if (
            block.timestamp - $._stakingContract.stakingEpochStartTime() <= $._stakingContract.stakingFixedEpochDuration() / 5
        ) {
            // The current validator set was finalized by the engine,
            // but we should let the previous validators finish
            // reporting malicious validator within a few blocks
            // bool previousValidator = isValidatorPrevious[_miningAddress];
            // return isValid || previousValidator;
            return isValid;
        }
        return isValid;
    }
}
