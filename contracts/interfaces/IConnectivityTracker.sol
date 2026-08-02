// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

interface IConnectivityTracker {
    function isFaultyValidator(uint256, address) external view returns (bool);

    function getValidatorConnectivityScore(uint256, address) external view returns (uint256);
}
