// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

import { IStakingHbbft } from "diamond-contracts-core/interfaces/IStakingHbbft.sol";

interface IStakingHbbftExtended is IStakingHbbft {
    function getPools() external view returns (address[] memory);

    function candidateMinStake() external view returns (uint256);

    function delegatorMinStake() external view returns (uint256);

    function poolNodeOperator(address) external view returns (address);

    function poolNodeOperatorShare(address) external view returns (uint256);

    function orderWithdrawEpoch(address, address) external view returns (uint256);

    function maxWithdrawAllowed(address, address) external view returns (uint256);

    function maxWithdrawOrderAllowed(address, address) external view returns (uint256);
}
