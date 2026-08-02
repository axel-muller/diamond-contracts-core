// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

interface IBlockRewardHbbft {
    function deltaPot() external view returns (uint256);

    function reinsertPot() external view returns (uint256);
}
