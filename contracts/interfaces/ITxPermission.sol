// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

interface ITxPermission {
    function minimumGasPrice() external view returns (uint256);
}
