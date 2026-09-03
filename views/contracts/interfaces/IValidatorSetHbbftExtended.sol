// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

import { IValidatorSetHbbft } from "diamond-contracts-core/interfaces/IValidatorSetHbbft.sol";

interface IValidatorSetHbbftExtended is IValidatorSetHbbft {
    function bonusScoreSystem() external view returns (address);

    function keyGenHistoryContract() external view returns (address);
}
