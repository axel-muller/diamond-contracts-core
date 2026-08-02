// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity =0.8.25;

import { DaoPhase, Proposal, VotingResult } from "diamond-contracts-dao/library/DaoStructs.sol";

interface IDiamondDao {
    function proposalExists(uint256 proposalId) external view returns (bool);

    function getProposal(uint256 proposalId) external view returns (Proposal memory);

    function daoPhaseCount() external view returns (uint256);

    function daoPhase() external view returns (DaoPhase memory);

    function createProposalFee() external view returns (uint256);

    function getProposalVotersCount(uint256 proposalId) external view returns (uint256);

    function countVotes(uint256 proposalId) external view returns (VotingResult memory);

    function getProposalVoters(uint256 proposalId) external view returns (address[] memory);

    function currentPhaseProposals() external view returns (uint256[] memory);

    function daoEpochTotalStakeSnapshot(uint256 daoEpoch) external view returns (uint256);

    function daoPhaseProposals(uint256 daoPhase, uint256 index) external view returns (uint256);

    function getCurrentPhaseProposals() external view returns (uint256[] memory);

    function MAX_NEW_PROPOSALS() external view returns (uint256);
}
