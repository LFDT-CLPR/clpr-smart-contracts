// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IEthL1StateVerifier
/// @notice Stateless Ethereum (L1) light client: authenticates an execution-layer `state_root` under
///         a sync-committee trust anchor. Verifiers of chains that settle on Ethereum (the OP Stack
///         family) delegate the L1 half of their proof here and then walk L1 storage themselves.
/// @dev The trust anchor is the flat 260-byte {EthBeaconLightClient} anchor
///      (`gvr ‖ forkVersion ‖ channelId ‖ aggregate ‖ committeeMerkleRoot ‖ codeHash`), identical to
///      {EthMainnetVerifier}'s, so the same relay tooling builds both.
interface IEthL1StateVerifier {
    /// @notice Verify a light-client proof and return the authenticated L1 execution state root.
    /// @param lightClientProof RLP `[attestedHeader, syncAggregate, executionStateRoot, executionBranch,
    ///        nextCommittee, nextCommitteeBranch, nonSignerProofs]` (items as in {EthMainnetVerifier}).
    /// @param trustAnchor the channel's current 260-byte anchor.
    /// @return executionStateRoot the L1 execution state root the sync committee attested to.
    /// @return slot the attested beacon slot (its wall-clock time is `genesisTime + slot × secondsPerSlot`).
    /// @return newTrustAnchor the successor anchor when the proof carries a committee rotation, else empty.
    /// @return newTrustAnchorId the successor anchor's sync-committee period (8-byte BE), else empty.
    function verifyL1State(bytes calldata lightClientProof, bytes calldata trustAnchor)
        external
        view
        returns (bytes32 executionStateRoot, uint64 slot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId);

    /// @notice Build the genesis trust anchor from a config proof.
    /// @param configProof RLP `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`
    ///        ({EthMainnetVerifier}'s config format).
    /// @param channelId the channel the anchor is bound to.
    /// @return trustAnchor the 260-byte anchor committing to the (on-curve checked) committee.
    /// @return trustAnchorId the committee's sync-committee period (8-byte BE).
    /// @return ledgerConfiguration the raw `ClprControlMessage` bytes (item 4), for the caller to decode.
    function genesisTrustAnchor(bytes calldata configProof, bytes32 channelId)
        external
        view
        returns (bytes memory trustAnchor, bytes memory trustAnchorId, bytes memory ledgerConfiguration);
}
