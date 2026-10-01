// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosLightClient} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosLightClient.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";

/// @title EtherlinkCementedState
/// @notice The Tezos L1 half of an Etherlink (Tezos smart-rollup EVM) → Hiero path: proves, from a
///         Tezos finality proof, the rollup's last cemented commitment and returns the PVM state hash
///         it commits to.
///
/// Context paths (octez src/proto_025_PsUshuai/lib_protocol/storage.ml, carbonated maps keep their
/// values under `data/`):
///   smart_rollup/index/<hex rollup address>/data/last_cemented_commitment   → 32-byte commitment hash
///   smart_rollup/index/<hex rollup address>/commitments/<hex hash>/data     → 0x00 ‖ commitment
/// Commitment (`Sc_rollup_commitment_repr` V1): compressed_state(32) ‖ inbox_level(int32) ‖
/// predecessor(32) ‖ number_of_ticks(int64); its hash is BLAKE2b-256 of those 76 bytes.
///
/// A commitment is cemented only after the refutation window (`smart_rollup_challenge_window_in_blocks`
/// = 201600 blocks, 14 days at 6 s) passes without a successful challenge, so the returned state is
/// final but about two weeks old.
///
/// What this does NOT do yet: prove an EVM storage slot under the PVM state hash. That needs a
/// binary-Irmin (2-way inode) proof of the durable-storage value of the slot from an
/// Etherlink rollup node; no public endpoint serves one (see the Etherlink chain page).
contract EtherlinkCementedState is TezosLightClient {
    /// @notice Hex of the 20-byte rollup address (path step).
    bytes public rollupHex;

    error BadCommitment();

    constructor(
        Profile memory profile_,
        IEd25519Verifier ed25519,
        TezosSignatureCache cache,
        TezosContextVerifier context,
        bytes20 rollup
    ) TezosLightClient(profile_, ed25519, cache, context) {
        bytes16 digits = "0123456789abcdef";
        bytes memory h = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            h[2 * i] = digits[uint8(rollup[i]) >> 4];
            h[2 * i + 1] = digits[uint8(rollup[i]) & 0x0f];
        }
        rollupHex = h;
    }

    /// @notice Verify finality from `trustAnchor`, then the last cemented commitment of the rollup in
    ///         the final state. Returns its PVM state hash, inbox level and hash, and the new anchor.
    function verifyCementedState(
        FinalityProof calldata finality,
        bytes calldata trustAnchor,
        bytes calldata lccProof,
        bytes calldata commitmentProof
    )
        external
        view
        returns (bytes32 stateHash, uint32 inboxLevel, bytes32 commitmentHash, bytes memory newTrustAnchor)
    {
        (uint32 anchorLevel, bytes32 anchorRoot) = decodeAnchor(trustAnchor);
        (uint32 stateLevel, bytes32 root) = _verifyFinality(finality, anchorLevel, anchorRoot);

        bytes[] memory steps = new bytes[](6);
        steps[0] = "data";
        steps[1] = "smart_rollup";
        steps[2] = "index";
        steps[3] = rollupHex;
        steps[4] = "data";
        steps[5] = "last_cemented_commitment";
        bytes memory lcc = _contextValue(root, steps, lccProof);
        if (lcc.length != 32) revert BadCommitment();
        // casting is safe: lcc.length == 32 is checked above.
        // forge-lint: disable-next-line(unsafe-typecast)
        commitmentHash = bytes32(lcc);

        bytes[] memory csteps = new bytes[](7);
        csteps[0] = "data";
        csteps[1] = "smart_rollup";
        csteps[2] = "index";
        csteps[3] = rollupHex;
        csteps[4] = "commitments";
        csteps[5] = _hex(commitmentHash);
        csteps[6] = "data";
        bytes memory c = _contextValue(root, csteps, commitmentProof);
        if (c.length != 77 || c[0] != 0x00) revert BadCommitment();
        uint256 at;
        assembly ("memory-safe") {
            at := add(c, 0x21)
        }
        if (TezosBlake2b.hashAt(at, 76, TezosBlake2b.H0_32) != commitmentHash) revert BadCommitment();
        assembly ("memory-safe") {
            stateHash := mload(at)
            inboxLevel := shr(224, mload(add(at, 32)))
        }
        newTrustAnchor = encodeAnchor(stateLevel, root);
    }

    function _hex(bytes32 v) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            out[2 * i] = digits[uint8(v[i]) >> 4];
            out[2 * i + 1] = digits[uint8(v[i]) & 0x0f];
        }
    }
}
