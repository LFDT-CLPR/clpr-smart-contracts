// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";

/// @dev Overrides Ed25519 so unit tests can run without the precompile.
///      All signatures are accepted when _alwaysVerifyOk is true.
contract SeiCometBftVerifierHarness is SeiCometBftVerifier {
    bool internal _alwaysVerifyOk;

    constructor(bool alwaysOk) SeiCometBftVerifier(address(0xED)) {
        // ED25519 dependency is unused here: _verifyEd25519 is overridden below. A non-zero
        // placeholder satisfies the base constructor's zero-address guard.
        _alwaysVerifyOk = alwaysOk;
    }

    function setAlwaysVerifyOk(bool v) external {
        _alwaysVerifyOk = v;
    }

    function _verifyEd25519(bytes32, bytes memory, bytes memory sig) internal view virtual override returns (bool) {
        if (_alwaysVerifyOk) return true;
        // Reject if sig is all-zero (sentinel for "bad signature" in tests)
        // forge-lint: disable-next-line(unsafe-typecast)
        return sig.length == 64 && uint256(bytes32(sig)) != 0;
    }

    // ── Expose internal helpers ───────────────────────────────────────────────

    function findLastMessageId(bytes32 channelId, bytes32 slot, uint64 acked, uint64 next, uint256 count)
        external
        pure
        returns (uint64)
    {
        return _findLastMessageId(channelId, slot, acked, next, count);
    }

    function lastMessageRunningHashSlot(bytes32 channelId, uint64 messageId) external pure returns (bytes32) {
        return _lastMessageRunningHashSlot(channelId, messageId);
    }

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }

    function validatorSetHash(CometBftLib.SeiValidator[] memory validators) external pure returns (bytes32) {
        return CometBftLib.validatorSetHash(validators);
    }

    function simpleMerkleRoot(bytes[] memory items) external pure returns (bytes32) {
        return CometBftLib.simpleMerkleRoot(items);
    }

    function encodeValidator(CometBftLib.SeiValidator memory v) external pure returns (bytes memory) {
        return CometBftLib.encodeValidator(v);
    }

    function headerHash(CometBftLib.SeiHeader memory h) external pure returns (bytes32) {
        return CometBftLib.headerHash(h);
    }

    function precommitSignBytes(
        string memory chainId,
        int64 height,
        int32 round,
        bytes32 blockIdHash,
        uint32 partTotal,
        bytes32 partHash,
        int64 tsSeconds,
        int32 tsNanos
    ) external pure returns (bytes memory) {
        return CometBftLib.precommitSignBytes(
            chainId, height, round, blockIdHash, partTotal, partHash, tsSeconds, tsNanos
        );
    }

    function pbVarint(uint256 value) external pure returns (bytes memory) {
        return CometBftLib.pbVarint(value);
    }

    function pbBytesField(uint64 field, bytes memory value) external pure returns (bytes memory) {
        return CometBftLib.pbBytesField(field, value);
    }

    function pbVarintField(uint64 field, uint256 value) external pure returns (bytes memory) {
        return CometBftLib.pbVarintField(field, value);
    }
}
