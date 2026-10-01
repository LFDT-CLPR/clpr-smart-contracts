// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TronVerifier} from "@hiero-ledger/clpr/verifiers/evm/tron/TronVerifier.sol";
import {TronLib} from "@hiero-ledger/clpr/verifiers/evm/tron/TronLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes TronVerifier's internal steps so live TRON data can be checked piecewise: there is no
///      ClprService (and so no attestQueue transaction) on TRON yet, so a live bundle reaches the
///      verifier's last check (the attestQueue selector) and stops there. This harness runs every step
///      before that check, on the same production code, and returns what it proved.
contract TronVerifierHarness is TronVerifier {
    constructor(uint256 srCount, uint256 threshold, uint64 intervalMs, uint64 offsetMs, string memory chainId)
        TronVerifier(srCount, threshold, intervalMs, offsetMs, chainId)
    {}

    /// @notice Steps 0-2 of verifyBundle (set check, key updates, rotation), then confirm a
    ///         TriggerSmartContract tx with the resulting set (>= THRESHOLD signatures, else revert). Mirrors verifyBundle up to the
    ///         attestation-selector check.
    function liveBundle(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (uint64 period, bytes32 setHash, uint64 txBlock, address target, bytes4 selector, uint64 contractRet)
    {
        Anchor memory anchor = _decodeTrustAnchor(trustAnchor);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS) revert InvalidPayloadShape();
        (SrSet memory set, bytes32 h) = _decodeSrSet(p[0]);
        if (h != anchor.setHash) revert SrSetHashMismatch();
        (PendingKeys memory pending,) = _applyKeyUpdates(p[1], set, anchor);
        Memory.Slice[] memory rotation = RLP.readList(p[2]);
        period = anchor.period;
        if (rotation.length != 0) (set, period) = _rotate(rotation, set, pending, anchor.period);
        setHash = _hashSrSet(set);

        (TronLib.Header memory hdr, bytes memory txBytes) = _confirmTx(p[3], set);
        txBlock = hdr.number;
        (uint64 ctype, bytes memory param, uint64 ret) = TronLib.parseTransaction(txBytes);
        if (ctype != TronLib.TRIGGER_SMART_CONTRACT) revert UnexpectedContractType(ctype);
        contractRet = ret;
        bytes memory data;
        (target, data) = TronLib.parseTrigger(param);
        // casting to 'bytes4' takes the selector; data shorter than 4 bytes yields zero padding
        // forge-lint: disable-next-line(unsafe-typecast)
        selector = bytes4(data);
    }

    /// @notice Parse one raw header: (number, timestamp, witness, blockId, signer).
    function header(bytes calldata raw, bytes calldata sig)
        external
        pure
        returns (uint64 number, uint64 timestamp, address witness, bytes32 id, address signer)
    {
        TronLib.Header memory h = TronLib.parseHeader(raw);
        return (h.number, h.timestamp, h.witness, TronLib.blockId(h), TronLib.recoverSigner(h.rawHash, sig));
    }
}
