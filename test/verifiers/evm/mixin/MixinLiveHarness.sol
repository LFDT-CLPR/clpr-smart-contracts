// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MixinKernelVerifier} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinKernelVerifier.sol";
import {MixinLib} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinLib.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Live-replay harness: runs every step of `verifyBundle` (node changes, record snapshot CoSi,
///      thread) on real kernel data and returns what was proven, stopping before the record decode
///      (live Mixin transactions do not carry a ClprQueueRecord).
contract MixinLiveHarness is MixinKernelVerifier {
    constructor(IEd25519Verifier ed25519) MixinKernelVerifier("mixin:mainnet", ed25519) {}

    function provenThread(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (bytes memory newAnchor, bytes32 lastTx, bytes memory extra, uint64 timestamp)
    {
        Anchor memory a = _decodeAnchor(trustAnchor);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        NodeSet memory ns =
            NodeSet({ready: _words(p[0]), pendingKey: a.pendingKey, pendingAt: a.pendingAt, changedAt: a.changedAt});
        if (keccak256(abi.encodePacked(ns.ready)) != a.nodesHash) revert NodeSetMismatch();
        _applyChanges(ns, RLP.readList(p[1]));
        (lastTx, extra,) = _thread(RLP.readList(p[3]), a.tip);
        MixinLib.Snapshot memory s = _finalSnapshot(ns, RLP.readList(p[2]), bytes32(0));
        _requireTx(s, lastTx);
        _promote(ns, s.timestamp);
        newAnchor = _encodeAnchor(ns, lastTx);
        timestamp = s.timestamp;
    }
}
