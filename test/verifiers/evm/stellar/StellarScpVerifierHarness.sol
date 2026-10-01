// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {StellarScpVerifier} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarScpVerifier.sol";
import {StellarXdr} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarXdr.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Test harness for live data. No CLPR service exists on Stellar, so a live bundle's event is a
///      real Soroban event of another contract (a `new_block_event` on testnet, a RedStone
///      `REDSTONE` price update on pubnet). `proveEvent`
///      runs the production steps of `verifyBundle` (quorum set, SCP finality, checkpoint, header walk,
///      result set, transaction hash, success preimage, emitter) and returns what they proved instead
///      of insisting on the `clpr_queue` topics.
contract StellarScpVerifierHarness is StellarScpVerifier {
    struct Proven {
        uint64 slot;
        uint32 checkpointSeq;
        bytes32 checkpointHash;
        uint32 ledgerSeq;
        bytes32 emitter;
        uint256 eventCount;
        bytes eventBody; // from the first event's topics vector to the end of the preimage
    }

    constructor(IEd25519Verifier ed25519, bytes32 networkId, string memory chainId)
        StellarScpVerifier(ed25519, networkId, chainId)
    {}

    function proveEvent(bytes calldata proofBytes, bytes calldata trustAnchor, bytes32 serviceContract)
        external
        view
        returns (Proven memory out)
    {
        Anchor memory a = _decodeTrustAnchor(trustAnchor);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS) revert InvalidPayloadShape();
        StellarXdr.QuorumSet memory q = _trustedQuorumSet(RLP.readBytes(p[0]), a.qsetHash);
        Memory.Slice[] memory scp = RLP.readList(p[1]);
        if (scp.length != 0) {
            ScpResult memory r = _verifyScp(scp, q, true);
            if (r.slot <= a.lastSlot) revert StaleSlot(r.slot, a.lastSlot);
            a.checkpointSeq = uint32(r.slot - 1);
            a.checkpointHash = r.previousLedgerHash;
            out.slot = r.slot;
        }
        out.checkpointSeq = a.checkpointSeq;
        out.checkpointHash = a.checkpointHash;
        StellarXdr.Header memory h = _walkHeaders(p[2], a);
        out.ledgerSeq = h.ledgerSeq;
        (bytes memory pre, uint256 o) = _provenEvent(RLP.readList(p[3]), h, serviceContract);
        (out.emitter,, out.eventCount) = StellarXdr.firstContractEvent(pre);
        out.eventBody = StellarXdr.slice(pre, o, pre.length - o);
    }

    /// @dev A LedgerConfiguration control message for live verifyConfig runs (no CLPR service on
    ///      Stellar publishes one, so the spec supplies it; verifyConfig only reads its chain id,
    ///      service address, timestamp and throttles).
    function controlMessage(string calldata chainId, bytes calldata serviceAddress)
        external
        pure
        returns (bytes memory)
    {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = serviceAddress;
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }
}
