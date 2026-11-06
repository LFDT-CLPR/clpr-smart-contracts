// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";

/// @dev Measures the production `_encodeTrustAnchor` (flat packed layout) with an internal
///      `gasleft()` delta so the external-call ABI copy of the 512-key array is excluded.
contract AnchorEncodeHarness is EthMainnetVerifier {
    constructor() {}

    /// @dev Measures the full window encode: two committee Merkle roots plus the flat pack. Both
    ///      committees use the same key material here — this measures cost, not correctness.
    function measureEncode(bytes[] memory pubkeys, bytes memory aggregate)
        external
        view
        returns (uint256 used, uint256 len)
    {
        uint256 g = gasleft();
        bytes memory a = _encodeTrustAnchor(
            AnchorScalars({
                gvr: bytes32(0), forkVersion: hex"04000000", channelId: bytes32(0), codeHash: bytes32(0), period: 0
            }),
            aggregate,
            ClprCommitteeMerkle.root(pubkeys),
            aggregate,
            ClprCommitteeMerkle.root(pubkeys)
        );
        used = g - gasleft();
        len = a.length;
    }
}

/// @notice Gas breakdown of `EthMainnetVerifier._verifyRotation`'s sub-steps, to locate where the
///         rotation cost goes and to measure the uncompressed-only redesign. Uses the generator
///         committee from {EthCommitteeFixtures} (shape-only; per-step costs are representative of
///         the real path).
contract RotationGasBreakdownTest is EthCommitteeFixtures {
    AnchorEncodeHarness internal encHarness;

    function setUp() public override {
        super.setUp();
        encHarness = new AnchorEncodeHarness();
    }

    /// Replicates the OLD RLP trust-anchor design (512 uncompressed keys in the anchor) for the
    /// (C) comparison below; the production `_encodeTrustAnchor` is the flat packed layout.
    function _encodeAnchor(bytes[] memory pubkeys, bytes memory aggregate) internal pure returns (bytes memory) {
        bytes[] memory encodedPubkeys = new bytes[](pubkeys.length);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            encodedPubkeys[i] = RLP.encode(pubkeys[i]);
        }
        bytes memory pubkeysList = RLP.encode(encodedPubkeys);
        bytes[] memory committee = new bytes[](2);
        committee[0] = pubkeysList;
        committee[1] = RLP.encode(aggregate);
        bytes memory forkVersion = hex"04000000";
        bytes[] memory anchor = new bytes[](4);
        anchor[0] = RLP.encode(committee);
        anchor[1] = RLP.encode(bytes32(0));
        anchor[2] = RLP.encode(forkVersion);
        anchor[3] = RLP.encode(bytes32(0));
        return RLP.encode(anchor);
    }

    function test_rotation_gas_breakdown() public view {
        console.log("=== rotation sub-step gas (512-member committee) ===");
        bytes[] memory uncompressed = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes[] memory compressed = _compressedKeys(SYNC_COMMITTEE_SIZE);

        // (A) CURRENT bind loop: compressG1(uncompressed[i]) == compressed[i] for all 512 (+aggregate).
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            require(keccak256(ClprBls12381.compressG1(uncompressed[i])) == keccak256(compressed[i]), "bind");
        }
        require(keccak256(ClprBls12381.compressG1(genUncompressed)) == keccak256(G1_GEN_COMPRESSED), "bindAgg");
        console.log("(A) CURRENT bind: 513x compressG1 + keccak compare:", g0 - gasleft());

        // (A') compressG1 alone (no compare), 512x.
        g0 = gasleft();
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            ClprBls12381.compressG1(uncompressed[i]);
        }
        console.log("(A') 512x compressG1 only:", g0 - gasleft());

        // (B) OLD path: SSZ root from the relayer-supplied compressed keys (test-side replica of the
        //     removed design — see {EthCommitteeFixtures._committeeRootFromCompressed}).
        g0 = gasleft();
        _committeeRootFromCompressed(compressed, G1_GEN_COMPRESSED);
        console.log("(B) OLD committeeRootFromCompressed:", g0 - gasleft());

        // (B') NEW path: SSZ root from the uncompressed keys, compressing on the fly (replaces the OLD
        //      bind loop (A) + root (B) with a single fused pass — no compressed committee needed).
        g0 = gasleft();
        ClprBeaconSsz.syncCommitteeRootFromUncompressed(uncompressed, genUncompressed);
        console.log("(B') NEW syncCommitteeRootFromUncompressed:", g0 - gasleft());

        // (C) OLD anchor encode (RLP of 512 uncompressed keys ~66 KB).
        g0 = gasleft();
        bytes memory anchor = _encodeAnchor(uncompressed, genUncompressed);
        console.log("(C) OLD encode anchor (512 uncompressed RLP):", g0 - gasleft());
        console.log("    anchor bytes:", anchor.length);

        // (C') NEW anchor encode (flat packed layout, production _encodeTrustAnchor).
        (uint256 flatGas, uint256 flatLen) = encHarness.measureEncode(uncompressed, genUncompressed);
        console.log("(C') NEW encode anchor (flat packed):", flatGas);
        console.log("    anchor bytes:", flatLen);

        // (D) Decode the CURRENT dual committee [ [compressed512,aggC], [uncompressed512,aggU] ].
        bytes[] memory dualPair = new bytes[](2);
        dualPair[0] = _encodeCommittee(compressed, G1_GEN_COMPRESSED);
        dualPair[1] = _encodeCommittee(uncompressed, genUncompressed);
        bytes memory dual = RLP.encode(dualPair);
        console.log("    CURRENT dual-committee wire bytes:", dual.length);
        g0 = gasleft();
        RLP.decodeList(dual);
        console.log("(D) decodeList(dual committee) shallow:", g0 - gasleft());

        // (E) NEW wire = uncompressed-only committee [ uncompressed512, aggU ]. Size + decode.
        bytes memory uncOnly = _encodeCommittee(uncompressed, genUncompressed);
        console.log("    NEW uncompressed-only wire bytes:", uncOnly.length);
        g0 = gasleft();
        RLP.decodeList(uncOnly);
        console.log("(E) decodeList(uncompressed-only) shallow:", g0 - gasleft());
    }
}
