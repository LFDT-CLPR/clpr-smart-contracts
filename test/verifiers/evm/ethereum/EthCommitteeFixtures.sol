// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Shared fixtures for the Ethereum-verifier test suites (unit tests + gas benchmarks):
///      the self-consistent generator committee (every member's pubkey is the G1 generator, so
///      sk = 1 and the aggregate of N members is N·G1), the EIP-2537 precompile addresses, and
///      the committee encoders/aggregates built from them. Single home so the gas benchmarks
///      measure exactly the fixtures the correctness tests verify.
abstract contract EthCommitteeFixtures is Test {
    address internal constant BLS12_G2MSM = address(0x0e);
    address internal constant BLS12_G1MSM = address(0x0c);
    uint256 internal constant SYNC_COMMITTEE_SIZE = 512;
    uint256 internal constant SUPERMAJORITY = 342; // ceil(2/3 · 512)

    // BLS12-381 G1 generator (ZCash/Ethereum serialization), used as every member's pubkey (sk = 1).
    bytes internal constant G1_GEN_X =
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes internal constant G1_GEN_Y =
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes internal constant G1_GEN_COMPRESSED =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes internal constant G1_GEN_Y_NEG =
        hex"114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    bytes internal genUncompressed; // 128-byte EIP-2537 uncompressed G1 generator (pad16‖x‖pad16‖y)

    function setUp() public virtual {
        genUncompressed = abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y);
    }

    /// `n` copies of the uncompressed generator key.
    function _uncompressedKeys(uint256 n) internal view returns (bytes[] memory keys) {
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = genUncompressed;
        }
    }

    /// `n` copies of the compressed generator key.
    function _compressedKeys(uint256 n) internal pure returns (bytes[] memory keys) {
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = G1_GEN_COMPRESSED;
        }
    }

    /// Aggregate signature N·H(signingRoot) via the EIP-2537 G2MSM precompile (one [point‖scalar] term).
    function _aggSig(bytes32 signingRoot, uint256 n) internal view returns (bytes memory) {
        bytes memory h = ClprBeaconBls.hashToG2(signingRoot); // 256-byte uncompressed G2
        (bool ok, bytes memory out) = BLS12_G2MSM.staticcall(abi.encodePacked(h, bytes32(n)));
        assertTrue(ok, "G2MSM failed");
        assertEq(out.length, 256, "sig length");
        return out;
    }

    /// Full-committee aggregate pubkey = SYNC_COMMITTEE_SIZE · gen (every member's sk = 1), via one
    /// G1MSM term — the authenticated `aggregate_pubkey` the verifier subtracts non-participants from.
    function _committeeAggregate() internal view returns (bytes memory) {
        (bool ok, bytes memory out) =
            BLS12_G1MSM.staticcall(abi.encodePacked(genUncompressed, bytes32(SYNC_COMMITTEE_SIZE)));
        assertTrue(ok, "G1MSM aggregate failed");
        assertEq(out.length, 128, "aggregate length");
        return out;
    }

    /// RLP `[pubkeys, aggregate]` committee — the full wire shape `_committee` accepts.
    function _encodeCommittee(bytes[] memory pubkeys, bytes memory agg) internal pure returns (bytes memory) {
        bytes[] memory enc = new bytes[](pubkeys.length);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            enc[i] = RLP.encode(pubkeys[i]);
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(enc); // already-encoded pubkeys list
        items[1] = RLP.encode(agg);
        return RLP.encode(items);
    }

    /// Test-side reference: SSZ `hash_tree_root(SyncCommittee)` from the COMPRESSED 48-byte keys —
    /// the beacon-native encoding the `next_sync_committee` proof commits to. Production only has
    /// the uncompressed-input variant (`ClprBeaconSsz.syncCommitteeRootFromUncompressed`); this
    /// independent replica cross-checks it and feeds the OLD-design gas comparisons.
    function _committeeRootFromCompressed(bytes[] memory compressed, bytes memory compressedAgg)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory leaves = new bytes32[](compressed.length);
        for (uint256 i = 0; i < compressed.length; i++) {
            leaves[i] = sha256(abi.encodePacked(compressed[i], bytes16(0))); // pad64(pubkey48)
        }
        bytes32 pubkeysRoot = ClprBeaconSsz.merkleize(leaves);
        return sha256(abi.encodePacked(pubkeysRoot, sha256(abi.encodePacked(compressedAgg, bytes16(0)))));
    }
}
