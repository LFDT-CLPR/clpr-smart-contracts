// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {EthMainnetVerifierTestHarness} from "@test/verifiers/evm/ethereum/EthVerifierHarnesses.sol";

/// @dev Shared fixtures for every Ethereum-verifier suite — unit, window, gas benchmark and
///      compliance. One home, so the fixture the correctness tests verify is the same one the gas
///      benchmarks measure and the compliance adapter feeds to the verifier.
abstract contract EthCommitteeFixtures is Test {
    address internal constant BLS12_G2MSM = address(0x0e);
    address internal constant BLS12_G1MSM = address(0x0c);
    uint256 internal constant SYNC_COMMITTEE_SIZE = 512;
    uint256 internal constant NEXT_COMMITTEE_BRANCH_DEPTH = 6;
    uint256 internal constant SUPERMAJORITY = 342; // ceil(2/3 · 512)
    /// Mirrors EthMainnetVerifier's mainnet preset: SLOTS_PER_EPOCH(32) × EPOCHS_PER_PERIOD(256).
    uint64 internal constant SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192;

    // Anchor scalars the builders below anchor against, shared by every Ethereum-verifier suite.
    bytes4 internal constant FORK_VERSION = 0x04000000; // Deneb mainnet
    bytes32 internal constant GVR = bytes32(uint256(0x9999));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC04EC));
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    /// SSZ generalized index of `next_sync_committee` in the beacon state (branch depth 6).
    uint256 internal constant GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE = 87;

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

    function _memberKey(uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = BLS12_G1MSM.staticcall(abi.encodePacked(genUncompressed, bytes32(sk)));
        assertTrue(ok, "G1MSM member key failed");
        assertEq(out.length, 128, "member key length");
        return out;
    }

    /// `n` copies of the uncompressed generator key.
    function _uncompressedKeys(uint256 n) internal view returns (bytes[] memory keys) {
        return _uncompressedKeys(n, 1);
    }

    /// `n` copies of the uncompressed member key of the committee at secret key `sk`.
    function _uncompressedKeys(uint256 n, uint256 sk) internal view returns (bytes[] memory keys) {
        bytes memory key = sk == 1 ? genUncompressed : _memberKey(sk);
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = key;
        }
    }

    /// `n` copies of the compressed generator key.
    function _compressedKeys(uint256 n) internal pure returns (bytes[] memory keys) {
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = G1_GEN_COMPRESSED;
        }
    }

    /// `n` copies of the compressed member key of the committee at secret key `sk`.
    function _compressedKeys(uint256 n, uint256 sk) internal view returns (bytes[] memory keys) {
        bytes memory key = sk == 1 ? G1_GEN_COMPRESSED : ClprBls12381.compressG1(_memberKey(sk));
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = key;
        }
    }

    /// Aggregate signature N·H(signingRoot) via the EIP-2537 G2MSM precompile (one [point‖scalar] term).
    function _aggSig(bytes32 signingRoot, uint256 n) internal view returns (bytes memory) {
        return _aggSig(signingRoot, n, 1);
    }

    /// Aggregate signature over `signingRoot` by `n` members of the committee at secret key `sk`.
    function _aggSig(bytes32 signingRoot, uint256 n, uint256 sk) internal view returns (bytes memory) {
        bytes memory h = ClprBeaconBls.hashToG2(signingRoot); // 256-byte uncompressed G2
        (bool ok, bytes memory out) = BLS12_G2MSM.staticcall(abi.encodePacked(h, bytes32(n * sk)));
        assertTrue(ok, "G2MSM failed");
        assertEq(out.length, 256, "sig length");
        return out;
    }

    /// Full-committee aggregate pubkey = SYNC_COMMITTEE_SIZE · gen (every member's sk = 1), via one
    /// G1MSM term — the authenticated `aggregate_pubkey` the verifier subtracts non-participants from.
    function _committeeAggregate() internal view returns (bytes memory) {
        return _committeeAggregate(1);
    }

    /// Full-committee aggregate pubkey of the committee at secret key `sk`: `(512·sk)·G1`.
    function _committeeAggregate(uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory out) =
            BLS12_G1MSM.staticcall(abi.encodePacked(genUncompressed, bytes32(SYNC_COMMITTEE_SIZE * sk)));
        assertTrue(ok, "G1MSM aggregate failed");
        assertEq(out.length, 128, "aggregate length");
        return out;
    }

    /// RLP `[pubkeys, aggregate]` committee — the wire shape `_decodeCommittee` expects.
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

    /// A participation bitvector with every one of the 512 bits set (full participation).
    function _allOneBits() internal pure returns (bytes memory bits) {
        bits = new bytes(SYNC_COMMITTEE_SIZE / 8);
        for (uint256 i = 0; i < bits.length; i++) {
            bits[i] = 0xff;
        }
    }

    /// Fold an SSZ leaf up to its root along `gindex`.
    function _foldSsz(bytes32 leaf, bytes32[] memory branch, uint256 gindex) internal pure returns (bytes32) {
        bytes32 computed = leaf;
        uint256 idx = gindex;
        for (uint256 i = 0; i < branch.length; i++) {
            computed = idx & 1 == 1
                ? sha256(abi.encodePacked(branch[i], computed))
                : sha256(abi.encodePacked(computed, branch[i]));
            idx >>= 1;
        }
        return computed;
    }

    /// A window trust anchor `{ C_sk, C_(sk+1) }` whose CURRENT committee belongs to `period`.
    function _windowAnchor(EthMainnetVerifierTestHarness codec, uint64 period, uint256 sk)
        internal
        view
        returns (bytes memory)
    {
        return codec.encodeTrustAnchor(
            EthMainnetVerifier.AnchorScalars({
                gvr: GVR,
                forkVersion: abi.encodePacked(FORK_VERSION),
                channelId: CHANNEL_ID,
                codeHash: SERVICE_CODE_HASH,
                period: period
            }),
            _uncompressedKeys(SYNC_COMMITTEE_SIZE, sk),
            _committeeAggregate(sk),
            _uncompressedKeys(SYNC_COMMITTEE_SIZE, sk + 1),
            _committeeAggregate(sk + 1)
        );
    }

    /// The first slot of sync-committee period `period` (offset so it is never a boundary slot).
    function _slotIn(uint64 period) internal pure returns (uint64) {
        return period * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 17;
    }

    /// RLP-encode an SSZ branch as the verifier's `_decodeBranch` expects: a list of 32-byte strings.
    function _encodeBranch(bytes32[] memory branch) internal pure returns (bytes memory) {
        bytes[] memory enc = new bytes[](branch.length);
        for (uint256 i = 0; i < branch.length; i++) {
            enc[i] = RLP.encode(abi.encodePacked(branch[i]));
        }
        return RLP.encode(enc);
    }

    /// RLP `[nextCommittee, nextCommitteeBranch]` for the committee at secret key `sk`, plus the
    /// beacon stateRoot its synthetic 6-sibling branch folds up to.
    function _rotationPair(uint256 sk, bytes memory key0Override)
        internal
        view
        returns (bytes memory rotationRlp, bytes32 stateRoot)
    {
        bytes[] memory uncompressed = _uncompressedKeys(SYNC_COMMITTEE_SIZE, sk);
        bytes memory aggregate = _committeeAggregate(sk);

        bytes32 committeeRoot =
            _committeeRootFromCompressed(_compressedKeys(SYNC_COMMITTEE_SIZE, sk), ClprBls12381.compressG1(aggregate));
        bytes32[] memory branch = new bytes32[](NEXT_COMMITTEE_BRANCH_DEPTH);
        for (uint256 i = 0; i < NEXT_COMMITTEE_BRANCH_DEPTH; i++) {
            branch[i] = keccak256(abi.encodePacked("next-committee-branch", i));
        }
        stateRoot = _foldSsz(committeeRoot, branch, GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE);

        if (key0Override.length != 0) {
            uncompressed[0] = key0Override;
        }

        bytes[] memory pair = new bytes[](2);
        pair[0] = _encodeCommittee(uncompressed, aggregate);
        pair[1] = _encodeBranch(branch);
        rotationRlp = RLP.encode(pair);
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
