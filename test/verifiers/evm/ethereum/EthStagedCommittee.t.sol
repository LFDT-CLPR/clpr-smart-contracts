// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {HederaTraceEstimate} from "@test/verifiers/evm/ethereum/HederaTraceEstimate.sol";

/// @dev Exposes the rotation step (payload items 4 and 5) the way `verifyBundle` slices them.
contract EthStagedCommitteeHarness is EthMainnetVerifier {
    constructor() {}

    function verifyRotationExt(
        bytes memory rotationRlp,
        bytes32 stateRoot,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) external view returns (bytes memory) {
        Memory.Slice[] memory items = RLP.decodeList(rotationRlp);
        return _verifyRotation(items[0], items[1], stateRoot, gvr, forkVersion, channelId, codeHash);
    }
}

/// @notice Staged committee input of EthMainnetVerifier ({stageCommitteeChunk} + the `[chunkRoots16,
///         aggregate]` committee form): parity with the full 512-key form for both verifyConfig and the
///         rotation step, the staging guards, gas, and Hedera trace-size estimates of every Hedera-side
///         transaction the staged flow uses.
/// @dev The committee is 512 DISTINCT valid G1 points, key i = (i + 1)·G1 (G1MSM), aggregate = Σ = 131,328·G1,
///      so a chunk-order or chunk-content mistake cannot cancel out the way it could with 512 equal keys.
contract EthStagedCommitteeTest is EthCommitteeFixtures, HederaTraceEstimate {
    bytes32 internal constant GVR = bytes32(uint256(0x9999));
    bytes4 internal constant FORK_VERSION = 0x06000000;
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC04EC));
    bytes32 internal constant CODE_HASH = bytes32(uint256(0xC0DE));
    uint256 internal constant CHUNK_KEYS = 32;
    uint256 internal constant CHUNKS = 16;

    EthStagedCommitteeHarness internal verifier;
    bytes[] internal keys;
    bytes internal aggregate;

    function setUp() public override {
        super.setUp();
        verifier = new EthStagedCommitteeHarness();
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            keys.push(_mulGen(i + 1));
        }
        aggregate = _mulGen((SYNC_COMMITTEE_SIZE * (SYNC_COMMITTEE_SIZE + 1)) / 2);
    }

    // ── chunk roots are the level-5 nodes of both committee trees ────────────

    function test_chunkRoots_foldToBothCommitteeRoots() public view {
        bytes32[] memory merkleNodes = new bytes32[](CHUNKS);
        bytes32[] memory sszNodes = new bytes32[](CHUNKS);
        for (uint256 c = 0; c < CHUNKS; c++) {
            (merkleNodes[c], sszNodes[c]) = verifier.committeeChunkRoots(_chunk(c));
        }
        assertEq(ClprCommitteeMerkle.fold(merkleNodes), ClprCommitteeMerkle.root(keys), "keccak committee root");
        assertEq(
            ClprBeaconSsz.syncCommitteeRootFromPubkeysRoot(ClprBeaconSsz.merkleize(sszNodes), aggregate),
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            "SSZ committee root"
        );
        // and the SSZ root equals the independent compressed-key reference
        bytes[] memory compressed = new bytes[](SYNC_COMMITTEE_SIZE);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            compressed[i] = _compress(keys[i]);
        }
        assertEq(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            _committeeRootFromCompressed(compressed, _compress(aggregate)),
            "SSZ root vs compressed reference"
        );
    }

    // ── parity with the full form ─────────────────────────────────────────────

    function test_stagedRotation_parityWithFullRotation() public {
        bytes32[] memory branch = _branch();
        bytes32 stateRoot = _fold(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            branch,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE
        );
        bytes memory full = verifier.verifyRotationExt(
            _rotation(_fullCommittee(), branch), stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, CODE_HASH
        );
        _stageAll();
        bytes memory staged = verifier.verifyRotationExt(
            _rotation(_stagedCommittee(), branch), stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, CODE_HASH
        );
        assertEq(staged.length, 260, "anchor length");
        assertEq(staged, full, "staged rotation anchor == full rotation anchor");
        assertEq(
            staged,
            abi.encodePacked(GVR, FORK_VERSION, CHANNEL_ID, aggregate, ClprCommitteeMerkle.root(keys), CODE_HASH),
            "anchor layout"
        );
    }

    function test_stagedConfig_parityWithFullConfig() public {
        bytes memory fullCfg = _config(_fullCommittee());
        _stageAll();
        bytes memory stagedCfg = _config(_stagedCommittee());
        (
            bytes memory ctxA,
            string memory chainA,
            bytes memory svcA,
            uint96 nanosA,
            ClprTypes.Throttles memory thrA,
            bytes memory anchorA,
            bytes memory idA,
            ClprTypes.ClprEndpointManifest memory mA
        ) = verifier.verifyConfig(fullCfg, CHANNEL_ID, "");
        (
            bytes memory ctxB,
            string memory chainB,
            bytes memory svcB,
            uint96 nanosB,
            ClprTypes.Throttles memory thrB,
            bytes memory anchorB,
            bytes memory idB,
            ClprTypes.ClprEndpointManifest memory mB
        ) = verifier.verifyConfig(stagedCfg, CHANNEL_ID, "");
        assertEq(ctxB, ctxA, "channel context");
        assertEq(chainB, chainA, "chain id");
        assertEq(svcB, svcA, "service address");
        assertEq(nanosB, nanosA, "config nanos");
        assertEq(abi.encode(thrB), abi.encode(thrA), "throttles");
        assertEq(anchorB, anchorA, "trust anchor");
        assertEq(idB, idA, "trust anchor id");
        assertEq(abi.encode(mB), abi.encode(mA), "endpoint manifest");
        assertEq(idA, abi.encodePacked(uint64(1377)), "period id");
    }

    // ── staging ───────────────────────────────────────────────────────────────

    function test_stageCommitteeChunk_recordsRootsOnce() public {
        bytes memory chunk = _chunk(3);
        (bytes32 root, bytes32 ssz) = verifier.committeeChunkRoots(chunk);
        assertEq(verifier.stagedCommitteeChunk(root), bytes32(0), "not staged yet");

        vm.expectEmit(true, true, false, true, address(verifier));
        emit EthMainnetVerifier.CommitteeChunkStaged(root, ssz, address(this));
        (bytes32 r1, bytes32 s1) = verifier.stageCommitteeChunk(chunk);
        assertEq(r1, root);
        assertEq(s1, ssz);
        assertEq(verifier.stagedCommitteeChunk(root), ssz, "recorded");

        vm.recordLogs();
        verifier.stageCommitteeChunk(chunk); // idempotent: no second record, no event
        assertEq(vm.getRecordedLogs().length, 0, "no event on re-stage");
        assertEq(verifier.stagedCommitteeChunk(root), ssz);
    }

    function test_stageCommitteeChunk_revertsOnWrongLength() public {
        vm.expectRevert(EthMainnetVerifier.CommitteeChunkInvalid.selector);
        verifier.stageCommitteeChunk(new bytes(31 * 128));
        vm.expectRevert(EthMainnetVerifier.CommitteeChunkInvalid.selector);
        verifier.stageCommitteeChunk(abi.encodePacked(_chunk(0), hex"00"));
    }

    function test_stageCommitteeChunk_revertsOnOffCurveKey() public {
        bytes memory chunk = _chunk(5);
        chunk[17 * 128 + 127] = bytes1(uint8(chunk[17 * 128 + 127]) ^ 0x01); // key 17: y + 1 (or − 1) ⇒ off curve
        vm.expectRevert(ClprBeaconBls.BlsPointNotOnCurveG1.selector);
        verifier.stageCommitteeChunk(chunk);
    }

    function test_stagedCommittee_revertsOnUnstagedChunk() public {
        _stageAll();
        bytes32[] memory roots = _chunkRootList();
        roots[9] = keccak256("never staged");
        bytes memory committee = _stagedCommitteeFrom(roots, aggregate);
        vm.expectRevert(abi.encodeWithSelector(EthMainnetVerifier.CommitteeChunkNotStaged.selector, 9, roots[9]));
        verifier.verifyConfig(_config(committee), CHANNEL_ID, "");
        vm.expectRevert(abi.encodeWithSelector(EthMainnetVerifier.CommitteeChunkNotStaged.selector, 9, roots[9]));
        verifier.verifyRotationExt(
            _rotation(committee, _branch()), bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, CODE_HASH
        );
    }

    /// Chunk order is positional in both trees: swapping two staged chunks changes the SSZ root, so the
    /// beacon branch rejects it.
    function test_stagedRotation_revertsOnSwappedChunks() public {
        _stageAll();
        bytes32[] memory branch = _branch();
        bytes32 stateRoot = _fold(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            branch,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE
        );
        bytes32[] memory roots = _chunkRootList();
        (roots[2], roots[3]) = (roots[3], roots[2]);
        vm.expectRevert(EthMainnetVerifier.NextCommitteeBranchInvalid.selector);
        verifier.verifyRotationExt(
            _rotation(_stagedCommitteeFrom(roots, aggregate), branch),
            stateRoot,
            GVR,
            abi.encodePacked(FORK_VERSION),
            CHANNEL_ID,
            CODE_HASH
        );
    }

    /// A different (on-curve) aggregate changes the SSZ root: rejected by the branch.
    function test_stagedRotation_revertsOnWrongAggregate() public {
        _stageAll();
        bytes32[] memory branch = _branch();
        bytes32 stateRoot = _fold(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            branch,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE
        );
        bytes memory rotation = _rotation(_stagedCommitteeFrom(_chunkRootList(), _mulGen(7)), branch);
        vm.expectRevert(EthMainnetVerifier.NextCommitteeBranchInvalid.selector);
        verifier.verifyRotationExt(rotation, stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, CODE_HASH);
    }

    function test_stagedCommittee_revertsOnOffCurveAggregate() public {
        _stageAll();
        bytes memory bad = aggregate;
        bad[127] = bytes1(uint8(bad[127]) ^ 0x01);
        bytes memory cfg = _config(_stagedCommitteeFrom(_chunkRootList(), bad));
        vm.expectRevert(ClprBeaconBls.BlsPointNotOnCurveG1.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_stagedCommittee_revertsOnWrongChunkCount() public {
        _stageAll();
        bytes32[] memory all = _chunkRootList();
        bytes32[] memory fifteen = new bytes32[](15);
        for (uint256 i = 0; i < 15; i++) {
            fifteen[i] = all[i];
        }
        vm.expectRevert(EthMainnetVerifier.InvalidCommittee.selector);
        verifier.verifyConfig(_config(_stagedCommitteeFrom(fifteen, aggregate)), CHANNEL_ID, "");
    }

    // ── gas and Hedera trace size ─────────────────────────────────────────────

    /// Gas of each staged step next to the full form, and the Hedera trace-size estimate of every
    /// Hedera-side transaction of the staged flow (see {HederaTraceEstimate}). Each must stay at most
    /// half of `contracts.maxSerializedTraceDataBytes`; the full forms are shown for comparison and
    /// must exceed it.
    function test_gasAndTraceSize_stagedVersusFull() public {
        bytes32[] memory branch = _branch();
        bytes32 stateRoot = _fold(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys, aggregate),
            branch,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE
        );

        // stageCommitteeChunk: called directly (no Service frames).
        uint256 worstChunk;
        uint256 stageGas;
        for (uint256 c = 0; c < CHUNKS; c++) {
            bytes memory data = abi.encodeCall(verifier.stageCommitteeChunk, (_chunk(c)));
            (uint256 est, uint256 gasUsed) = _measure(address(verifier), data, 0);
            if (est > worstChunk) worstChunk = est;
            stageGas = gasUsed;
        }
        console.log("stageCommitteeChunk gas (last chunk):", stageGas);
        console.log("stageCommitteeChunk trace estimate, worst of 16 (B):", worstChunk);
        assertLt(worstChunk, HEDERA_TRACE_LIMIT / 2, "stageCommitteeChunk trace");

        // completeChannel -> verifyConfig, staged config (behind the Service and its logic delegatecall).
        bytes memory cfgCall = abi.encodeCall(verifier.verifyConfig, (_config(_stagedCommittee()), CHANNEL_ID, ""));
        (uint256 cfgEst, uint256 cfgGas) = _measure(address(verifier), cfgCall, SERVICE_WRAPPER_FRAMES);
        console.log("verifyConfig (staged) gas:", cfgGas);
        console.log("completeChannel (staged) trace estimate (B):", cfgEst);
        assertLt(cfgEst, HEDERA_TRACE_LIMIT / 2, "completeChannel trace");

        bytes memory fullCfgCall = abi.encodeCall(verifier.verifyConfig, (_config(_fullCommittee()), CHANNEL_ID, ""));
        (uint256 fullCfgEst, uint256 fullCfgGas) = _measure(address(verifier), fullCfgCall, SERVICE_WRAPPER_FRAMES);
        console.log("verifyConfig (full) gas:", fullCfgGas);
        console.log("completeChannel (full) trace estimate (B):", fullCfgEst);
        assertGt(fullCfgEst, HEDERA_TRACE_LIMIT, "full config exceeds the limit");

        // Rotation step of submitBundle (payload items 4-5 only; the rest of the bundle is measured on
        // real Sepolia data in EthStagedRotationLive.t.sol).
        bytes memory rotCall = abi.encodeCall(
            verifier.verifyRotationExt,
            (
                _rotation(_stagedCommittee(), branch),
                stateRoot,
                GVR,
                abi.encodePacked(FORK_VERSION),
                CHANNEL_ID,
                CODE_HASH
            )
        );
        (uint256 rotEst, uint256 rotGas) = _measure(address(verifier), rotCall, SERVICE_WRAPPER_FRAMES);
        console.log("rotation step (staged) gas:", rotGas);
        console.log("rotation step (staged) trace estimate incl. Service frames (B):", rotEst);
        assertLt(rotEst, 16_384, "staged rotation adds under 16 KB");

        bytes memory fullRotCall = abi.encodeCall(
            verifier.verifyRotationExt,
            (_rotation(_fullCommittee(), branch), stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, CODE_HASH)
        );
        (uint256 fullRotEst, uint256 fullRotGas) = _measure(address(verifier), fullRotCall, SERVICE_WRAPPER_FRAMES);
        console.log("rotation step (full) gas:", fullRotGas);
        console.log("rotation step (full) trace estimate incl. Service frames (B):", fullRotEst);
        assertGt(fullRotEst, HEDERA_TRACE_LIMIT, "full rotation exceeds the limit on its own");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _mulGen(uint256 scalar) internal view returns (bytes memory p) {
        (bool ok, bytes memory out) = BLS12_G1MSM.staticcall(abi.encodePacked(genUncompressed, bytes32(scalar)));
        require(ok && out.length == 128, "G1MSM");
        return out;
    }

    function _compress(bytes memory uncompressed) internal pure returns (bytes memory) {
        return ClprBls12381.compressG1(uncompressed);
    }

    function _chunk(uint256 c) internal view returns (bytes memory out) {
        for (uint256 i = 0; i < CHUNK_KEYS; i++) {
            out = abi.encodePacked(out, keys[c * CHUNK_KEYS + i]);
        }
    }

    function _stageAll() internal {
        for (uint256 c = 0; c < CHUNKS; c++) {
            verifier.stageCommitteeChunk(_chunk(c));
        }
    }

    function _chunkRootList() internal view returns (bytes32[] memory roots) {
        roots = new bytes32[](CHUNKS);
        for (uint256 c = 0; c < CHUNKS; c++) {
            (roots[c],) = verifier.committeeChunkRoots(_chunk(c));
        }
    }

    function _fullCommittee() internal view returns (bytes memory) {
        return _encodeCommittee(keys, aggregate);
    }

    function _stagedCommittee() internal view returns (bytes memory) {
        return _stagedCommitteeFrom(_chunkRootList(), aggregate);
    }

    function _stagedCommitteeFrom(bytes32[] memory roots, bytes memory agg) internal pure returns (bytes memory) {
        bytes[] memory enc = new bytes[](roots.length);
        for (uint256 i = 0; i < roots.length; i++) {
            enc[i] = RLP.encode(abi.encodePacked(roots[i]));
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(enc);
        items[1] = RLP.encode(agg);
        return RLP.encode(items);
    }

    function _config(bytes memory committee) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "11155111";
        lc.serviceAddress = abi.encodePacked(address(0xA6DB474E3047C3d43b10a4Ff7AbAD547d89982B9));
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(1377 * 8192 + 100));
        cfg[1] = committee;
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(CODE_HASH));
        return RLP.encode(cfg);
    }

    function _branch() internal pure returns (bytes32[] memory branch) {
        branch = new bytes32[](6);
        for (uint256 i = 0; i < 6; i++) {
            branch[i] = keccak256(abi.encodePacked("next-committee-branch", i));
        }
    }

    function _rotation(bytes memory committee, bytes32[] memory branch) internal pure returns (bytes memory) {
        bytes[] memory enc = new bytes[](branch.length);
        for (uint256 i = 0; i < branch.length; i++) {
            enc[i] = RLP.encode(abi.encodePacked(branch[i]));
        }
        bytes[] memory pair = new bytes[](2);
        pair[0] = committee;
        pair[1] = RLP.encode(enc);
        return RLP.encode(pair);
    }

    function _fold(bytes32 leaf, bytes32[] memory branch, uint256 gindex) internal pure returns (bytes32 computed) {
        computed = leaf;
        for (uint256 i = 0; i < branch.length; i++) {
            computed = gindex & 1 == 1
                ? sha256(abi.encodePacked(branch[i], computed))
                : sha256(abi.encodePacked(computed, branch[i]));
            gindex >>= 1;
        }
    }
}
