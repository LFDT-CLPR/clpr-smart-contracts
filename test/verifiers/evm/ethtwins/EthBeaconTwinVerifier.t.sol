// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {EthBeaconTwinVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethtwins/EthBeaconTwinVerifier.sol";
import {EthTwinPresets} from "@hiero-ledger/clpr/verifiers/evm/ethtwins/EthTwinPresets.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {MerklePatriciaProof} from "@hiero-ledger/clpr/libraries/proof/evm/MerklePatriciaProof.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes the BLS + rotation internals (for the Gnosis rotation, whose attested block is too old
///      for a non-archive eth_getProof and therefore cannot ride a full bundle).
contract EthBeaconTwinVerifierHarness is EthBeaconTwinVerifier {
    constructor(ChainParams memory p) EthBeaconTwinVerifier(p) {}

    function verifyBlsExt(
        bytes calldata trustAnchor,
        bytes memory nonSignerWrapperRlp,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 gvr
    ) external view {
        Memory.Slice[] memory items = RLP.decodeList(nonSignerWrapperRlp);
        _verifyBls(trustAnchor, items[0], signature, bits, beaconBlockRoot, forkVersion, gvr);
    }

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

/// @notice EthBeaconTwinVerifier on REAL Gnosis (Fulu) and PulseChain (Capella) beacon + execution data,
///         recorded by `npm run ethtwins-live:refresh` (test/e2e/relay/buildEthTwinsLiveProof.ts).
///         Each bundle carries the chain's real sync-committee signature (with real non-signers), the
///         real execution state-root SSZ branch and a real MPT account proof of the chain's beacon
///         deposit contract; the channel slots are absent there, so the storage step checks genuine
///         exclusion proofs. The PulseChain bundle also exists with the real `next_sync_committee`
///         rotation (taken from the same attested state).
contract EthBeaconTwinVerifierTest is Test {
    struct Live {
        bytes proofBytes;
        bytes trustAnchor;
        bytes channelContext;
        bytes committeeRlp;
        bytes rotationProofBytes;
        bytes rotationRlp;
        bytes bits;
        bytes signature;
        bytes accountProofLastNode;
        bytes storageProofFirstNode;
        bytes32 gvr;
        bytes4 forkVersion;
        bytes32 channelId;
        bytes32 codeHash;
        bytes32 executionStateRoot;
        bytes32 rotationAttestedStateRoot;
        bytes32 rotationBeaconBlockRoot;
        bytes rotationBits;
        bytes rotationSignature;
        bytes rotationNonSignerWrapperRlp;
        bytes rotationNextAggregate;
        bytes32 rotationNextCommitteeMerkleRoot;
        uint256 attestedSlot;
        uint256 participants;
    }

    uint256 internal constant ANCHOR_OFF_FORK_VERSION = 32;
    uint256 internal constant ANCHOR_OFF_CHANNEL_ID = 36;
    uint256 internal constant ANCHOR_OFF_AGGREGATE = 68;
    uint256 internal constant ANCHOR_OFF_COMMITTEE_ROOT = 196;
    uint256 internal constant ANCHOR_OFF_CODE_HASH = 228;

    Live internal gno;
    Live internal pls;
    EthBeaconTwinVerifierHarness internal gnosisV;
    EthBeaconTwinVerifierHarness internal pulseV;
    EthMainnetVerifier internal ethV;

    function setUp() public {
        gno = _load("gnosis");
        pls = _load("pulsechain");
        gnosisV = new EthBeaconTwinVerifierHarness(EthTwinPresets.gnosis());
        pulseV = new EthBeaconTwinVerifierHarness(EthTwinPresets.pulsechain());
        ethV = new EthMainnetVerifier();
    }

    // ── Parameters ───────────────────────────────────────────────────────────

    function test_presets_matchRecordedChainIdentity() public view {
        assertEq(gnosisV.GENESIS_VALIDATORS_ROOT(), gno.gvr, "gnosis GVR");
        assertEq(gnosisV.FORK_VERSION(), gno.forkVersion, "gnosis fork version at signature slot");
        assertEq(pulseV.GENESIS_VALIDATORS_ROOT(), pls.gvr, "pulsechain GVR");
        assertEq(pulseV.FORK_VERSION(), pls.forkVersion, "pulsechain fork version at signature slot");
        assertEq(gnosisV.SLOTS_PER_PERIOD(), 8192);
        assertEq(pulseV.SLOTS_PER_PERIOD(), 8192);
        assertEq(gnosisV.EXECUTION_STATE_ROOT_GINDEX(), 802);
        assertEq(gnosisV.NEXT_SYNC_COMMITTEE_GINDEX(), 87);
        assertEq(pulseV.EXECUTION_STATE_ROOT_GINDEX(), 402);
        assertEq(pulseV.NEXT_SYNC_COMMITTEE_GINDEX(), 55);
    }

    function test_constructor_rejectsInvalidParams() public {
        EthBeaconTwinVerifier.ChainParams memory p = EthTwinPresets.pulsechain();
        p.genesisValidatorsRoot = bytes32(0);
        vm.expectRevert(EthBeaconTwinVerifier.InvalidChainParams.selector);
        new EthBeaconTwinVerifier(p);

        p = EthTwinPresets.pulsechain();
        p.slotsPerSyncCommitteePeriod = 0;
        vm.expectRevert(EthBeaconTwinVerifier.InvalidChainParams.selector);
        new EthBeaconTwinVerifier(p);

        p = EthTwinPresets.pulsechain();
        p.executionStateRootGindex = 1;
        vm.expectRevert(EthBeaconTwinVerifier.InvalidChainParams.selector);
        new EthBeaconTwinVerifier(p);

        p = EthTwinPresets.pulsechain();
        p.nextSyncCommitteeGindex = 0;
        vm.expectRevert(EthBeaconTwinVerifier.InvalidChainParams.selector);
        new EthBeaconTwinVerifier(p);
    }

    // ── Live bundles: happy path + gas ───────────────────────────────────────

    function test_gnosis_liveBundle_verifies() public view {
        _assertVerifies(gnosisV, gno, "gnosis");
    }

    function test_pulsechain_liveBundle_verifies() public view {
        _assertVerifies(pulseV, pls, "pulsechain");
    }

    /// A full rotation bundle on real PulseChain data: same signature + storage proof, plus the real
    /// next_sync_committee (512 uncompressed keys) proven at gindex 55 against the attested state.
    function test_pulsechain_liveRotationBundle_verifies() public view {
        Live memory l = pls; // copy out of storage first so the measurement is the verifier's alone
        uint256 g = gasleft();
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            pulseV.verifyBundle(l.rotationProofBytes, l.trustAnchor, l.channelContext);
        uint256 used = g - gasleft();
        assertEq(newAnchor.length, 260, "successor anchor");
        assertEq(newAnchorId, abi.encodePacked(uint64(pls.attestedSlot / 8192 + 1)), "next period id");
        assertEq(_slice(newAnchor, ANCHOR_OFF_AGGREGATE, 128), pls.rotationNextAggregate, "next aggregate");
        assertEq(
            bytes32(_slice(newAnchor, ANCHOR_OFF_COMMITTEE_ROOT, 32)), pls.rotationNextCommitteeMerkleRoot, "next root"
        );
        // Identity, channel and code hash carry through the rotation.
        assertEq(_slice(newAnchor, 0, 68), _slice(pls.trustAnchor, 0, 68), "gvr/fork/channel carried");
        assertEq(_slice(newAnchor, ANCHOR_OFF_CODE_HASH, 32), _slice(pls.trustAnchor, ANCHOR_OFF_CODE_HASH, 32));
        console.log("pulsechain rotation bundle: verifyBundle gas (execution)", used);
        console.log("pulsechain rotation bundle: proofBytes", pls.rotationProofBytes.length);
    }

    /// Gnosis rotation from `light_client/updates`: BLS over the update's attested header with the
    /// current committee, then the next_sync_committee branch at gindex 87.
    function test_gnosis_liveRotation_verifies() public view {
        Live memory l = gno; // copy out of storage first so the measurement is the verifier's alone
        gnosisV.verifyBlsExt(
            l.trustAnchor,
            l.rotationNonSignerWrapperRlp,
            l.rotationSignature,
            l.rotationBits,
            l.rotationBeaconBlockRoot,
            abi.encodePacked(l.forkVersion),
            l.gvr
        );
        uint256 g = gasleft();
        bytes memory newAnchor = gnosisV.verifyRotationExt(
            l.rotationRlp, l.rotationAttestedStateRoot, l.gvr, abi.encodePacked(l.forkVersion), l.channelId, l.codeHash
        );
        console.log("gnosis _verifyRotation gas (execution)", g - gasleft());
        assertEq(_slice(newAnchor, ANCHOR_OFF_AGGREGATE, 128), l.rotationNextAggregate);
        assertEq(bytes32(_slice(newAnchor, ANCHOR_OFF_COMMITTEE_ROOT, 32)), l.rotationNextCommitteeMerkleRoot);
    }

    /// verifyConfig with the real signing committee reproduces the exact anchor the bundle verifies under.
    function test_verifyConfig_liveCommittee_reproducesAnchor() public view {
        _assertConfigAnchor(gnosisV, gno);
        _assertConfigAnchor(pulseV, pls);
    }

    // ── Negative: chain identity / layout ────────────────────────────────────

    function test_verifyConfig_rejectsForeignChainIdentity() public {
        // PulseChain's committee + GVR offered to the Gnosis deployment (and vice versa).
        bytes memory cfg = _config(pls, pls.gvr, pls.forkVersion);
        vm.expectRevert(
            abi.encodeWithSelector(EthBeaconTwinVerifier.ChainIdentityMismatch.selector, pls.gvr, pls.forkVersion)
        );
        gnosisV.verifyConfig(cfg, pls.channelId, "");

        cfg = _config(gno, gno.gvr, gno.forkVersion);
        vm.expectRevert(
            abi.encodeWithSelector(EthBeaconTwinVerifier.ChainIdentityMismatch.selector, gno.gvr, gno.forkVersion)
        );
        pulseV.verifyConfig(cfg, gno.channelId, "");
    }

    function test_verifyConfig_rejectsOtherForkVersionOfSameChain() public {
        // Gnosis's own GVR with the pre-Fulu (Electra) version: not this deployment's signing domain.
        bytes memory cfg = _config(gno, gno.gvr, bytes4(0x05000064));
        vm.expectRevert(
            abi.encodeWithSelector(EthBeaconTwinVerifier.ChainIdentityMismatch.selector, gno.gvr, bytes4(0x05000064))
        );
        gnosisV.verifyConfig(cfg, gno.channelId, "");
    }

    /// The Ethereum-layout verifier (and the Gnosis deployment) reject a Capella bundle: its execution
    /// branch has 8 siblings, not 9.
    function test_pulsechainBundle_rejectedUnderElectraLayout() public {
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        ethV.verifyBundle(pls.proofBytes, pls.trustAnchor, pls.channelContext);
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        gnosisV.verifyBundle(pls.proofBytes, pls.trustAnchor, pls.channelContext);
    }

    /// And the Capella-layout deployment rejects a Fulu bundle (9 siblings, not 8).
    function test_gnosisBundle_rejectedUnderCapellaLayout() public {
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        pulseV.verifyBundle(gno.proofBytes, gno.trustAnchor, gno.channelContext);
    }

    /// Same Fulu layout as Ethereum: the unmodified EthMainnetVerifier also verifies the Gnosis bundle
    /// (the signing domain comes from the anchor) — the twin only adds the identity pin.
    function test_gnosisBundle_alsoVerifiesOnEthMainnetVerifier() public view {
        ethV.verifyBundle(gno.proofBytes, gno.trustAnchor, gno.channelContext);
    }

    // ── Negative: signature / committee ──────────────────────────────────────

    function test_rejectsBadSignature() public {
        bytes memory proof = _corrupt(pls.proofBytes, pls.signature, 200);
        // A flipped coordinate bit leaves the G2 point off the curve: the EIP-2537 precompile rejects
        // it (consuming the gas forwarded to it) before any pairing.
        vm.expectRevert(ClprBeaconBls.BlsPrecompileCallFailed.selector);
        pulseV.verifyBundle(proof, pls.trustAnchor, pls.channelContext);
    }

    function test_rejectsSignatureUnderWrongForkVersion() public {
        bytes memory anchor = bytes.concat(pls.trustAnchor); // copy
        anchor[ANCHOR_OFF_FORK_VERSION + 3] = 0x6b; // 0x0000036b = Bellatrix version
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        pulseV.verifyBundle(pls.proofBytes, anchor, pls.channelContext);
    }

    function test_rejectsBelowSupermajority() public {
        // Clear participation bits until 341/512 remain (one short of ceil(2/3·512) = 342).
        bytes memory bits = bytes.concat(pls.bits);
        uint256 n = pls.participants;
        for (uint256 i = 0; i < 512 && n > 341; i++) {
            uint8 b = uint8(bits[i >> 3]);
            if ((b >> (i & 7)) & 1 == 1) {
                bits[i >> 3] = bytes1(b & ~uint8(1 << (i & 7)));
                n--;
            }
        }
        bytes memory proof = _replace(pls.proofBytes, pls.bits, bits);
        vm.expectRevert(abi.encodeWithSelector(EthMainnetVerifier.InsufficientParticipation.selector, 341, 512));
        pulseV.verifyBundle(proof, pls.trustAnchor, pls.channelContext);
    }

    function test_rejectsWrongValidatorSet() public {
        // PulseChain's real bundle against the real Gnosis committee (anchor bytes 68..228), with
        // PulseChain's identity left in place: the non-signer keys fail the committee Merkle proof.
        bytes memory anchor = bytes.concat(pls.trustAnchor);
        for (uint256 i = ANCHOR_OFF_AGGREGATE; i < ANCHOR_OFF_CODE_HASH; i++) {
            anchor[i] = gno.trustAnchor[i];
        }
        vm.expectPartialRevert(EthMainnetVerifier.NonSignerProofInvalid.selector); // first non-signer
        pulseV.verifyBundle(pls.proofBytes, anchor, pls.channelContext);
    }

    function test_rejectsStaleCommitteeAfterRotation() public {
        // Rotate with the real PulseChain rotation bundle, then replay the same (old-committee) bundle
        // against the successor anchor: the next committee did not sign it.
        (,, bytes memory nextAnchor,,) =
            pulseV.verifyBundle(pls.rotationProofBytes, pls.trustAnchor, pls.channelContext);
        vm.expectPartialRevert(EthMainnetVerifier.NonSignerProofInvalid.selector);
        pulseV.verifyBundle(pls.proofBytes, nextAnchor, pls.channelContext);
    }

    function test_rejectsCrossChainReplay() public {
        // The Gnosis bundle replayed under the PulseChain anchor (different committee and domain).
        vm.expectPartialRevert(EthMainnetVerifier.NonSignerProofInvalid.selector);
        gnosisV.verifyBundle(gno.proofBytes, pls.trustAnchor, gno.channelContext);
    }

    // ── Negative: execution / storage proofs ─────────────────────────────────

    function test_rejectsWrongExecutionStateRoot() public {
        bytes memory proof = _corruptFirst32(pls.proofBytes, abi.encodePacked(pls.executionStateRoot));
        vm.expectRevert(EthMainnetVerifier.ExecutionBranchInvalid.selector);
        pulseV.verifyBundle(proof, pls.trustAnchor, pls.channelContext);
    }

    function test_rejectsWrongAccountProof() public {
        bytes memory proof = _corrupt(pls.proofBytes, pls.accountProofLastNode, 40);
        vm.expectRevert(MerklePatriciaProof.MPTInvalidHashRef.selector);
        pulseV.verifyBundle(proof, pls.trustAnchor, pls.channelContext);
    }

    function test_rejectsWrongStorageProof() public {
        bytes memory proof = _corrupt(gno.proofBytes, gno.storageProofFirstNode, 40);
        vm.expectRevert(MerklePatriciaProof.MPTInvalidHashRef.selector);
        gnosisV.verifyBundle(proof, gno.trustAnchor, gno.channelContext);
    }

    function test_rejectsStorageProofForOtherChannel() public {
        // Another channel id in the anchor → different Channel slots than the ones proven.
        bytes memory anchor = bytes.concat(gno.trustAnchor);
        anchor[ANCHOR_OFF_CHANNEL_ID] = bytes1(uint8(anchor[ANCHOR_OFF_CHANNEL_ID]) ^ 1);
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        gnosisV.verifyBundle(gno.proofBytes, anchor, gno.channelContext);
    }

    function test_rejectsWrongCodeHash() public {
        bytes memory anchor = bytes.concat(pls.trustAnchor);
        anchor[ANCHOR_OFF_CODE_HASH] = bytes1(uint8(anchor[ANCHOR_OFF_CODE_HASH]) ^ 1);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        pulseV.verifyBundle(pls.proofBytes, anchor, pls.channelContext);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _assertVerifies(EthBeaconTwinVerifier v, Live memory l, string memory name) internal view {
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory newAnchor, bytes memory id,) =
            v.verifyBundle(l.proofBytes, l.trustAnchor, l.channelContext);
        uint256 used = g - gasleft();
        assertEq(m.nextMessageId, 0, "exclusion proofs give zero metadata");
        assertEq(payloads.length, 0);
        assertEq(newAnchor.length, 0, "no rotation");
        assertEq(id.length, 0);
        console.log(string.concat(name, " bundle: verifyBundle gas (execution)"), used);
        console.log(string.concat(name, " bundle: participants"), l.participants);
        console.log(string.concat(name, " bundle: proofBytes"), l.proofBytes.length);
    }

    function _assertConfigAnchor(EthBeaconTwinVerifier v, Live memory l) internal view {
        (,,,,, bytes memory anchor, bytes memory anchorId,) =
            v.verifyConfig(_config(l, l.gvr, l.forkVersion), l.channelId, "");
        assertEq(anchor, l.trustAnchor, "config anchor == bundle anchor");
        assertEq(anchorId, abi.encodePacked(uint64(l.attestedSlot / 8192)), "period id");
    }

    function _config(Live memory l, bytes32 gvr, bytes4 forkVersion) internal pure returns (bytes memory) {
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(l.attestedSlot);
        cfg[1] = l.committeeRlp;
        cfg[2] = RLP.encode(abi.encodePacked(gvr));
        cfg[3] = RLP.encode(abi.encodePacked(forkVersion));
        ClprTypes.LedgerConfiguration memory lc;
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(l.codeHash));
        return RLP.encode(cfg);
    }

    function _load(string memory network) internal view returns (Live memory l) {
        string memory json = vm.readFile(_path(network));
        l.proofBytes = vm.parseJsonBytes(json, ".proofBytes");
        l.trustAnchor = vm.parseJsonBytes(json, ".trustAnchor");
        l.channelContext = vm.parseJsonBytes(json, ".channelContext");
        l.committeeRlp = vm.parseJsonBytes(json, ".committeeRlp");
        l.rotationProofBytes = vm.parseJsonBytes(json, ".rotationProofBytes");
        l.rotationRlp = vm.parseJsonBytes(json, ".rotationRlp");
        l.bits = vm.parseJsonBytes(json, ".bits");
        l.signature = vm.parseJsonBytes(json, ".signature");
        l.accountProofLastNode = vm.parseJsonBytes(json, ".accountProofLastNode");
        l.storageProofFirstNode = vm.parseJsonBytes(json, ".storageProofFirstNode");
        l.gvr = vm.parseJsonBytes32(json, ".genesisValidatorsRoot");
        l.forkVersion = bytes4(vm.parseJsonBytes(json, ".forkVersion"));
        l.channelId = vm.parseJsonBytes32(json, ".channelId");
        l.codeHash = vm.parseJsonBytes32(json, ".codeHash");
        l.executionStateRoot = vm.parseJsonBytes32(json, ".executionStateRoot");
        l.rotationAttestedStateRoot = vm.parseJsonBytes32(json, ".rotationAttestedStateRoot");
        l.rotationBeaconBlockRoot = vm.parseJsonBytes32(json, ".rotationBeaconBlockRoot");
        l.rotationBits = vm.parseJsonBytes(json, ".rotationBits");
        l.rotationSignature = vm.parseJsonBytes(json, ".rotationSignature");
        l.rotationNonSignerWrapperRlp = vm.parseJsonBytes(json, ".rotationNonSignerWrapperRlp");
        l.rotationNextAggregate = vm.parseJsonBytes(json, ".rotationNextAggregate");
        l.rotationNextCommitteeMerkleRoot = vm.parseJsonBytes32(json, ".rotationNextCommitteeMerkleRoot");
        l.attestedSlot = vm.parseJsonUint(json, ".attestedSlot");
        l.participants = vm.parseJsonUint(json, ".participants");
    }

    function _path(string memory network) internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/test/verifiers/evm/ethtwins/fixtures/", network, ".json");
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[off + i];
        }
    }

    function _indexOf(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        bytes32 h = keccak256(needle);
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            if (hay[i] == needle[0] && keccak256(_slice(hay, i, needle.length)) == h) return i;
        }
        revert("needle not found");
    }

    /// Copy of `hay` with one bit flipped at byte `at` of the first occurrence of `needle`.
    function _corrupt(bytes memory hay, bytes memory needle, uint256 at) internal pure returns (bytes memory out) {
        out = bytes.concat(hay);
        uint256 i = _indexOf(hay, needle) + at;
        out[i] = bytes1(uint8(out[i]) ^ 1);
    }

    function _corruptFirst32(bytes memory hay, bytes memory needle) internal pure returns (bytes memory) {
        return _corrupt(hay, needle, 31);
    }

    /// Copy of `hay` with the first occurrence of `needle` overwritten by `repl` (same length).
    function _replace(bytes memory hay, bytes memory needle, bytes memory repl)
        internal
        pure
        returns (bytes memory out)
    {
        require(needle.length == repl.length, "length");
        out = bytes.concat(hay);
        uint256 i = _indexOf(hay, needle);
        for (uint256 k = 0; k < repl.length; k++) {
            out[i + k] = repl[k];
        }
    }
}
