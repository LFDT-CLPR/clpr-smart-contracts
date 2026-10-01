// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {AntelopeBls} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeBls.sol";
import {AntelopeClprBase} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeClprBase.sol";
import {SavannaVerifier} from "@hiero-ledger/clpr/verifiers/evm/antelope/SavannaVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {SavannaBuilders} from "./SavannaBuilders.sol";

/// @dev Exposes the QC and policy steps for the live-data checks (Jungle4 QC, see the e2e spec).
contract SavannaVerifierHarness is SavannaVerifier {
    constructor(string memory chainId) SavannaVerifier(chainId) {}

    function parsePolicy(bytes calldata pack)
        external
        pure
        returns (uint32 generation, uint64 threshold, bytes32 digest, uint256 finalizers)
    {
        Policy memory p = _parsePolicy(pack);
        return (p.generation, p.threshold, p.digest, p.weights.length);
    }

    /// @dev qc = RLP([bitset, sig192]).
    function verifyStrongQc(bytes calldata pack, bytes calldata qc, bytes32 digest) external view {
        bytes memory q = qc;
        _verifyStrongQc(_parsePolicy(pack), RLP.decodeList(q), digest);
    }
}

/// @notice SavannaVerifier on synthetic Savanna data: real BLS12-381 keys and aggregate signatures
///         (EIP-2537 G1MSM/G2MSM, Spring encodings), finality digests, finality leaves and Merkle
///         trees built exactly as Spring 1.2.2 builds them.
contract SavannaVerifierTest is SavannaBuilders {
    SavannaVerifierHarness internal verifier;

    function setUp() public {
        verifier = new SavannaVerifierHarness(CHAIN_ID);
        _initPolicies();
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_verifyBundle_provesQueueState() public view {
        bytes memory proof = _simpleBundle(_queueTarget());
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId,
            ClprTypes.ClprEndpointManifest memory manifest
        ) = verifier.verifyBundle(proof, _anchor(g1), _context());
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 7);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedMessageId, 3);
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(m.endpointManifestVersion, 1);
        assertEq(payloads.length, 2);
        assertEq(payloads[1], hex"0d0e0f10");
        assertEq(newAnchor.length, 0);
        assertEq(newAnchorId.length, 0);
        assertEq(manifest.version, 0);
    }

    function test_verifyBundle_bindsManifestToQueueState() public {
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 3;
        mf.serviceAddress = _serviceAddress();
        bytes memory manifest = ClprProtobuf.encodeEndpointManifest(mf);
        bytes memory ret = _queueState(CHANNEL, 1, 7, keccak256("sent"), 3, keccak256("recv"), 3, keccak256(manifest));
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"), abi.encodePacked(CHANNEL), ret, SERVICE_NAME, 1
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        bytes memory proof = _bundle(g1.pack, "", new bytes[](0), fin, t, manifest);
        (,,,, ClprTypes.ClprEndpointManifest memory got) = verifier.verifyBundle(proof, _anchor(g1), _context());
        assertEq(got.version, 3);
        assertEq(got.serviceAddress, _serviceAddress());

        // A different manifest preimage does not match the proven commitment.
        mf.version = 4;
        proof = _bundle(g1.pack, "", new bytes[](0), fin, t, ClprProtobuf.encodeEndpointManifest(mf));
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        verifier.verifyBundle(proof, _anchor(g1), _context());
    }

    function test_verifyBundle_exactThresholdPasses() public view {
        Target memory t = _queueTarget();
        uint256 mask = (uint256(1) << THRESHOLD) - 1; // exactly 15 of 21
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, mask);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev Rotation: C1 carries pending policy g2 (strong under g1 and g2); the bundle's finality
    ///      proof is under g2 (active_gen = 2), which promotes it. The anchor moves to g2.
    function test_verifyBundle_rotation() public view {
        Target memory t = _queueTarget();
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _finalityPendingRlp(_fin(sha256("C1 root"), 1, 2), g1, g2);
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 2, 2), g2, ALL_BUT_ONE);
        bytes memory proof = _bundle(g1.pack, "", rotations, fin, t, "");
        (,, bytes memory newAnchor, bytes memory newAnchorId,) = verifier.verifyBundle(proof, _anchor(g1), _context());
        assertEq(newAnchor, _anchor(g2));
        assertEq(newAnchorId, abi.encodePacked(uint32(2)));
    }

    /// @dev A proof that only records a pending policy returns an anchor with that pending policy;
    ///      the next bundle carries it and promotes it.
    function test_verifyBundle_pendingThenPromote() public view {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityPendingRlp(_fin(t.finalityMroot, 1, 2), g1, g2);
        bytes memory proof = _bundle(g1.pack, "", new bytes[](0), fin, t, "");
        (,, bytes memory anchor1,,) = verifier.verifyBundle(proof, _anchor(g1), _context());
        assertEq(anchor1, abi.encode(uint32(1), g1.digest, uint32(2), g2.digest));

        bytes memory fin2 = _finalityRlp(_fin(t.finalityMroot, 2, 2), g2, ALL_BUT_ONE);
        bytes memory proof2 = _bundle(g1.pack, g2.pack, new bytes[](0), fin2, t, "");
        (,, bytes memory anchor2,,) = verifier.verifyBundle(proof2, anchor1, _context());
        assertEq(anchor2, _anchor(g2));
    }

    function test_verifyConfig() public view {
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "ledgerconfig", "relayer"), "", _ledgerConfigReturn(CHAIN_ID), SERVICE_NAME, 9
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        bytes[] memory c = new bytes[](4);
        c[0] = _rlpBytes(g1.pack);
        c[1] = fin;
        c[2] = _blockRlp(t);
        c[3] = _actionRlp(t);
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory serviceAddress,,
            ClprTypes.Throttles memory th,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory mf
        ) = verifier.verifyConfig(_rlpList(c), CHANNEL, "");
        assertEq(chainId, CHAIN_ID);
        assertEq(serviceAddress, _serviceAddress());
        assertEq(ctx, _context());
        assertEq(th.maxMessagesPerBundle, 10);
        assertEq(anchor, _anchor(g1));
        assertEq(anchorId, abi.encodePacked(uint32(1)));
        assertEq(mf.version, 0);
    }

    function test_verifyConfig_rejectsOtherChain() public {
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "ledgerconfig", "relayer"),
            "",
            _ledgerConfigReturn("antelope:4667b205c6838ef70ff7988f6e8257e8"),
            SERVICE_NAME,
            9
        );
        bytes[] memory c = new bytes[](4);
        c[0] = _rlpBytes(g1.pack);
        c[1] = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        c[2] = _blockRlp(t);
        c[3] = _actionRlp(t);
        vm.expectRevert(
            abi.encodeWithSelector(AntelopeClprBase.WrongChain.selector, "antelope:4667b205c6838ef70ff7988f6e8257e8")
        );
        verifier.verifyConfig(_rlpList(c), CHANNEL, "");
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        Target memory t = _queueTarget();
        Fin memory f = _fin(t.finalityMroot, 1, 1);
        bytes32 wrong = _finalityDigest(_fin(sha256("other root"), 1, 1), g1.digest);
        bytes memory fin = _finalityRlpRaw(f, _qc(g1, ALL_BUT_ONE, ALL_BUT_ONE, wrong), "", _rlpEmptyList());
        vm.expectRevert(AntelopeBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_belowThreshold() public {
        Target memory t = _queueTarget();
        uint256 mask = (uint256(1) << (THRESHOLD - 1)) - 1; // 14 of 21
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, mask);
        vm.expectRevert(abi.encodeWithSelector(SavannaVerifier.QcBelowThreshold.selector, 14, THRESHOLD));
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev The bitset claims 20 voters but only 19 signed: the aggregate key does not match.
    function test_rejects_bitsetClaimsNonSigner() public {
        Target memory t = _queueTarget();
        Fin memory f = _fin(t.finalityMroot, 1, 1);
        bytes32 digest = _finalityDigest(f, g1.digest);
        uint256 signers = ALL_BUT_ONE & ~uint256(1);
        bytes memory fin = _finalityRlpRaw(f, _qc(g1, ALL_BUT_ONE, signers, digest), "", _rlpEmptyList());
        vm.expectRevert(AntelopeBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev A QC by a different finalizer set, carried with that set's policy: the anchor pins g1.
    function test_rejects_wrongFinalizerSet() public {
        Target memory t = _queueTarget();
        Pol memory rogue = _mkPolicy(1, 999, THRESHOLD);
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), rogue, ALL_BUT_ONE);
        vm.expectRevert(SavannaVerifier.PolicyMismatch.selector);
        verifier.verifyBundle(_bundle(rogue.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev Same policy pack, but the QC is signed by other keys: BLS fails.
    function test_rejects_signatureByOtherKeys() public {
        Target memory t = _queueTarget();
        Pol memory rogue = _mkPolicy(1, 999, THRESHOLD);
        Fin memory f = _fin(t.finalityMroot, 1, 1);
        bytes32 digest = _finalityDigest(f, g1.digest);
        bytes memory fin = _finalityRlpRaw(f, _qc(rogue, ALL_BUT_ONE, ALL_BUT_ONE, digest), "", _rlpEmptyList());
        vm.expectRevert(AntelopeBls.BlsSignatureInvalid.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_unknownGeneration() public {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 2, 2), g2, ALL_BUT_ONE);
        vm.expectRevert(abi.encodeWithSelector(SavannaVerifier.UnknownPolicyGeneration.selector, 2));
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev After rotating to g2, a bundle proven under g1 is stale.
    function test_rejects_staleProofAfterRotation() public {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        vm.expectRevert(SavannaVerifier.PolicyMismatch.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g2), _context());
        vm.expectRevert(abi.encodeWithSelector(SavannaVerifier.UnknownPolicyGeneration.selector, 1));
        verifier.verifyBundle(_bundle(g2.pack, "", new bytes[](0), fin, t, ""), _anchor(g2), _context());
    }

    function test_rejects_pendingWithoutPendingQc() public {
        Target memory t = _queueTarget();
        Fin memory f = _fin(t.finalityMroot, 1, 2);
        bytes32 digest = _finalityDigest(f, g2.digest);
        bytes memory fin = _finalityRlpRaw(f, _qc(g1, ALL_BUT_ONE, ALL_BUT_ONE, digest), g2.pack, _rlpEmptyList());
        vm.expectRevert(AntelopeClprBase.InvalidPayloadShape.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_wrongFinalitySibling() public {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        t.fSibs[3] = bytes32(uint256(t.fSibs[3]) ^ 1);
        vm.expectRevert(SavannaVerifier.FinalityRootMismatch.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_tamperedReturnValue() public {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        t.ret = _queueState(CHANNEL, 1, 8, keccak256("sent"), 3, keccak256("recv"), 1, bytes32(0));
        vm.expectRevert(SavannaVerifier.FinalityRootMismatch.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_wrongLeafIndex() public {
        Target memory t = _queueTarget();
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        t.aIndex = 4;
        vm.expectRevert(SavannaVerifier.FinalityRootMismatch.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_otherAccountsAction() public {
        Target memory t = _target(
            _actionBase("eosio.token", "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _defaultQueueState(),
            "eosio.token",
            1
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        uint64 tok = AntelopeLib.nameValue("eosio.token");
        vm.expectRevert(abi.encodeWithSelector(AntelopeClprBase.NotServiceAction.selector, tok, tok));
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    /// @dev A notification copy of the service's action (receiver != account) does not count.
    function test_rejects_notificationReceipt() public {
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _defaultQueueState(),
            "relayer",
            1
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        vm.expectRevert(
            abi.encodeWithSelector(
                AntelopeClprBase.NotServiceAction.selector,
                AntelopeLib.nameValue("relayer"),
                AntelopeLib.nameValue(SERVICE_NAME)
            )
        );
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_otherChannel() public {
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(bytes32(uint256(0xBAD))),
            _defaultQueueState(),
            SERVICE_NAME,
            1
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        vm.expectRevert(AntelopeClprBase.WrongActionData.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    function test_rejects_unsafeThreshold() public {
        uint256[] memory sks = new uint256[](N);
        for (uint256 i = 0; i < N; ++i) {
            sks[i] = _blsSecret(300 + i);
        }
        bytes memory pack = _packPolicy(1, 14, sks); // 14 * 3 <= 21 * 2
        vm.expectRevert(abi.encodeWithSelector(SavannaVerifier.PolicyThresholdUnsafe.selector, 14, 21));
        verifier.parsePolicy(pack);
    }

    function test_rejects_malformedBitset() public {
        Target memory t = _queueTarget();
        Fin memory f = _fin(t.finalityMroot, 1, 1);
        bytes32 digest = _finalityDigest(f, g1.digest);
        bytes memory bits = _bitset(ALL_BUT_ONE);
        bits[2] = bytes1(uint8(bits[2]) | 0x80); // bit 23 does not exist (21 finalizers)
        bytes memory qc = _rlpList(_l2(_rlpBytes(bits), _rlpBytes(_blsSign(_skSum(g1, ALL_BUT_ONE), digest))));
        bytes memory fin = _finalityRlpRaw(f, qc, "", _rlpEmptyList());
        vm.expectRevert(SavannaVerifier.QcBitsetMalformed.selector);
        verifier.verifyBundle(_bundle(g1.pack, "", new bytes[](0), fin, t, ""), _anchor(g1), _context());
    }

    // ── Live Jungle4 (Vaulta testnet) data ──────────────────────────────────

    function _jungle4() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/antelope/fixtures/vaulta-jungle4.json"));
    }

    /// @dev The live finalizer policy (get_finalizer_info) packs to the digest the snapshot's
    ///      block state records as last_pending_finalizer_policy_digest.
    function test_live_jungle4_policy() public view {
        string memory j = _jungle4();
        (uint32 gen, uint64 threshold, bytes32 digest, uint256 n) =
            verifier.parsePolicy(vm.parseJsonBytes(j, ".policyPack"));
        assertEq(gen, vm.parseJsonUint(j, ".generation"));
        assertEq(threshold, vm.parseJsonUint(j, ".threshold"));
        assertEq(n, vm.parseJsonUint(j, ".finalizers"));
        assertEq(digest, vm.parseJsonBytes32(j, ".policyDigest"));
    }

    /// @dev Real QCs from Jungle4 block headers verify against the finality digests the snapshot
    ///      records for the certified blocks.
    function test_live_jungle4_qcs() public view {
        string memory j = _jungle4();
        bytes memory pack = vm.parseJsonBytes(j, ".policyPack");
        for (uint256 i = 0; i < 2; ++i) {
            string memory k = string.concat(".qcs[", vm.toString(i), "]");
            bytes memory qc = vm.parseJsonBytes(j, string.concat(k, ".qc"));
            bytes32 digest = vm.parseJsonBytes32(j, string.concat(k, ".digest"));
            uint256 g0 = gasleft();
            verifier.verifyStrongQc(pack, qc, digest);
            console.log(
                "Jungle4 live QC on block",
                vm.parseJsonUint(j, string.concat(k, ".certifiedBlock")),
                "gas:",
                g0 - gasleft()
            );
        }
    }

    function test_live_jungle4_rejectsOtherDigest() public {
        string memory j = _jungle4();
        bytes memory pack = vm.parseJsonBytes(j, ".policyPack");
        bytes memory qc = vm.parseJsonBytes(j, ".qcs[1].qc");
        bytes32 otherDigest = vm.parseJsonBytes32(j, ".qcs[0].digest");
        vm.expectRevert(AntelopeBls.BlsSignatureInvalid.selector);
        verifier.verifyStrongQc(pack, qc, otherDigest);
    }

    function test_live_jungle4_rejectsDroppedVoter() public {
        string memory j = _jungle4();
        bytes memory pack = vm.parseJsonBytes(j, ".policyPack");
        bytes memory qc = vm.parseJsonBytes(j, ".qcs[1].qc");
        bytes32 digest = vm.parseJsonBytes32(j, ".qcs[1].digest");
        Memory.Slice[] memory q = RLP.decodeList(qc);
        bytes memory bits = RLP.readBytes(q[0]);
        bits[0] = bytes1(uint8(bits[0]) & 0xFE);
        vm.expectRevert(AntelopeBls.BlsSignatureInvalid.selector);
        verifier.verifyStrongQc(pack, _rlpList(_l2(_rlpBytes(bits), _rlpBytes(RLP.readBytes(q[1])))), digest);
    }

    // ── Library checks ────────────────────────────────────────────────────────

    /// @dev savannaMerkleRoot (index/count walk) equals the layered promote-odd tree for every
    ///      leaf of trees of 1..33 leaves.
    function test_savannaMerkle_matchesLayeredTree() public pure {
        for (uint256 n = 1; n <= 33; ++n) {
            bytes32[] memory leaves = _filler(n, n);
            bytes32 root = _savannaRoot(leaves);
            for (uint256 i = 0; i < n; ++i) {
                assertEq(AntelopeLib.savannaMerkleRoot(leaves[i], i, n, _savannaProof(leaves, i)), root);
            }
        }
    }

    function test_legacyMerkle_matchesLayeredTree() public pure {
        for (uint256 n = 1; n <= 33; ++n) {
            bytes32[] memory leaves = _filler(n, n + 100);
            bytes32 root = _legacyRoot(leaves);
            for (uint256 i = 0; i < n; ++i) {
                assertEq(AntelopeLib.legacyMerkleRoot(leaves[i], i, n, _legacyProof(leaves, i)), root);
            }
        }
    }

    function test_names() public pure {
        assertEq(AntelopeLib.nameValue("eosio"), 0x5530ea0000000000);
        assertEq(AntelopeLib.nameValue("eosio.token"), 0x5530ea033482a600);
        assertEq(AntelopeLib.nameValue("queuestate"), 0xb695a56326ca8000);
    }

    // ── Gas ───────────────────────────────────────────────────────────────────

    function test_gas_verifyBundle_21finalizers() public view {
        bytes memory proof = _simpleBundle(_queueTarget());
        bytes memory cd = abi.encodeCall(SavannaVerifier.verifyBundle, (proof, _anchor(g1), _context()));
        uint256 g0 = gasleft();
        verifier.verifyBundle(proof, _anchor(g1), _context());
        uint256 used = g0 - gasleft();
        console.log("Savanna verifyBundle (21 finalizers, 20 votes, 28-level finality proof) gas:", used);
        console.log("  proofBytes:", proof.length, "calldata:", cd.length);
        assertLt(used, 15_000_000);
        assertLt(cd.length, 128 * 1024);
    }

    function test_gas_verifyBundle_rotation() public view {
        Target memory t = _queueTarget();
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _finalityPendingRlp(_fin(sha256("C1 root"), 1, 2), g1, g2);
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 2, 2), g2, ALL_BUT_ONE);
        bytes memory proof = _bundle(g1.pack, "", rotations, fin, t, "");
        bytes memory cd = abi.encodeCall(SavannaVerifier.verifyBundle, (proof, _anchor(g1), _context()));
        uint256 g0 = gasleft();
        verifier.verifyBundle(proof, _anchor(g1), _context());
        uint256 used = g0 - gasleft();
        console.log("Savanna verifyBundle with one policy rotation (3 QCs) gas:", used);
        console.log("  proofBytes:", proof.length, "calldata:", cd.length);
        assertLt(used, 15_000_000);
        assertLt(cd.length, 128 * 1024);
    }
}
