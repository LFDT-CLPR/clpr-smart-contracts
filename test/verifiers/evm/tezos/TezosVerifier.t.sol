// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";
import {TezosLightClient} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosLightClient.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosVerifier.sol";
import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";
import {TezosContextProof} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosContextProof.sol";
import {TezosSampler} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosSampler.sol";

/// @dev Exposes the libraries to external calls (fresh memory, catchable reverts).
contract TezosLibHarness {
    function blake256(bytes memory b) external view returns (bytes32) {
        return TezosBlake2b.hash256(b);
    }

    function blake160(bytes memory b) external view returns (bytes20) {
        return TezosBlake2b.hash160(b);
    }

    function contextValue(bytes32 root, bytes[] memory steps, bytes memory proof) external view returns (bytes memory) {
        return TezosContextProof.verify(root, steps, proof, type(uint256).max, bytes32(0));
    }

    /// Signer slots counted until `threshold` (live cost measurement).
    function countSigned(
        bytes memory sampler,
        bytes32 seed,
        uint256 position,
        uint256[] memory signers,
        uint256 committee,
        uint256 threshold
    ) external view returns (uint256 counted, uint256 gasUsed) {
        TezosSampler.Sampler memory s = TezosSampler.parse(sampler);
        bytes memory flags = new bytes(s.n);
        for (uint256 i = 0; i < signers.length; i++) {
            flags[signers[i]] = 0x01;
        }
        gasUsed = gasleft();
        counted = TezosSampler.countSignedSlots(s, seed, position, committee, threshold, flags);
        gasUsed -= gasleft();
    }

    /// Slots in [0, committee) owned by `index` (signer flag set only for it).
    function slotsOf(bytes memory sampler, bytes32 seed, uint256 position, uint256 committee, uint256 index)
        external
        view
        returns (uint256)
    {
        TezosSampler.Sampler memory s = TezosSampler.parse(sampler);
        bytes memory flags = new bytes(s.n);
        flags[index] = 0x01;
        return TezosSampler.countSignedSlots(s, seed, position, committee, committee + 1, flags);
    }
}

/// @notice TezosVerifier on a synthetic Tezos chain (test/verifiers/evm/tezos/fixtures/synthetic.json,
///         regenerate with `npx tsx test/e2e/relay/tezos/buildTezosSynthetic.ts`): five delegates
///         covering tz1/tz2/tz3/tz4 (one tz4 with a DAL companion key), a 100-slot committee with a
///         67-slot threshold, and a CLPR Service big_map. Covers verifyBundle, verifyConfig, the
///         signature cache and the negative cases.
contract TezosVerifierTest is Test {
    string internal j;
    Ed25519Verifier internal ed;
    TezosSignatureCache internal cache;
    TezosVerifier internal v;
    TezosLibHarness internal lib;
    bytes internal ctx;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/tezos/fixtures/synthetic.json"));
        ed = new Ed25519Verifier();
        cache = new TezosSignatureCache(ed);
        lib = new TezosLibHarness();
        TezosLightClient.Profile memory p;
        p.chainId = bytes4(vm.parseJsonBytes(j, ".profile.chainId"));
        p.protocolLevel = uint8(vm.parseJsonUint(j, ".profile.protocolLevel"));
        p.eraFirstLevel = uint32(vm.parseJsonUint(j, ".profile.eraFirstLevel"));
        p.eraFirstCycle = uint32(vm.parseJsonUint(j, ".profile.eraFirstCycle"));
        p.blocksPerCycle = uint32(vm.parseJsonUint(j, ".profile.blocksPerCycle"));
        p.committeeSize = uint16(vm.parseJsonUint(j, ".profile.committeeSize"));
        p.threshold = uint16(vm.parseJsonUint(j, ".profile.threshold"));
        v = new TezosVerifier(
            p,
            ed,
            cache,
            new TezosContextVerifier(),
            vm.parseJsonString(j, ".caip2"),
            vm.parseJsonBytes(j, ".service"),
            vm.parseJsonUint(j, ".bigMapId"),
            uint32(vm.parseJsonUint(j, ".anchorLevel")),
            vm.parseJsonBytes32(j, ".anchorRoot")
        );
        ctx = _ctx(vm.parseJsonBytes32(j, ".channelId"), vm.parseJsonBytes(j, ".service"));
    }

    function _ctx(bytes32 channelId, bytes memory service) internal pure returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: service})
            );
    }

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, key);
    }

    function _fin(string memory key) internal view returns (TezosLightClient.FinalityProof memory) {
        return abi.decode(_b(key), (TezosLightClient.FinalityProof));
    }

    function _bundleWith(TezosLightClient.FinalityProof memory f) internal view returns (bytes memory) {
        TezosVerifier.BundleProof memory b = abi.decode(_b(".bundle"), (TezosVerifier.BundleProof));
        b.finality = f;
        return abi.encode(b);
    }

    // ── happy paths ──────────────────────────────────────────────────────────

    function test_verifyBundle() public view {
        uint256 g = gasleft();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,
            bytes memory naId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyBundle(_b(".bundle"), _b(".anchor"), ctx);
        g -= gasleft();
        assertLt(g, 15_000_000);
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 5);
        assertEq(m.receivedMessageId, 4);
        assertEq(
            m.sentRunningHash,
            bytes32(uint256(0xaa) * 0x0101010101010101010101010101010101010101010101010101010101010101)
        );
        assertEq(
            m.receivedRunningHash,
            bytes32(uint256(0xbb) * 0x0101010101010101010101010101010101010101010101010101010101010101)
        );
        assertEq(m.endpointManifestVersion, 3);
        assertEq(payloads.length, 2);
        assertEq(payloads[0], bytes("payload-one"));
        assertEq(na, _b(".newAnchor"));
        assertEq(naId, abi.encodePacked(uint32(vm.parseJsonUint(j, ".level") - 2)));
        assertEq(man.version, 3);
        assertEq(man.endpoints.length, 1);
        assertEq(man.endpoints[0].port, 50211);
    }

    function test_verifyBundle_withoutManifest() public view {
        (,,,, ClprTypes.ClprEndpointManifest memory man) = v.verifyBundle(_b(".bundleNoManifest"), _b(".anchor"), ctx);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_chainsFromTheNewAnchor() public view {
        // The returned anchor holds the next cycles' rights (the synthetic state carries cycle 5).
        (,, bytes memory na,,) = v.verifyBundle(_b(".bundle"), _b(".anchor"), ctx);
        (uint32 lvl, bytes32 root) = v.decodeAnchor(na);
        assertEq(root, vm.parseJsonBytes32(j, ".stateRoot"));
        assertEq(lvl, vm.parseJsonUint(j, ".level") - 2);
    }

    function test_verifyConfig() public view {
        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory service,
            uint96 nanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(_b(".config"), bytes32(uint256(9)), _b(".configManifest"));
        assertEq(chainId, "tezos:NetXdQprcVkpaWU");
        assertEq(service, _b(".service"));
        assertEq(nanos, uint96(1_790_000_000) * 1e9);
        assertEq(t.maxMessagesPerBundle, 50);
        assertEq(anchor, _b(".newAnchor"));
        assertEq(anchorId.length, 4);
        assertEq(man.version, 3);
        assertEq(channelContext, _ctx(bytes32(uint256(9)), _b(".service")));
    }

    function test_verifyConfig_withoutManifest() public view {
        (,,,,,,, ClprTypes.ClprEndpointManifest memory man) = v.verifyConfig(_b(".config"), bytes32(uint256(9)), "");
        assertEq(man.version, 0);
        assertEq(man.serviceAddress, _b(".service"));
    }

    function test_cachedSignatures() public {
        bytes memory bundle = _bundleWith(_fin(".finalityCached"));
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.SignatureNotCached.selector, 0));
        v.verifyBundle(bundle, _b(".anchor"), ctx);
        cache.record(abi.decode(_b(".cacheEntries"), (TezosSignatureCache.Entry[])));
        (ClprTypes.QueueMetadata memory m,,,,) = v.verifyBundle(bundle, _b(".anchor"), ctx);
        assertEq(m.nextMessageId, 5);
    }

    function test_cache_rejectsBadSignature() public {
        TezosSignatureCache.Entry[] memory es = abi.decode(_b(".cacheEntries"), (TezosSignatureCache.Entry[]));
        es[0].digest = bytes32(uint256(es[0].digest) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(TezosSignatureCache.InvalidSignature.selector, 0));
        cache.record(es);
    }

    function test_cache_rejectsUnsupportedScheme() public {
        TezosSignatureCache.Entry[] memory es = abi.decode(_b(".cacheEntries"), (TezosSignatureCache.Entry[]));
        es[0].scheme = 3;
        vm.expectRevert(abi.encodeWithSelector(TezosSignatureCache.UnsupportedScheme.selector, 0));
        cache.record(es);
    }

    // ── negative cases ───────────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.BadAttestationSignature.selector, 0));
        v.verifyBundle(_bundleWith(_fin(".finalityBadSig")), _b(".anchor"), ctx);
    }

    function test_rejects_belowThreshold() public {
        uint256[] memory power = vm.parseJsonUintArray(j, ".power");
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.QuorumNotReached.selector, power[1] + power[4]));
        v.verifyBundle(_bundleWith(_fin(".finalityWeak")), _b(".anchor"), ctx);
    }

    function test_rejects_wrongValidatorSet() public {
        // Rights proven from an anchor whose sampler holds other keys: the signatures do not match.
        vm.expectRevert();
        v.verifyBundle(_bundleWith(_fin(".finalityAltSet")), _b(".altAnchor"), ctx);
        // The real proofs against the other anchor root do not hash to it.
        vm.expectRevert(abi.encodeWithSelector(TezosContextProof.ProofHashMismatch.selector, 0));
        v.verifyBundle(_b(".bundle"), _b(".altAnchor"), ctx);
    }

    function test_rejects_allBakersAttestScheduled() public {
        // The anchor state records `all_bakers_attest_first_level`: slot rights no longer apply.
        vm.expectRevert(abi.encodeWithSelector(TezosContextProof.ProofEntryPresent.selector, 1));
        v.verifyBundle(_bundleWith(_fin(".finalityAbaa")), _b(".abaaAnchor"), ctx);
    }

    function test_rejects_staleOrReplayed() public {
        // Re-submitting the bundle against the anchor it produced is not "after" that anchor.
        vm.expectRevert(TezosLightClient.NotAfterAnchor.selector);
        v.verifyBundle(_b(".bundle"), _b(".newAnchor"), ctx);
        vm.expectRevert(TezosLightClient.NotAfterAnchor.selector);
        v.verifyBundle(_b(".bundle"), _b(".staleAnchor"), ctx);
    }

    function test_rejects_wrongStorageProof() public {
        // Another channel id: the verifier derives a different big_map key.
        vm.expectRevert();
        v.verifyBundle(_b(".bundle"), _b(".anchor"), _ctx(bytes32(uint256(1)), _b(".service")));
        // A tampered queue proof.
        TezosVerifier.BundleProof memory b = abi.decode(_b(".bundle"), (TezosVerifier.BundleProof));
        b.queueProof[b.queueProof.length - 1] ^= 0x01;
        vm.expectRevert();
        v.verifyBundle(abi.encode(b), _b(".anchor"), ctx);
        // The manifest proof standing in for the queue record (wrong value length).
        b = abi.decode(_b(".bundle"), (TezosVerifier.BundleProof));
        b.queueProof = b.manifestProof;
        vm.expectRevert();
        v.verifyBundle(abi.encode(b), _b(".anchor"), ctx);
    }

    function test_rejects_wrongService() public {
        vm.expectRevert(TezosVerifier.WrongServiceAddress.selector);
        v.verifyBundle(_b(".bundle"), _b(".anchor"), _ctx(vm.parseJsonBytes32(j, ".channelId"), hex"01aa"));
    }

    function test_rejects_wrongStateRoot() public {
        TezosLightClient.FinalityProof memory f = _fin(".finality");
        f.contextRoot = bytes32(uint256(f.contextRoot) ^ 1);
        vm.expectRevert(TezosLightClient.ContextCommitMismatch.selector);
        v.verifyBundle(_bundleWith(f), _b(".anchor"), ctx);
        vm.expectRevert(TezosLightClient.ContextCommitMismatch.selector);
        v.verifyBundle(_bundleWith(_fin(".finalityBadTail")), _b(".anchor"), ctx);
    }

    function test_rejects_wrongPayload() public {
        TezosLightClient.FinalityProof memory f = _fin(".finality");
        f.operationsHash = bytes32(uint256(f.operationsHash) ^ 1); // different payload hash: signatures fail
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.BadAttestationSignature.selector, 0));
        v.verifyBundle(_bundleWith(f), _b(".anchor"), ctx);
    }

    function test_rejects_headerLevelAndProtocol() public {
        vm.expectRevert(TezosLightClient.HeaderLevelMismatch.selector);
        v.verifyBundle(_bundleWith(_fin(".finalityWrongLevel")), _b(".anchor"), ctx);
        vm.expectRevert(TezosLightClient.ProtocolMismatch.selector);
        v.verifyBundle(_bundleWith(_fin(".finalityWrongProto")), _b(".anchor"), ctx);
    }

    function test_rejects_aggregateKeyMismatch() public {
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.BlsKeyMismatch.selector, 0));
        v.verifyBundle(_bundleWith(_fin(".finalityBadAggKey")), _b(".anchor"), ctx);
    }

    function test_rejects_badAggregateSignature() public {
        TezosLightClient.FinalityProof memory f = _fin(".finality");
        f.aggregates[0].signers = new uint16[](1);
        f.aggregates[0].signers[0] = uint16(vm.parseJsonUintArray(j, ".supportIndex")[3]);
        bytes[] memory k = new bytes[](1);
        k[0] = f.aggregates[0].keys[0];
        bytes[] memory d = new bytes[](1);
        d[0] = f.aggregates[0].dal[0];
        bytes[] memory c = new bytes[](1);
        c[0] = f.aggregates[0].companionKeys[0];
        f.aggregates[0].keys = k;
        f.aggregates[0].dal = d;
        f.aggregates[0].companionKeys = c;
        vm.expectRevert(); // one member dropped: the aggregate key no longer matches the signature
        v.verifyBundle(_bundleWith(f), _b(".anchor"), ctx);
    }

    function test_rejects_twoAggregates() public {
        vm.expectRevert(TezosLightClient.TooManyAggregates.selector);
        v.verifyBundle(_bundleWith(_fin(".finalityTwoAggs")), _b(".anchor"), ctx);
    }

    function test_rejects_signerOutOfRange() public {
        TezosLightClient.FinalityProof memory f = _fin(".finality");
        f.attestations[0].signer = 500;
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.SignerOutOfRange.selector, 0));
        v.verifyBundle(_bundleWith(f), _b(".anchor"), ctx);
    }

    function test_rejects_tz2WithWrongY() public {
        TezosLightClient.FinalityProof memory f = _fin(".finality");
        f.attestations[1].y = bytes32(uint256(f.attestations[1].y) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.BadAttestationSignature.selector, 1));
        v.verifyBundle(_bundleWith(f), _b(".anchor"), ctx);
    }

    function test_rejects_configStorageMismatch() public {
        TezosVerifier.ConfigProof memory c = abi.decode(_b(".config"), (TezosVerifier.ConfigProof));
        c.storageProof = c.configProof; // a different context value
        vm.expectRevert();
        v.verifyConfig(abi.encode(c), bytes32(uint256(9)), "");
        c = abi.decode(_b(".config"), (TezosVerifier.ConfigProof));
        c.controlMessage[c.controlMessage.length - 1] ^= 0x01;
        vm.expectRevert(TezosVerifier.ConfigCommitmentMismatch.selector);
        v.verifyConfig(abi.encode(c), bytes32(uint256(9)), "");
    }

    // ── libraries ──────────────────────────────────────────────────────────────

    function test_blake2b_vectors() public view {
        assertEq(lib.blake256(""), 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8);
        assertEq(lib.blake256("abc"), 0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319);
        assertEq(lib.blake256(new bytes(128)), 0x378d0caaaa3855f1b38693c1d6ef004fd118691c95c959d4efa950d6d6fcf7c1);
        bytes memory b = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            b[i] = bytes1(uint8(i));
        }
        assertEq(lib.blake256(b), 0x39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835);
        assertEq(lib.blake160("abc"), bytes20(hex"384264f676f39536840523f284921cdc68b6846b"));
    }

    function test_sampler_matchesOctezDraws() public view {
        uint256[] memory power = vm.parseJsonUintArray(j, ".power");
        uint256[] memory index = vm.parseJsonUintArray(j, ".supportIndex");
        for (uint256 i = 0; i < 5; i++) {
            assertEq(
                lib.slotsOf(
                    _b(".sampler"), vm.parseJsonBytes32(j, ".seed"), vm.parseJsonUint(j, ".position"), 100, index[i]
                ),
                power[i]
            );
        }
    }

    function test_contextProof_valueAndTamper() public view {
        string[] memory s = vm.parseJsonStringArray(j, ".queueSteps");
        bytes[] memory steps = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            steps[i] = bytes(s[i]);
        }
        bytes memory proof = _b(".queueProof");
        bytes memory value = lib.contextValue(vm.parseJsonBytes32(j, ".stateRoot"), steps, proof);
        assertEq(value, abi.encodePacked(hex"0a00000059", _b(".record")));
        // Asking for a directory as if it were the value fails the kind check.
        bytes[] memory shorter = new bytes[](s.length - 1);
        for (uint256 i = 0; i < shorter.length; i++) {
            shorter[i] = steps[i];
        }
        try lib.contextValue(vm.parseJsonBytes32(j, ".stateRoot"), shorter, proof) {
            revert("directory accepted as contents");
        } catch {}
        try lib.contextValue(bytes32(uint256(1)), steps, proof) {
            revert("wrong root accepted");
        } catch {}
    }
}
