// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {StacksTestBuilder} from "./StacksTestBuilder.sol";
import {ClprSha512t256Hasher} from "../../../src/libraries/crypto/ClprSha512t256Hasher.sol";
import {StacksVerifier} from "../../../src/verifiers/stacks/StacksVerifier.sol";
import {StacksMarf} from "../../../src/libraries/proof/stacks/StacksMarf.sol";
import {NakamotoHeader} from "../../../src/libraries/proof/stacks/NakamotoHeader.sol";
import {ClarityCodec} from "../../../src/libraries/proof/stacks/ClarityCodec.sol";
import {ClprTypes} from "../../../src/libraries/ClprTypes.sol";
import {ClprProtobuf} from "../../../src/libraries/codec/ClprProtobuf.sol";

/// @notice StacksVerifier on recorded Stacks mainnet data (test/e2e/fixtures/stacks-live/mainnet.json,
///         refresh with `npm run stacks-live:refresh`) and on synthetic CLPR queue records.
///
/// Live: the reward-cycle N set signs the block that wrote `.signers` cycle-signer-set[N+1]
/// (registerRotation), then cycle N+1 blocks prove a real Clarity map entry with 1, 2 and 3 MARF
/// segments. Synthetic: no Clarity CLPR service is deployed on Stacks, so the queue-record path
/// (verifyConfig, verifyBundle) runs on a builder that emits the same wire formats.
contract StacksVerifierTest is StacksTestBuilder {
    string internal constant FIXTURE = "test/e2e/fixtures/stacks-live/mainnet.json";
    string internal constant SIGNERS = "SP000000000000000000002Q6VF78.signers";
    bytes internal constant SERVICE = "SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.clpr-service";

    string internal json;
    uint256 internal fromCycle;
    uint256 internal toCycle;
    StacksVerifier internal live; // genesis = live cycle N set

    function setUp() public {
        hasher = address(new ClprSha512t256Hasher());
        json = vm.readFile(FIXTURE);
        fromCycle = vm.parseJsonUint(json, ".cycles.current");
        toCycle = vm.parseJsonUint(json, ".cycles.next");
        live = new StacksVerifier(hasher, "stacks:1", SIGNERS, 22, _liveSet(fromCycle));
    }

    // ── live fixture helpers ─────────────────────────────────────────────────

    function _liveSet(uint256 cycle) internal view returns (StacksVerifier.SignerSet memory s) {
        string memory k = string.concat(".signerSets.", vm.toString(cycle));
        s.cycle = uint64(cycle);
        s.signers = vm.parseJsonAddressArray(json, string.concat(k, ".addresses"));
        uint256[] memory w = vm.parseJsonUintArray(json, string.concat(k, ".weights"));
        s.weights = new uint64[](w.length);
        for (uint256 i = 0; i < w.length; ++i) {
            s.weights[i] = uint64(w[i]);
        }
    }

    function _signed(string memory e) internal view returns (StacksVerifier.SignedHeader memory b) {
        b.header = vm.parseJsonBytes(json, string.concat(".", e, ".block.preimage"));
        b.signatures = vm.parseJsonBytes(json, string.concat(".", e, ".block.signatures"));
    }

    function _rotation() internal view returns (StacksVerifier.RotationProof memory r) {
        r.current = _liveSet(fromCycle);
        r.block = _signed("rotation");
        r.marfProof = vm.parseJsonBytes(json, ".rotation.proof");
        r.bindings = new bytes[](0);
        r.signerList = vm.parseJsonBytes(json, ".rotation.value");
        string memory k = string.concat(".signerSets.", vm.toString(toCycle));
        bytes32[] memory xs = vm.parseJsonBytes32Array(json, string.concat(k, ".x"));
        bytes32[] memory ys = vm.parseJsonBytes32Array(json, string.concat(k, ".y"));
        r.nextKeys = new StacksVerifier.PublicKey[](xs.length);
        for (uint256 i = 0; i < xs.length; ++i) {
            r.nextKeys[i] = StacksVerifier.PublicKey({x: xs[i], y: ys[i]});
        }
    }

    function _genesisAnchor() internal view returns (bytes memory) {
        return abi.encode(
            StacksVerifier.Anchor({
                cycle: uint64(fromCycle), signerSetHash: live.setHash(_liveSet(fromCycle)), lastChainLength: 0
            })
        );
    }

    struct Entry {
        StacksVerifier.SignedHeader blk;
        bytes proof;
        bytes[] bindings;
        bytes key;
        bytes value;
    }

    function _entry(string memory e) internal view returns (Entry memory x) {
        x.blk = _signed(e);
        x.proof = vm.parseJsonBytes(json, string.concat(".", e, ".proof"));
        x.bindings = vm.parseJsonBytesArray(json, string.concat(".", e, ".bindings"));
        string memory contractId = vm.parseJsonString(json, string.concat(".", e, ".contract"));
        string memory map = vm.parseJsonString(json, string.concat(".", e, ".map"));
        bytes memory k = vm.parseJsonBytes(json, string.concat(".", e, ".key"));
        x.key = bytes.concat("vm::", bytes(contractId), "::0::", bytes(map), "::", ClarityCodec.toHex(k));
        x.value = vm.parseJsonBytes(json, string.concat(".", e, ".value"));
    }

    /// @dev Everything is computed before the one external call, so expectRevert and gas readings see
    ///      only {StacksVerifier.verifyEntry}.
    function _verifyEntry(Entry memory x, StacksVerifier.SignerSet memory set, bytes memory anchor)
        internal
        view
        returns (bytes32 id, uint64 len, uint256 segs)
    {
        return live.verifyEntry(anchor, set, x.blk, x.proof, x.bindings, x.key, x.value);
    }

    // ── live: rotation ───────────────────────────────────────────────────────

    function test_live_registerRotation() public {
        StacksVerifier.RotationProof memory r = _rotation();
        uint256 g = gasleft();
        bytes32 next = live.registerRotation(r);
        console.log("live rotation: gas", g - gasleft(), "calldata", abi.encodeCall(live.registerRotation, (r)).length);
        // the set derived on-chain (hash160 → uncompressed key → address) equals the stacker set
        assertEq(next, live.setHash(_liveSet(toCycle)));
        assertEq(live.successorOf(live.GENESIS_SET_HASH()), next);
        // idempotent
        assertEq(live.registerRotation(r), next);
    }

    function test_live_rotation_rejects_wrongParityKey() public {
        StacksVerifier.RotationProof memory r = _rotation();
        r.nextKeys[3].y =
            bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F - uint256(r.nextKeys[3].y));
        vm.expectRevert(abi.encodeWithSelector(StacksVerifier.NextKeyHashMismatch.selector, 3));
        live.registerRotation(r);
    }

    function test_live_rotation_rejects_offCurveKey() public {
        StacksVerifier.RotationProof memory r = _rotation();
        r.nextKeys[0].y = bytes32(uint256(r.nextKeys[0].y) ^ 2);
        vm.expectRevert(abi.encodeWithSelector(StacksVerifier.NextKeyNotOnCurve.selector, 0));
        live.registerRotation(r);
    }

    function test_live_rotation_rejects_wrongKeyCount() public {
        StacksVerifier.RotationProof memory r = _rotation();
        StacksVerifier.PublicKey[] memory k = new StacksVerifier.PublicKey[](r.nextKeys.length - 1);
        for (uint256 i = 0; i < k.length; ++i) {
            k[i] = r.nextKeys[i];
        }
        r.nextKeys = k;
        vm.expectRevert(StacksVerifier.NextKeyCountMismatch.selector);
        live.registerRotation(r);
    }

    function test_live_rotation_rejects_tamperedSignerList() public {
        StacksVerifier.RotationProof memory r = _rotation();
        r.signerList[r.signerList.length - 1] = bytes1(uint8(r.signerList[r.signerList.length - 1]) ^ 1); // a weight
        vm.expectRevert(StacksMarf.MarfValueMismatch.selector);
        live.registerRotation(r);
    }

    function test_live_rotation_rejects_wrongCycle() public {
        StacksVerifier.RotationProof memory r = _rotation();
        r.current.cycle += 1; // the proof is for cycle-signer-set[N+1], not [N+2]
        vm.expectRevert(StacksMarf.MarfPathMismatch.selector);
        live.registerRotation(r);
    }

    function test_live_rotation_rejects_belowThreshold() public {
        StacksVerifier.RotationProof memory r = _rotation();
        r.block.signatures = _prefix(r.block.signatures, 10 * 67);
        vm.expectPartialRevert(NakamotoHeader.BelowThreshold.selector);
        live.registerRotation(r);
    }

    // ── live: entries signed by the rotated set ──────────────────────────────

    function test_live_entry_singleSegment() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        uint256 g = gasleft();
        (bytes32 id, uint64 len, uint256 segs) = _verifyEntry(x, set, anchor);
        console.log("live entry (1 segment): gas", g - gasleft());
        assertEq(id, vm.parseJsonBytes32(json, ".entry.blockId"));
        assertEq(len, vm.parseJsonUint(json, ".entry.block.chainLength"));
        assertEq(segs, 1);
    }

    function test_live_entry_twoSegments() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("hop1");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        uint256 g = gasleft();
        (bytes32 id,, uint256 segs) = _verifyEntry(x, set, anchor);
        console.log("live entry (2 segments): gas", g - gasleft());
        assertEq(id, vm.parseJsonBytes32(json, ".hop1.blockId"));
        assertEq(segs, 2);
    }

    function test_live_entry_threeSegments() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("hop2");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        uint256 g = gasleft();
        (bytes32 id,, uint256 segs) = _verifyEntry(x, set, anchor);
        console.log("live entry (3 segments): gas", g - gasleft());
        assertEq(id, vm.parseJsonBytes32(json, ".hop2.blockId"));
        assertEq(segs, 3);
    }

    function test_live_entry_rejects_withoutRotation() public {
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        vm.expectRevert(StacksVerifier.SignerSetUnknown.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_oldSetForNewBlock() public {
        // the cycle N set cannot vouch for a cycle N+1 block
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(fromCycle);
        bytes memory anchor = _genesisAnchor();
        vm.expectRevert();
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_tamperedSignature() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.blk.signatures[40] = bytes1(uint8(x.blk.signatures[40]) ^ 1); // r of the first signature
        vm.expectPartialRevert(NakamotoHeader.SignerMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_duplicateSignature() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.blk.signatures = bytes.concat(_prefix(x.blk.signatures, 67), x.blk.signatures);
        vm.expectRevert(NakamotoHeader.SignerIndexNotAscending.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_tamperedHeader() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.blk.header[140] = bytes1(uint8(x.blk.header[140]) ^ 1); // timestamp: new block hash
        vm.expectPartialRevert(NakamotoHeader.SignerMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_tamperedTrieNode() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.proof[x.proof.length - 2000] = bytes1(uint8(x.proof[x.proof.length - 2000]) ^ 1); // a root sibling hash
        vm.expectPartialRevert(StacksMarf.MarfRootMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_wrongValue() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.value[x.value.length - 1] = bytes1(uint8(x.value[x.value.length - 1]) ^ 1);
        vm.expectRevert(StacksMarf.MarfValueMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_wrongKey() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.key[x.key.length - 1] = x.key[x.key.length - 1] == "0" ? bytes1("1") : bytes1("0");
        vm.expectRevert(StacksMarf.MarfPathMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_entry_rejects_truncatedProof() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.proof = _prefix(x.proof, x.proof.length - 32);
        vm.expectRevert(StacksMarf.MarfMalformed.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_hop_rejects_missingBinding() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("hop1");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.bindings = new bytes[](0);
        vm.expectRevert(StacksMarf.MarfBindingCount.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_hop_rejects_wrongBinding() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("hop2");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        (x.bindings[0], x.bindings[1]) = (x.bindings[1], x.bindings[0]); // swap the two older tries
        vm.expectRevert(StacksMarf.MarfBindingMismatch.selector);
        _verifyEntry(x, set, anchor);
    }

    function test_live_hop_rejects_extraBinding() public {
        live.registerRotation(_rotation());
        Entry memory x = _entry("entry");
        StacksVerifier.SignerSet memory set = _liveSet(toCycle);
        bytes memory anchor = _genesisAnchor();
        x.bindings = new bytes[](1);
        x.bindings[0] = x.blk.header;
        vm.expectRevert(StacksMarf.MarfBindingCount.selector);
        _verifyEntry(x, set, anchor);
    }

    // ── synthetic CLPR queue record ──────────────────────────────────────────

    bytes32 internal constant CHANNEL = keccak256("stacks-channel-1");

    struct Synth {
        StacksVerifier verifier;
        Signer[] signers;
        StacksVerifier.SignerSet set;
        StacksVerifier.QueueRecord record;
        bytes header;
        bytes proof;
    }

    function _weights() internal pure returns (uint64[] memory w) {
        w = new uint64[](5);
        (w[0], w[1], w[2], w[3], w[4]) = (1000, 900, 800, 700, 600);
    }

    function _synth(uint64 chainLength) internal returns (Synth memory s) {
        return _synthW(chainLength, _weights());
    }

    function _synthW(uint64 chainLength, uint64[] memory weights) internal returns (Synth memory s) {
        s.signers = _signers("stacks-synth-", weights);
        s.set = _set(144, s.signers);
        s.verifier = new StacksVerifier(hasher, "stacks:1", SIGNERS, 22, s.set);
        s.record = StacksVerifier.QueueRecord({
            nextMessageId: 3,
            sentRunningHash: keccak256("sent"),
            receivedMessageId: 1,
            receivedRunningHash: keccak256("received"),
            status: uint8(ClprTypes.ChannelStatus.ACTIVE),
            endpointManifestVersion: 1
        });
        bytes32 path = ClarityCodec.mapEntryPath(hasher, SERVICE, "clpr-queue", ClarityCodec.buff32(CHANNEL));
        bytes32 value = ClarityCodec.valueHash(hasher, s.verifier.queueRecordValue(s.record));
        bytes32 root;
        (s.proof, root) = _marf(path, value);
        s.header = _header(chainLength, root);
    }

    function _bundle(Synth memory s, uint256 mask) internal view returns (bytes memory) {
        bytes memory content = abi.encodePacked(uint8(0x12), uint8(3), "abc", uint8(0x12), uint8(2), "de");
        return abi.encode(
            StacksVerifier.BundleProof({
                signerSet: s.set,
                block: StacksVerifier.SignedHeader({
                    header: s.header, signatures: _sign(s.signers, _h(s.header), mask)
                }),
                marfProof: s.proof,
                bindings: new bytes[](0),
                record: s.record,
                bundleContent: content
            })
        );
    }

    function _ctx(bytes32 channel, bytes memory service) internal pure returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: channel, remoteServiceAddress: service})
            );
    }

    function _anchor(Synth memory s, uint64 last) internal pure returns (bytes memory) {
        return abi.encode(
            StacksVerifier.Anchor({cycle: 144, signerSetHash: keccak256(abi.encode(s.set)), lastChainLength: last})
        );
    }

    function test_synthetic_verifyConfig() public {
        Synth memory s = _synth(9_000_000);
        ClprTypes.Throttles memory th;
        bytes memory cfg = abi.encode(
            StacksVerifier.ConfigProof({
                signerSet: s.set,
                block: StacksVerifier.SignedHeader({
                    header: s.header, signatures: _sign(s.signers, _h(s.header), 0x0f)
                }),
                servicePrincipal: SERVICE,
                peerConfigNanos: 1,
                throttles: th
            })
        );
        (bytes memory ctx, string memory chainId, bytes memory service,,, bytes memory anchor, bytes memory anchorId,) =
            s.verifier.verifyConfig(cfg, CHANNEL, "");
        assertEq(ctx, _ctx(CHANNEL, SERVICE));
        assertEq(chainId, "stacks:1");
        assertEq(service, SERVICE);
        assertEq(anchor, _anchor(s, 0));
        assertEq(anchorId, abi.encodePacked(_blockId(s.header)));
    }

    /// Config-time manifest: the service's clpr-manifest-commitment data-var, mainnet-shaped proof.
    function test_synthetic_verifyConfig_withManifest() public {
        Synth memory s = _synth(9_000_000);
        ClprTypes.ClprEndpointManifest memory m;
        m.version = 2;
        m.serviceAddress = SERVICE;
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: "", accountId: hex"01"});
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);
        bytes32 path = _h(bytes.concat("vm::", SERVICE, "::1::clpr-manifest-commitment"));
        (bytes memory proof, bytes32 root) =
            _marf(path, ClarityCodec.valueHash(hasher, ClarityCodec.buff32(keccak256(preimage))));
        bytes memory header = _header(9_000_000, root);
        ClprTypes.Throttles memory th;
        bytes memory cfg = abi.encode(
            StacksVerifier.ConfigProof({
                signerSet: s.set,
                block: StacksVerifier.SignedHeader({header: header, signatures: _sign(s.signers, _h(header), 0x0f)}),
                servicePrincipal: SERVICE,
                peerConfigNanos: 1,
                throttles: th
            })
        );
        bytes memory mp = abi.encode(
            StacksVerifier.ConfigManifestProof({manifestPreimage: preimage, marfProof: proof, bindings: new bytes[](0)})
        );
        uint256 g = gasleft();
        (,,,,,,, ClprTypes.ClprEndpointManifest memory got) = s.verifier.verifyConfig(cfg, CHANNEL, mp);
        console.log("synthetic config + manifest: gas", g - gasleft(), "calldata", cfg.length + mp.length);
        assertEq(got.version, 2);
        assertEq(got.endpoints.length, 1);
        assertEq(got.serviceAddress, SERVICE);
    }

    function test_synthetic_verifyConfig_rejects_badPrincipal() public {
        Synth memory s = _synth(9_000_000);
        ClprTypes.Throttles memory th;
        bytes memory cfg = abi.encode(
            StacksVerifier.ConfigProof({
                signerSet: s.set,
                block: StacksVerifier.SignedHeader({
                    header: s.header, signatures: _sign(s.signers, _h(s.header), 0x0f)
                }),
                servicePrincipal: "SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE::clpr",
                peerConfigNanos: 1,
                throttles: th
            })
        );
        vm.expectRevert(StacksVerifier.BadServicePrincipal.selector);
        s.verifier.verifyConfig(cfg, CHANNEL, "");
    }

    function test_synthetic_verifyBundle_fullPipeline() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x0f); // 3,400 of 4,000 weight
        uint256 g = gasleft();
        (
            ClprTypes.QueueMetadata memory md,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId,
            ClprTypes.ClprEndpointManifest memory manifest
        ) = s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
        console.log("synthetic bundle: gas", g - gasleft(), "proofBytes", proof.length);
        assertEq(md.nextMessageId, 3);
        assertEq(md.sentRunningHash, keccak256("sent"));
        assertEq(md.receivedMessageId, 1);
        assertEq(md.receivedRunningHash, keccak256("received"));
        assertEq(uint8(md.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(md.endpointManifestVersion, 1);
        assertEq(payloads.length, 2);
        assertEq(payloads[0], "abc");
        assertEq(newAnchor, _anchor(s, 9_000_000));
        assertEq(newAnchorId, abi.encodePacked(_blockId(s.header)));
        assertEq(manifest.version, 0);
    }

    function test_synthetic_rejects_replayedBlock() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x1f);
        vm.expectRevert(abi.encodeWithSelector(StacksVerifier.StaleBlock.selector, 9_000_000, 9_000_000));
        s.verifier.verifyBundle(proof, _anchor(s, 9_000_000), _ctx(CHANNEL, SERVICE));
    }

    function test_synthetic_rejects_belowThreshold() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x1c); // 800 + 700 + 600 = 2,100 of 4,000 (< 70%)
        vm.expectRevert(abi.encodeWithSelector(NakamotoHeader.BelowThreshold.selector, 2100, 4000));
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
    }

    /// 70% exactly passes (stacks-core: signed ≥ ⌈7·total/10⌉); one weight unit less fails.
    function test_synthetic_thresholdBoundary() public {
        uint64[] memory w = new uint64[](3);
        (w[0], w[1], w[2]) = (2799, 1, 1200);
        Synth memory s = _synthW(9_000_000, w);
        bytes memory anchor = abi.encode(
            StacksVerifier.Anchor({cycle: 144, signerSetHash: keccak256(abi.encode(s.set)), lastChainLength: 0})
        );
        bytes memory ctx = _ctx(CHANNEL, SERVICE);
        s.verifier.verifyBundle(_bundle(s, 0x03), anchor, ctx); // 2,800 of 4,000
        bytes memory below = _bundle(s, 0x01); // 2,799
        vm.expectRevert(abi.encodeWithSelector(NakamotoHeader.BelowThreshold.selector, 2799, 4000));
        s.verifier.verifyBundle(below, anchor, ctx);
    }

    function test_synthetic_rejects_wrongChannel() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x1f);
        vm.expectRevert(StacksMarf.MarfPathMismatch.selector);
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(keccak256("other"), SERVICE));
    }

    function test_synthetic_rejects_wrongService() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x1f);
        vm.expectRevert(StacksMarf.MarfPathMismatch.selector);
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, "SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.other"));
    }

    function test_synthetic_rejects_forgedRecord() public {
        Synth memory s = _synth(9_000_000);
        s.record.nextMessageId = 4; // claims one more message than the state holds
        bytes memory proof = _bundle(s, 0x1f);
        vm.expectRevert(StacksMarf.MarfValueMismatch.selector);
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
    }

    function test_synthetic_rejects_unknownSet() public {
        Synth memory s = _synth(9_000_000);
        bytes memory proof = _bundle(s, 0x1f);
        bytes memory other =
            abi.encode(StacksVerifier.Anchor({cycle: 144, signerSetHash: keccak256("x"), lastChainLength: 0}));
        vm.expectRevert(StacksVerifier.SignerSetUnknown.selector);
        s.verifier.verifyBundle(proof, other, _ctx(CHANNEL, SERVICE));
    }

    function test_synthetic_rejects_impostorSigner() public {
        Synth memory s = _synth(9_000_000);
        Signer[] memory impostors = _signers("impostor-", _weights());
        bytes memory sigs = _sign(impostors, _h(s.header), 0x1f);
        bytes memory proof = abi.encode(
            StacksVerifier.BundleProof({
                signerSet: s.set,
                block: StacksVerifier.SignedHeader({header: s.header, signatures: sigs}),
                marfProof: s.proof,
                bindings: new bytes[](0),
                record: s.record,
                bundleContent: ""
            })
        );
        vm.expectRevert(abi.encodeWithSelector(NakamotoHeader.SignerMismatch.selector, 0));
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
    }

    function test_synthetic_rejects_unsupportedHeaderVersion() public {
        Synth memory s = _synth(9_000_000);
        s.header[0] = 0x02;
        bytes memory proof = _bundle(s, 0x1f);
        vm.expectRevert(abi.encodeWithSelector(NakamotoHeader.HeaderVersionUnsupported.selector, 2));
        s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
    }

    /// Two different successors for one set (equivocation) — the first recorded one stays.
    function test_synthetic_rotation_conflict() public {
        Synth memory s = _synth(9_000_000);
        StacksVerifier.RotationProof memory a = _synthRotation(s, "next-a-", 9_000_001);
        bytes32 ha = s.verifier.registerRotation(a);
        assertEq(s.verifier.successorOf(keccak256(abi.encode(s.set))), ha);
        StacksVerifier.RotationProof memory b = _synthRotation(s, "next-b-", 9_000_002);
        vm.expectPartialRevert(StacksVerifier.ConflictingRotation.selector);
        s.verifier.registerRotation(b);
    }

    /// After a recorded rotation, a bundle signed by the new set is accepted against the old anchor.
    function test_synthetic_rotation_thenBundle() public {
        Synth memory s = _synth(9_000_000);
        StacksVerifier.RotationProof memory r = _synthRotation(s, "next-a-", 8_999_000);
        s.verifier.registerRotation(r);
        Signer[] memory nextSigners = _signers("next-a-", _weights());
        StacksVerifier.SignerSet memory nextSet = _set(145, nextSigners);
        bytes memory proof = abi.encode(
            StacksVerifier.BundleProof({
                signerSet: nextSet,
                block: StacksVerifier.SignedHeader({
                    header: s.header, signatures: _sign(nextSigners, _h(s.header), 0x1f)
                }),
                marfProof: s.proof,
                bindings: new bytes[](0),
                record: s.record,
                bundleContent: ""
            })
        );
        (,, bytes memory newAnchor,,) = s.verifier.verifyBundle(proof, _anchor(s, 0), _ctx(CHANNEL, SERVICE));
        StacksVerifier.Anchor memory a = abi.decode(newAnchor, (StacksVerifier.Anchor));
        assertEq(a.cycle, 145);
        assertEq(a.signerSetHash, keccak256(abi.encode(nextSet)));
    }

    function _synthRotation(Synth memory s, string memory seed, uint64 chainLength)
        internal
        returns (StacksVerifier.RotationProof memory r)
    {
        Signer[] memory next = _signers(seed, _weights());
        bytes memory list = abi.encodePacked(uint8(0x0a), uint8(0x0b), uint32(next.length));
        r.nextKeys = new StacksVerifier.PublicKey[](next.length);
        for (uint256 i = 0; i < next.length; ++i) {
            bytes20 h160 =
                ripemd160(abi.encodePacked(sha256(abi.encodePacked(uint8(2 + (uint256(next[i].y) & 1)), next[i].x))));
            list = bytes.concat(
                list,
                abi.encodePacked(uint8(0x0c), uint32(2), uint8(6), "signer", uint8(0x05), uint8(22), h160),
                abi.encodePacked(uint8(6), "weight", ClarityCodec.uintValue(next[i].weight))
            );
            r.nextKeys[i] = StacksVerifier.PublicKey({x: next[i].x, y: next[i].y});
        }
        bytes32 path =
            ClarityCodec.mapEntryPath(hasher, bytes(SIGNERS), "cycle-signer-set", ClarityCodec.uintValue(145));
        (bytes memory proof, bytes32 root) = _marf(path, ClarityCodec.valueHash(hasher, list));
        bytes memory header = _header(chainLength, root);
        r.current = s.set;
        r.block = StacksVerifier.SignedHeader({header: header, signatures: _sign(s.signers, _h(header), 0x1f)});
        r.marfProof = proof;
        r.bindings = new bytes[](0);
        r.signerList = list;
    }

    function _prefix(bytes memory b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = b[i];
        }
    }
}
