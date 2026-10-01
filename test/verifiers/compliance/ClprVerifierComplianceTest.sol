// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @title ClprVerifierComplianceTest
abstract contract ClprVerifierComplianceTest is Test {
    IClprVerifier internal verifier;

    struct ConfigVector {
        bytes configProof;
        bytes32 channelId;
        string expectedChainId;
        bytes expectedServiceAddress;
    }

    struct BundleVector {
        bytes proofBytes;
        bytes trustAnchor;
        bytes channelContext;
        uint64 expectedNextMessageId;
        uint256 expectedPayloadCount;
    }

    struct RunningHashVector {
        bytes proofBytes;
        bytes trustAnchor;
        bytes channelContext;
        bytes32 previousRunningHash;
    }

    // ── Adapter hooks ────────────────────────────────────────────────────────
    function _deployVerifier() internal virtual returns (IClprVerifier);
    function _validConfig() internal virtual returns (ConfigVector memory);
    function _validBundle() internal virtual returns (BundleVector memory);
    /// @dev Build a config proof plus a cryptographically VALID config-time endpoint-manifest proof:
    ///      the manifest-commitment slot this verifier's transport authenticates MUST equal
    ///      `keccak256(committedPreimage)`, while the proof CARRIES `carriedPreimage` as the manifest
    ///      bytes. Passing the same value for both (see the single-argument overload) is the honest
    ///      case; passing different values forges a preimage that does not match its commitment.
    ///
    ///      Returned as a pair because some transports couple the two — Sei verifies the manifest
    ///      proof against the very IAVL store root the config's state proof authenticates, so both
    ///      must be built over one tree. Transports that keep them independent (QBFT, Ethereum) can
    ///      return their standard config proof alongside.
    ///
    ///      The base cases vary ONLY the preimage, so the transport stays valid while the manifest
    ///      content under test changes. That isolates the manifest rules from proof mechanics: any
    ///      revert is attributable to the manifest, not to a broken transport.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        virtual
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof);

    /// @dev The honest case: the proof commits to and carries the same manifest bytes.
    function _manifestConfigVector(bytes memory manifestPreimage)
        internal
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        return _manifestConfigVector(manifestPreimage, manifestPreimage);
    }
    /// @dev Return a bundle proof where sentRunningHash in storage equals the sha256-chain of the
    ///      included payloads starting from previousRunningHash (bytes32(0) for first bundle).
    function _runningHashVector() internal virtual returns (RunningHashVector memory);
    /// @dev Return a structurally valid config proof whose identity/chain does not match the
    ///      expected one, so verifyConfig MUST revert.
    function _wrongChainConfigVector() internal virtual returns (bytes memory configProof, bytes32 channelId);

    function setUp() public virtual {
        verifier = _deployVerifier();
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    /// @dev Spec: verifyConfig reverts on empty configProofBytes
    function test_compliance_verifyConfig_revertsOnEmptyProof() public {
        vm.expectRevert();
        verifier.verifyConfig("", bytes32(0), "");
    }

    /// @dev Spec: a valid proof returns a non-empty chainId, serviceAddress, and
    ///      channelContext, and the context ABI-decodes to {channelId, serviceAddress}
    ///      with the expected values.
    function test_compliance_verifyConfig_returnsFieldsAndContextDecodes() public {
        ConfigVector memory v = _validConfig();
        (bytes memory ctx, string memory chainId, bytes memory serviceAddress,,,,,) =
            verifier.verifyConfig(v.configProof, v.channelId, "");

        assertGt(bytes(chainId).length, 0, "chainId must be non-empty");
        assertEq(chainId, v.expectedChainId, "chainId mismatch");
        assertGt(serviceAddress.length, 0, "serviceAddress must be non-empty");
        assertEq(serviceAddress, v.expectedServiceAddress, "serviceAddress mismatch");
        assertGt(ctx.length, 0, "channelContext must be non-empty");

        ClprTypes.ChannelContext memory cc = ClprTypes.decodeChannelContext(ctx);
        assertEq(cc.channelId, v.channelId, "context channelId mismatch");
        assertEq(cc.remoteServiceAddress, v.expectedServiceAddress, "context serviceAddress mismatch");
    }

    /// @dev Spec: initialTrustAnchorId is non-empty iff initialTrustAnchor is non-empty.
    function test_compliance_verifyConfig_trustAnchorIdPairsWithAnchor() public {
        ConfigVector memory v = _validConfig();
        (,,,,, bytes memory initialTrustAnchor, bytes memory initialTrustAnchorId,) =
            verifier.verifyConfig(v.configProof, v.channelId, "");

        assertEq(
            initialTrustAnchor.length > 0,
            initialTrustAnchorId.length > 0,
            "initialTrustAnchorId must be non-empty iff initialTrustAnchor is non-empty"
        );
    }

    /// @dev Spec: verifyConfig reverts on a corrupted proof. A single flipped byte in the
    ///      otherwise-valid proof breaks the hash / merkle / signature chain, so verification MUST
    ///      revert rather than return attacker-chosen fields.
    function test_compliance_verifyConfig_revertsOnCorruptedProof() public virtual {
        ConfigVector memory v = _validConfig();
        require(v.configProof.length > 0, "adapter: _validConfig proof must be non-empty");
        bytes memory corrupted = _flipByte(v.configProof, v.configProof.length / 2);
        vm.expectRevert();
        verifier.verifyConfig(corrupted, v.channelId, "");
    }

    /// @dev Spec: verifyConfig reverts on a structurally valid proof built for a DIFFERENT chain
    ///      than the verifier is pinned to.
    function test_compliance_verifyConfig_revertsOnDifferentChainProof() public {
        (bytes memory configProof, bytes32 channelId) = _wrongChainConfigVector();
        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, "");
    }

    //── Manifest ────────────────────────────────────────────────────────

    /// @dev A 20-byte service address no verifier under test is pinned to. Used to force the
    ///      manifest ↔ config service-address binding to fail.
    bytes internal constant FOREIGN_SERVICE_ADDRESS = hex"DeaDbeefdEAdbeefdEadbEEFdeadbeEFdeadbEEF";

    /// @dev Spec: a valid endpoint_manifest_proof_bytes with manifest.version >= 1 causes
    //      verifyConfig to succeed and return the ClprEndpointManifest; Channel.endpoint_manifest
    //      is populated and endpoint_manifest_version is set to the manifest's version.
    function test_compliance_verifyConfig_validManifestProof_returnsManifest() public {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        ClprTypes.ClprEndpointManifest memory expected = _buildManifest(3, serviceAddress, 2);
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(expected));

        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) = verifier.verifyConfig(configProof, channelId, manifestProof);

        assertEq(m.version, 3, "manifest version must be the proven one");
        assertEq(m.serviceAddress, serviceAddress, "manifest service_address must be the config's");
        assertEq(m.endpoints.length, 2, "every proven endpoint must be returned");
        // Endpoint bodies must survive the commitment round-trip verbatim — a verifier that
        // returned a manifest whose endpoints differ from the committed preimage would let a relay
        // substitute dial targets while still matching the on-ledger commitment.
        for (uint256 i = 0; i < expected.endpoints.length; i++) {
            assertEq(m.endpoints[i].ipAddress, expected.endpoints[i].ipAddress, "endpoint ip");
            assertEq(m.endpoints[i].port, expected.endpoints[i].port, "endpoint port");
            assertEq(m.endpoints[i].accountId, expected.endpoints[i].accountId, "endpoint accountId");
        }
    }

    /// @dev Spec: an empty endpoint_manifest_proof_bytes is the bring-up case — verifyConfig MUST
    ///      succeed and return the UNINITIALIZED manifest (version 0), never invent a version. The
    ///      Channel then stores version 0 so the first manifest-carrying bundle (version >= 1)
    ///      advances it.
    function test_compliance_verifyConfig_emptyManifestProof_returnsUninitializedManifest() public {
        ConfigVector memory v = _validConfig();
        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) = verifier.verifyConfig(v.configProof, v.channelId, "");

        assertEq(m.version, 0, "bring-up: manifest version must be 0");
        assertEq(m.endpoints.length, 0, "bring-up: manifest must carry no endpoints");
    }

    /// @dev Spec: invalid endpoint_manifest_proof_bytes (malformed or cryptographically
    ///      invalid) causes verifyConfig to revert; completeChannel is rejected
    function test_compliance_verifyConfig_invalidManifestProof_reverts() public {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(1, serviceAddress, 1)));

        // Structurally unparseable bytes.
        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, hex"DEADBEEF");

        // Cryptographically broken: one flipped byte anywhere in an otherwise-valid proof breaks
        // either the transport's hash/seal chain or the preimage↔commitment binding.
        require(manifestProof.length > 0, "adapter: _manifestConfigVector proof must be non-empty");
        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, _flipByte(manifestProof, manifestProof.length / 2));
    }

    /// @dev Spec: manifest.service_address does not match ctx.service_address causes verifyConfig to revert
    /// @dev The transport is identical to the passing case above and only `service_address` inside
    ///      the committed preimage differs, so the revert is attributable to the binding check.
    ///      Without it a relay could present a valid proof of some OTHER service's manifest and
    ///      steer this channel's dial targets to endpoints that peer never published.
    function test_compliance_verifyConfig_manifestServiceAddressMismatch_reverts() public virtual {
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(1, FOREIGN_SERVICE_ADDRESS, 1)));

        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }

    /// @dev Spec: manifest version 0 in the proof causes verifyConfig to revert
    /// @dev Version 0 is the reserved "absent/uninitialized" sentinel. A proven manifest that
    ///      claimed it would be indistinguishable from bring-up and could never be advanced past,
    ///      so it must be rejected even though the proof itself is valid.
    function test_compliance_verifyConfig_manifestVersionZero_reverts() public virtual {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(0, serviceAddress, 1)));

        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }

    /// @dev Spec: a valid proof with an empty endpoint list (version >= 1, no endpoints)
    ///      causes verifyConfig to succeed.
    function test_compliance_verifyConfig_emptyEndpointList_succeeds() public {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(1, serviceAddress, 0)));

        // A peer that has published a manifest but admitted no endpoints yet is a legitimate state;
        // MUST NOT be conflated with a missing manifest.
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }

    /// @dev Spec: completeChannel succeeds when the remote CLPR Service has an empty
    ///      manifest (version >= 1, no endpoints). Channel.endpoint_manifest stores the empty
    ///      manifest with the correct service_address and version; endpoint_manifest_version is
    ///      set to the manifest's version value (>= 1); the Channel transitions to ACTIVE
    ///      normally with no error for the empty endpoint list.
    /// @dev Verifier half: the returned manifest must carry the proven version and service address
    ///      with a genuinely empty endpoint list. The CLPR-Service half — that completeChannel
    ///      stores exactly this and reaches ACTIVE — is asserted in ClprManifestServiceComplianceTest.
    function test_compliance_verifyConfig_emptyManifest_storedCorrectly() public {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(7, serviceAddress, 0)));

        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) = verifier.verifyConfig(configProof, channelId, manifestProof);

        assertEq(m.version, 7, "empty manifest must keep its proven version, not collapse to 0");
        assertEq(m.serviceAddress, serviceAddress, "empty manifest must still bind service_address");
        assertEq(m.endpoints.length, 0, "endpoint list must be empty");
    }

    // ── verifyBundle ─────────────────────────────────────────────────────────

    /// @dev Spec: verifyBundle reverts on empty proofBytes, and not with a Panic.
    function test_compliance_verifyBundle_revertsOnEmptyProof() public {
        BundleVector memory v = _validBundle();
        _assertBundleRejectedWithoutPanic("", v.trustAnchor, v.channelContext, "empty proof");
    }

    /// @dev Spec: verifyBundle reverts on an empty trust anchor, and not with a Panic.
    function test_compliance_verifyBundle_revertsOnEmptyTrustAnchor() public {
        BundleVector memory v = _validBundle();
        _assertBundleRejectedWithoutPanic(v.proofBytes, "", v.channelContext, "empty trust anchor");
    }

    /// @dev Spec: verifyBundle reverts on a truncated trust anchor, and not with a Panic.
    function test_compliance_verifyBundle_revertsOnTruncatedTrustAnchor() public {
        BundleVector memory v = _validBundle();
        require(v.trustAnchor.length >= 2, "adapter: _validBundle trustAnchor too short to truncate");
        bytes memory truncated = _truncate(v.trustAnchor, v.trustAnchor.length / 2);
        _assertBundleRejectedWithoutPanic(v.proofBytes, truncated, v.channelContext, "truncated trust anchor");
    }

    /// @dev Spec: no single-byte proof may Panic. Enumerated rather than fuzzed because the input
    ///      space is exactly 256 wide and each byte selects a distinct decode branch - for an RLP
    ///      transport, 0x00-0x7f is a data item, 0xb8-0xbf a long string, 0xc0 the empty list,
    ///      0xf8-0xff a long list. Every one of them must reach a named error.
    function test_compliance_verifyBundle_singleByteProofNeverPanics() public {
        BundleVector memory v = _validBundle();
        for (uint256 i = 0; i < 256; i++) {
            // casting to 'uint8' is safe because the loop bound is 256.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes1 prefix = bytes1(uint8(i));
            _assertBundleRejectedWithoutPanic(
                abi.encodePacked(prefix),
                v.trustAnchor,
                v.channelContext,
                string.concat("single byte ", vm.toString(prefix))
            );
        }
    }

    /// @dev Spec: no truncation of a VALID proof may Panic.
    ///
    ///      The single-byte sweep only ever exercises the outermost length prefix. Truncating a real
    ///      proof drives the same guards at every nesting depth, where a short inner item is reached
    ///      through a different code path than a short outer one. Truncation is also the realistic
    ///      corruption mode for a proof crossing a relay.
    ///
    ///      Dense up to 64 bytes, then strided - the interesting boundaries cluster in the header,
    ///      and a prime stride avoids aligning with any fixed-width field further in.
    function test_compliance_verifyBundle_truncatedProofNeverPanics() public {
        BundleVector memory v = _validBundle();
        uint256 fullLength = v.proofBytes.length;
        require(fullLength > 1, "adapter: _validBundle proofBytes too short to truncate");

        uint256 denseLimit = fullLength - 1 < 64 ? fullLength - 1 : 64;
        for (uint256 len = 1; len <= denseLimit; len++) {
            _assertTruncatedProofRejected(v, len);
        }
        for (uint256 len = denseLimit + 1; len < fullLength; len += 97) {
            _assertTruncatedProofRejected(v, len);
        }
    }

    function _assertTruncatedProofRejected(BundleVector memory v, uint256 len) private {
        _assertBundleRejectedWithoutPanic(
            _truncate(v.proofBytes, len),
            v.trustAnchor,
            v.channelContext,
            string.concat("proof truncated to ", vm.toString(len), " bytes")
        );
    }

    /// @dev Spec: a valid bundle yields the expected queue metadata and payload count.
    function test_compliance_verifyBundle_happyPath() public {
        BundleVector memory v = _validBundle();
        (ClprTypes.QueueMetadata memory metadata, bytes[] memory messagePayloads,,,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);

        assertEq(metadata.nextMessageId, v.expectedNextMessageId, "nextMessageId mismatch");
        assertEq(messagePayloads.length, v.expectedPayloadCount, "payload count mismatch");
    }

    /// @dev Spec: newTrustAnchor is empty bytes when the proof contains no rotation.
    /// @dev Virtual for verifiers whose anchor advances with every bundle even without a key
    ///      rotation (IClprVerifier: "empty bytes if the anchor was not advanced"), such as a
    ///      proof-of-work checkpoint or a last-proven block height. Such adapters override this case
    ///      and assert what their anchor must contain instead.
    function test_compliance_verifyBundle_noRotation_returnsEmptyNewAnchor() public virtual {
        BundleVector memory v = _validBundle();
        (,, bytes memory newTrustAnchor,,) = verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        assertEq(newTrustAnchor.length, 0, "no rotation: newTrustAnchor must be empty");
    }

    /// @dev Spec: newTrustAnchorId is non-empty if newTrustAnchor is non-empty.
    function test_compliance_verifyBundle_trustAnchorIdPairsWithAnchor() public {
        BundleVector memory v = _validBundle();
        (,, bytes memory newTrustAnchor, bytes memory newTrustAnchorId,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        assertEq(
            newTrustAnchor.length > 0,
            newTrustAnchorId.length > 0,
            "newTrustAnchorId must be non-empty iff newTrustAnchor is non-empty"
        );
    }

    /// @dev Spec: metadata.sentRunningHash must be the running hash chained over all returned
    ///      payloads starting from previousRunningHash.
    function test_compliance_verifyBundle_runningHashCoversPayloads() public {
        RunningHashVector memory v = _runningHashVector();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads,,,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        bytes32 computed = v.previousRunningHash;
        for (uint256 i = 0; i < payloads.length; i++) {
            computed = sha256(abi.encodePacked(computed, sha256(payloads[i])));
        }
        assertEq(computed, meta.sentRunningHash, "sentRunningHash must equal sha256-chain over all returned payloads");
    }

    // ── Endpoint manifest advancement & bundle update ordering ────────────────
    //
    // The remaining manifest obligations — advancement gating on
    // new_endpoint_manifest.version vs Channel.endpoint_manifest_version, full replacement of the
    // cached manifest, ordering against the trust-anchor update, NoProgress on a non-advancing
    // manifest, and which Channel states accept a manifest-only bundle — are CLPR Service
    // obligations, not verifier ones. They are identical for every verifier (the service only sees
    // the manifest a verifier returned), and asserting them needs control over Channel state and
    // over successive manifest versions, which real cryptographic fixtures cannot express.
    //
    // They are implemented once, against ClprService with a controllable verifier, in
    // test/compliance/ClprManifestServiceComplianceTest.t.sol.

    // ── helpers ──────────────────────────────────────────────────────────────

    /// @dev Selector of the builtin `Panic(uint256)`, emitted by solc for unchecked indexing,
    ///      arithmetic overflow, and friends.
    bytes4 private constant _PANIC_SELECTOR = 0x4e487b71;

    /// @dev Spec helper: `verifyBundle` MUST reject the given input by reverting, and that revert
    ///      MUST NOT be a `Panic`.
    ///
    ///      The distinction is the whole point. A named revert says the verifier inspected
    ///      attacker-controlled bytes and rejected them deliberately; a `Panic` says the verifier
    ///      indexed or subtracted without checking first, i.e. the guard is missing rather than
    ///      failing. `submitBundle` is permissionless, so every byte string reaching this function is
    ///      attacker-chosen and only the first outcome is acceptable.
    ///
    ///      Uses a low-level call rather than `vm.expectRevert()` because a bare `expectRevert` is
    ///      satisfied by a `Panic` and so cannot express "reverted, but not that way".
    function _assertBundleRejectedWithoutPanic(
        bytes memory proofBytes,
        bytes memory trustAnchor,
        bytes memory channelContext,
        string memory label
    ) internal {
        (bool ok, bytes memory returndata) = address(verifier)
            .call(abi.encodeCall(IClprVerifier.verifyBundle, (proofBytes, trustAnchor, channelContext)));

        assertFalse(ok, string.concat(label, ": expected verifyBundle to revert, but it returned"));

        // casting to 'bytes4' is safe because it is the intended selector read: the length guard
        // above ensures 4 bytes are present, and truncating the trailing revert arguments is exactly
        // what reading a selector means.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (returndata.length >= 4 && bytes4(returndata) == _PANIC_SELECTOR) {
            uint256 code;
            assembly ("memory-safe") {
                code := mload(add(returndata, 0x24))
            }
            fail(
                string.concat(
                    label,
                    ": verifyBundle reverted with Panic(",
                    vm.toString(code),
                    ") instead of a named error - unchecked indexing or arithmetic on attacker-controlled bytes"
                )
            );
        }
    }

    /// @dev Build a `ClprEndpointManifest` with `endpointCount` distinct endpoints. Ports and
    ///      accountIds vary per index so a verifier that returned endpoints in the wrong order, or
    ///      duplicated one, is caught by the round-trip assertions.
    function _buildManifest(uint64 version, bytes memory serviceAddress, uint256 endpointCount)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.version = version;
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](endpointCount);
        for (uint256 i = 0; i < endpointCount; i++) {
            m.endpoints[i] = ClprTypes.Endpoint({
                ipAddress: "10.0.0.1",
                // casting to 'uint32' is safe because endpointCount is a small test-chosen bound.
                // forge-lint: disable-next-line(unsafe-typecast)
                port: uint32(50211 + i),
                tlsCertificate: "",
                // casting to 'uint8' is safe because we know i + 1 won't be greater than uint8.max in our tests
                // forge-lint: disable-next-line(unsafe-typecast)
                accountId: abi.encodePacked(uint8(i + 1))
            });
        }
    }

    /// @dev Returns a copy of `data` with the byte at `index` inverted. Copies rather than mutating
    ///      in place so the caller's proof bytes are left intact for other cases.
    function _flipByte(bytes memory data, uint256 index) internal pure returns (bytes memory corrupted) {
        corrupted = bytes.concat(data);
        corrupted[index] = bytes1(uint8(corrupted[index]) ^ 0xFF);
    }

    /// @dev Returns the first `newLength` bytes of `data`. Used to build truncated inputs for
    ///      negative cases without mutating the caller's bytes.
    function _truncate(bytes memory data, uint256 newLength) internal pure returns (bytes memory out) {
        require(newLength <= data.length, "truncate: newLength exceeds data length");
        out = new bytes(newLength);
        for (uint256 i = 0; i < newLength; i++) {
            out[i] = data[i];
        }
    }
}
