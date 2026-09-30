// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";

/// @title ClprEvmStorageComplianceTest
/// @notice Spec-compliance cases specific to verifiers that authenticate the peer CLPR Service's
///         Channel struct via storage-slot proofs (the `ClprEvmBundleVerifier` family).
///
/// @dev Extends the verifier-agnostic base, so adapters inheriting this layer also run every base
///      case. Abstract; only concrete adapters emit tests.
abstract contract ClprEvmStorageComplianceTest is ClprVerifierComplianceTest {
    /// @dev Spec: the peer CLPR Service commits `keccak256(protobuf(ClprEndpointManifest))` to this
    ///      storage slot. Hard-coded rather than read from the verifier so a silent slot change on
    ///      either side fails the suite — the relay (clpr-evm-endpoint) proves this exact number.
    uint256 internal constant MANIFEST_COMMITMENT_SLOT = 18;

    /// @dev Spec: channel metadata lives under `keccak256(abi.encode(channelId, 15))`.
    uint256 internal constant CHANNELS_BASE_SLOT = 15;

    /// @dev Proven `nextMessageId` for a one-payload bundle with nothing acked: the payload is
    ///      message 1, so the sender's next id is 2.
    uint64 internal constant ONE_MESSAGE_NEXT_MESSAGE_ID = 2;

    /// @dev A bundle whose storage proof is bound to one channel but whose channelContext
    ///      claims a DIFFERENT channel, plus the exact revert this verifier must produce. The
    ///      revert bytes differ per verifier (e.g. SlotNotProven vs StorageKeyMismatch), so the
    ///      adapter supplies them rather than the base assuming a selector.
    function _crossChannelVector()
        internal
        virtual
        returns (
            bytes memory proofBytes,
            bytes memory trustAnchor,
            bytes memory attackerContext,
            bytes memory expectedRevert
        );

    /// @dev Return a structurally parseable config proof with at least one required slot/field
    ///      omitted, so verifyConfig must revert rather than return attacker-chosen values.
    function _partialSlotCoverageVector() internal virtual returns (bytes memory configProof, bytes32 channelId);

    /// @dev Return a bundle proof built for the correct service address, plus a channelContext
    ///      that claims a DIFFERENT service address, so verifyBundle must revert.
    function _wrongServiceAddressVector()
        internal
        virtual
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory wrongContext);

    /// @dev Return a bundle proof with exactly 3 storage entries (instead of the required 5 or 6).
    function _threeSlotStorageVector()
        internal
        virtual
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext);

    /// @dev Return a bundle proof with a shape-valid entry count where one entry carries a wrong
    ///      slot key (e.g. cBase+3 instead of cBase+4) so the verifier cannot find an expected slot.
    function _wrongSlotIndexVector()
        internal
        virtual
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext);

    /// @dev Spec: a proof keyed to channel B, submitted for channel A, must revert. Storage
    ///      slot keys are derived from the channelId, never read from the proof, so a relay
    ///      cannot substitute another channel's slots.
    function test_compliance_verifyConfig_crossChannelStorageProof_reverts() public {
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory attackerContext, bytes memory expectedRevert) =
            _crossChannelVector();
        vm.expectRevert(expectedRevert);
        verifier.verifyBundle(proofBytes, trustAnchor, attackerContext);
    }

    /// @dev Spec: every config field must be state-proofed. Omitting any one of
    ///      the proven channel slots must revert, proving no field is taken on
    ///      trust from unproven input — i.e. verifyConfig is fully trustless over storage.
    function test_compliance_verifyConfig_partialSlotCoverage_reverts() public {
        (bytes memory configProof, bytes32 channelId) = _partialSlotCoverageVector();
        vm.expectRevert();
        verifier.verifyConfig(configProof, channelId, "");
    }

    /// @dev Spec: the account proof is keyed by the service address derived from channelContext.
    ///      A proof built for address A cannot authenticate address B — verifyBundle must revert.
    function test_compliance_verifyBundle_wrongServiceAddress_reverts() public {
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory wrongContext) = _wrongServiceAddressVector();
        vm.expectRevert();
        verifier.verifyBundle(proofBytes, trustAnchor, wrongContext);
    }

    /// @dev Spec: a storage proof with only 3 of the required Channel struct slots must revert.
    ///      The verifier rejects entry counts that are neither 5 nor 6.
    function test_compliance_verifyBundle_threeSlotStorageProof_reverts() public {
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext) = _threeSlotStorageVector();
        vm.expectRevert();
        verifier.verifyBundle(proofBytes, trustAnchor, channelContext);
    }

    /// @dev Spec: slot keys are derived from the storage layout, never read from the proof.
    ///      A shape-valid proof with one wrong slot index must revert — the expected slot
    ///      is absent from the proof so the verifier cannot satisfy the SlotNotProven check.
    function test_compliance_verifyBundle_wrongSlotIndex_reverts() public {
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext) = _wrongSlotIndexVector();
        vm.expectRevert();
        verifier.verifyBundle(proofBytes, trustAnchor, channelContext);
    }

    /// @dev Spec: channel metadata slot keys are derived as
    ///      keccak256(abi.encode(channelId, CHANNELS_BASE_SLOT)) + {1, 2, 4, 5, 16}
    ///      where CHANNELS_BASE_SLOT == 15.
    function test_compliance_verifyBundle_slotKeyDerivationMatchesFormula() public {
        BundleVector memory v = _validBundle();
        // Does not revert ↔ the verifier accepted a proof keyed by the canonical formula.
        verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
    }

    /// @dev Return a five-slot bundle proof whose Channel proves `nextMessageId`, `sentRunningHash`
    ///      and ackedMessageId 0, carrying `bundleContent`.
    function _fiveSlotBundleVector(uint64 nextMessageId, bytes32 sentRunningHash, bytes memory bundleContent)
        internal
        virtual
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext);

    /// @dev One payload with nothing acked must be message 1; a proven nextMessageId of 1 places it
    ///      at message 0, at the sender's ackedMessageId.
    function test_compliance_verifyBundle_fiveSlotStartsAtAcked_reverts() public {
        (bytes memory content, bytes32 sentHash) = _oneMessageBundleContent();
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext) =
            _fiveSlotBundleVector(ONE_MESSAGE_NEXT_MESSAGE_ID - 1, sentHash, content);
        vm.expectRevert(ClprTypes.ClprBundleStartsAtOrBeforeAcked.selector);
        verifier.verifyBundle(proofBytes, trustAnchor, channelContext);
    }

    function test_compliance_verifyBundle_fiveSlotStartsAfterAcked_succeeds() public {
        (bytes memory content, bytes32 sentHash) = _oneMessageBundleContent();
        (bytes memory proofBytes, bytes memory trustAnchor, bytes memory channelContext) =
            _fiveSlotBundleVector(ONE_MESSAGE_NEXT_MESSAGE_ID, sentHash, content);
        (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads,,,) =
            verifier.verifyBundle(proofBytes, trustAnchor, channelContext);
        assertEq(payloads.length, 1);
        assertEq(meta.lastMessageId, ONE_MESSAGE_NEXT_MESSAGE_ID - 1);
        assertEq(meta.lastMessageRunningHash, sentHash);
    }

    /// @dev A ClprBundleContent with one DATA payload, and the running hash over it from zero.
    function _oneMessageBundleContent() internal pure returns (bytes memory content, bytes32 sentHash) {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        ClprTypes.QueueMetadata memory emptyMeta;
        content = ClprProtobuf.encodeBundleContent(emptyMeta, payloads);
        sentHash = sha256(abi.encodePacked(bytes32(0), sha256(payloads[0])));
    }

    // ── Manifest: exact rejection reasons ─────────────────────────────────────
    //
    // The base states these as "must revert", which any transport failure would also satisfy. Every
    // ClprEvmBundleVerifier-family verifier shares one manifest-binding implementation and therefore
    // one set of error selectors, so this layer can pin the exact reason — proving the rejection came
    // from the manifest rule and not from an incidentally malformed fixture.

    /// @dev Spec: a proven manifest whose service_address is not the config's must be rejected
    ///      specifically as a service-address mismatch.
    function test_compliance_verifyConfig_manifestServiceAddressMismatch_reverts() public override {
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(1, FOREIGN_SERVICE_ADDRESS, 1)));

        vm.expectRevert(ClprEvmBundleVerifier.ManifestServiceAddressMismatch.selector);
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }

    /// @dev Spec: a proven manifest at version 0 must be rejected specifically as version-zero.
    function test_compliance_verifyConfig_manifestVersionZero_reverts() public override {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) =
            _manifestConfigVector(ClprProtobuf.encodeEndpointManifest(_buildManifest(0, serviceAddress, 1)));

        vm.expectRevert(ClprEvmBundleVerifier.ManifestVersionZero.selector);
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }

    /// @dev Spec: the supplied preimage MUST hash to the proven on-ledger commitment. Without this
    ///      binding a relay could attach any manifest to a valid slot proof, so the mismatch has its
    ///      own dedicated rejection.
    function test_compliance_verifyConfig_manifestPreimageNotMatchingCommitment_reverts() public {
        bytes memory serviceAddress = _validConfig().expectedServiceAddress;
        // The slot proof commits to manifest A, but the proof carries manifest B. Both are
        // well-formed manifests, so only the commitment binding can catch the substitution.
        (bytes memory configProof, bytes32 channelId, bytes memory manifestProof) = _manifestConfigVector(
            ClprProtobuf.encodeEndpointManifest(_buildManifest(1, serviceAddress, 1)),
            ClprProtobuf.encodeEndpointManifest(_buildManifest(9, serviceAddress, 3))
        );

        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        verifier.verifyConfig(configProof, channelId, manifestProof);
    }
}
