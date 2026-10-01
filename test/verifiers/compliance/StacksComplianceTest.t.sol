// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {StacksTestBuilder} from "@test/verifiers/stacks/StacksTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprSha512t256Hasher} from "@hiero-ledger/clpr/libraries/crypto/ClprSha512t256Hasher.sol";
import {StacksVerifier} from "@hiero-ledger/clpr/verifiers/stacks/StacksVerifier.sol";
import {ClarityCodec} from "@hiero-ledger/clpr/libraries/proof/stacks/ClarityCodec.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title StacksComplianceTest
/// @dev IClprVerifier compliance for StacksVerifier on synthetic Stacks data: Nakamoto headers signed by
///      Foundry keys and MARF proofs in stacks-core's wire format (StacksTestBuilder). The live mainnet
///      signer, rotation and MARF paths are covered in test/verifiers/stacks/StacksVerifier.t.sol.
contract StacksComplianceTest is ClprVerifierComplianceTest, StacksTestBuilder {
    bytes internal constant SERVICE = "SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.clpr-service";
    bytes32 internal constant CHANNEL = keccak256("stacks-compliance-channel");
    uint64 internal constant CHAIN_LENGTH = 9_000_000;

    Signer[] internal signers;
    StacksVerifier.SignerSet internal set;

    function _weights() internal pure returns (uint64[] memory w) {
        w = new uint64[](4);
        (w[0], w[1], w[2], w[3]) = (1000, 1000, 1000, 1000);
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        hasher = address(new ClprSha512t256Hasher());
        Signer[] memory s = _signers("stacks-compliance-", _weights());
        for (uint256 i = 0; i < s.length; ++i) {
            signers.push(s[i]);
        }
        set = _set(144, s);
        return IClprVerifier(
            address(new StacksVerifier(hasher, "stacks:1", "SP000000000000000000002Q6VF78.signers", 22, set))
        );
    }

    function _signed(bytes32 stateRoot, uint64 chainLength)
        internal
        view
        returns (StacksVerifier.SignedHeader memory b)
    {
        b.header = _header(chainLength, stateRoot);
        b.signatures = _sign(signers, _h(b.header), 0x07); // 3 of 4 signers, 75%
    }

    function _config(StacksVerifier.SignerSet memory s, bytes32 stateRoot) internal view returns (bytes memory) {
        ClprTypes.Throttles memory th = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        return abi.encode(
            StacksVerifier.ConfigProof({
                signerSet: s,
                block: _signed(stateRoot, CHAIN_LENGTH),
                servicePrincipal: SERVICE,
                peerConfigNanos: 1,
                throttles: th
            })
        );
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(set, keccak256("any state root")),
            channelId: CHANNEL,
            expectedChainId: "stacks:1",
            expectedServiceAddress: SERVICE
        });
    }

    /// A config signed by a set the verifier was not deployed with (another network's signers).
    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        Signer[] memory other = _signers("stacks-testnet-", _weights());
        StacksVerifier.SignerSet memory otherSet = _set(144, other);
        bytes memory header = _header(CHAIN_LENGTH, keccak256("any state root"));
        ClprTypes.Throttles memory th;
        bytes memory cfg = abi.encode(
            StacksVerifier.ConfigProof({
                signerSet: otherSet,
                block: StacksVerifier.SignedHeader({header: header, signatures: _sign(other, _h(header), 0x0f)}),
                servicePrincipal: SERVICE,
                peerConfigNanos: 1,
                throttles: th
            })
        );
        return (cfg, CHANNEL);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        bytes32 path = _h(bytes.concat("vm::", SERVICE, "::1::clpr-manifest-commitment"));
        bytes32 value = ClarityCodec.valueHash(hasher, ClarityCodec.buff32(keccak256(committedPreimage)));
        (bytes memory proof, bytes32 root) = _marfCompact(path, value);
        configProof = _config(set, root);
        channelId = CHANNEL;
        manifestProof = abi.encode(
            StacksVerifier.ConfigManifestProof({
                manifestPreimage: carriedPreimage, marfProof: proof, bindings: new bytes[](0)
            })
        );
    }

    function _payloads() internal pure returns (bytes memory content, bytes[] memory p) {
        p = new bytes[](2);
        p[0] = hex"0a0401020304";
        p[1] = hex"0a03050607";
        content = abi.encodePacked(uint8(0x12), uint8(6), p[0], uint8(0x12), uint8(5), p[1]);
    }

    function _bundle(bytes32 sentRunningHash) internal view returns (bytes memory proofBytes) {
        (bytes memory content,) = _payloads();
        StacksVerifier.QueueRecord memory r = StacksVerifier.QueueRecord({
            nextMessageId: 3,
            sentRunningHash: sentRunningHash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            status: uint8(ClprTypes.ChannelStatus.ACTIVE),
            endpointManifestVersion: 0
        });
        bytes32 path = ClarityCodec.mapEntryPath(hasher, SERVICE, "clpr-queue", ClarityCodec.buff32(CHANNEL));
        bytes32 value = ClarityCodec.valueHash(hasher, StacksVerifier(address(verifier)).queueRecordValue(r));
        (bytes memory proof, bytes32 root) = _marfCompact(path, value);
        proofBytes = abi.encode(
            StacksVerifier.BundleProof({
                signerSet: set,
                block: _signed(root, CHAIN_LENGTH),
                marfProof: proof,
                bindings: new bytes[](0),
                record: r,
                bundleContent: content
            })
        );
    }

    function _anchor() internal view returns (bytes memory) {
        return
            abi.encode(
                StacksVerifier.Anchor({cycle: 144, signerSetHash: keccak256(abi.encode(set)), lastChainLength: 0})
            );
    }

    function _context() internal pure returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: SERVICE})
            );
    }

    function _chain(bytes32 h, bytes[] memory p) internal pure returns (bytes32) {
        for (uint256 i = 0; i < p.length; ++i) {
            h = sha256(abi.encodePacked(h, sha256(p[i])));
        }
        return h;
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(keccak256("sent")),
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        (, bytes[] memory p) = _payloads();
        return RunningHashVector({
            proofBytes: _bundle(_chain(bytes32(0), p)),
            trustAnchor: _anchor(),
            channelContext: _context(),
            previousRunningHash: bytes32(0)
        });
    }

    /// The anchor advances with every bundle (lastChainLength = the proven block), so it is never
    /// empty. Without a rotation the signer set and cycle stay those of the input anchor.
    function test_compliance_verifyBundle_noRotation_returnsEmptyNewAnchor() public override {
        BundleVector memory v = _validBundle();
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        StacksVerifier.Anchor memory before = abi.decode(v.trustAnchor, (StacksVerifier.Anchor));
        StacksVerifier.Anchor memory a = abi.decode(newAnchor, (StacksVerifier.Anchor));
        assertEq(a.cycle, before.cycle, "no rotation: same cycle");
        assertEq(a.signerSetHash, before.signerSetHash, "no rotation: same signer set");
        assertEq(a.lastChainLength, CHAIN_LENGTH, "anchor records the proven block");
        assertEq(newAnchorId.length, 32, "anchor id = proven block id");
    }
}
