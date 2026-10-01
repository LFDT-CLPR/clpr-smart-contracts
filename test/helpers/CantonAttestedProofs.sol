// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CantonAttestedVerifier} from "@hiero-ledger/clpr/verifiers/canton/CantonAttestedVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @notice Builds and signs CantonAttestedVerifier proofs for tests. Operators are generated from
///         fixed seeds and kept sorted by address, matching the verifier's ordering rule.
abstract contract CantonAttestedProofs is Test {
    string internal constant CLPR_PARTY_ID = "clpr::1220c0ffee00000000000000000000000000000000000000000000000000000000";
    string internal constant CANTON_CHAIN_ID = "canton:localnet";
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC4C4));

    struct OperatorSet {
        uint16 threshold;
        address[] addrs;
        uint256[] keys;
    }

    function _serviceAddress() internal pure returns (bytes memory) {
        return bytes(CLPR_PARTY_ID);
    }

    function _cantonParty() internal pure returns (bytes32) {
        return keccak256(bytes(CLPR_PARTY_ID));
    }

    function _channelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: _serviceAddress()})
        );
    }

    /// @dev n operators from seeds `seed..seed+n-1`, sorted ascending by address.
    function _operators(uint256 seed, uint256 n, uint16 t) internal pure returns (OperatorSet memory s) {
        s.threshold = t;
        s.addrs = new address[](n);
        s.keys = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            s.keys[i] = uint256(keccak256(abi.encode("canton-operator", seed + i)));
            s.addrs[i] = vm.addr(s.keys[i]);
        }
        // insertion sort by address
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && s.addrs[j] < s.addrs[j - 1]; --j) {
                (s.addrs[j], s.addrs[j - 1]) = (s.addrs[j - 1], s.addrs[j]);
                (s.keys[j], s.keys[j - 1]) = (s.keys[j - 1], s.keys[j]);
            }
        }
    }

    function _anchor(OperatorSet memory s, uint64 epoch)
        internal
        pure
        returns (CantonAttestedVerifier.TrustAnchor memory)
    {
        return CantonAttestedVerifier.TrustAnchor({
            cantonParty: _cantonParty(), epoch: epoch, threshold: s.threshold, operators: s.addrs
        });
    }

    /// @dev Sign `digest` with the operators at `indexes` (must be ascending) into the packed format.
    function _sign(bytes32 digest, OperatorSet memory s, uint256[] memory indexes)
        internal
        pure
        returns (bytes memory out)
    {
        for (uint256 i = 0; i < indexes.length; ++i) {
            (uint8 v, bytes32 r, bytes32 sg) = vm.sign(s.keys[indexes[i]], digest);
            // forge-lint: disable-next-line(unsafe-typecast)
            out = bytes.concat(out, abi.encodePacked(uint8(indexes[i]), r, sg, v));
        }
    }

    /// @dev The first `count` operators.
    function _firstN(uint256 count) internal pure returns (uint256[] memory idx) {
        idx = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            idx[i] = i;
        }
    }

    function _head(uint64 messageId, bytes32 runningHash)
        internal
        pure
        returns (CantonAttestedVerifier.QueueHead memory)
    {
        return CantonAttestedVerifier.QueueHead({
            channelId: CHANNEL_ID,
            messageId: messageId,
            runningHash: runningHash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            status: uint8(ClprTypes.ChannelStatus.ACTIVE),
            endpointManifestVersion: 1
        });
    }

    /// @dev Pre-ADR running hash the reference ClprService checks: sha256(prev || sha256(payload)).
    function _chain(bytes32 prev, bytes[] memory payloads) internal pure returns (bytes32 h) {
        h = prev;
        for (uint256 i = 0; i < payloads.length; ++i) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
        }
    }

    function _samplePayloads(uint256 k) internal pure returns (bytes[] memory p) {
        p = new bytes[](k);
        for (uint256 i = 0; i < k; ++i) {
            // ClprMessagePayload{message: ClprMessage{message_data = "msg-i"}}
            bytes memory data = abi.encodePacked("msg-", vm.toString(i));
            bytes memory inner = abi.encodePacked(uint8(0x22), uint8(data.length), data);
            p[i] = abi.encodePacked(uint8(0x0a), uint8(inner.length), inner);
        }
    }

    function _bundle(
        CantonAttestedVerifier v,
        OperatorSet memory s,
        uint64 epoch,
        CantonAttestedVerifier.Rotation[] memory rotations,
        CantonAttestedVerifier.QueueHead memory h,
        bytes[] memory payloads,
        bytes memory manifest,
        uint256[] memory signers
    ) internal view returns (bytes memory) {
        bytes32 digest = v.queueHeadDigest(_anchor(s, epoch), h, payloads, manifest);
        return abi.encode(
            CantonAttestedVerifier.BundleProof({
                version: 1,
                rotations: rotations,
                head: h,
                payloads: payloads,
                manifest: manifest,
                signatures: _sign(digest, s, signers)
            })
        );
    }

    function _rotation(
        CantonAttestedVerifier v,
        OperatorSet memory from,
        uint64 fromEpoch,
        OperatorSet memory to,
        uint256[] memory signers
    ) internal view returns (CantonAttestedVerifier.Rotation memory) {
        bytes32 digest = v.rotationDigest(_anchor(from, fromEpoch), to.threshold, to.addrs);
        return CantonAttestedVerifier.Rotation({
            newThreshold: to.threshold, newOperators: to.addrs, signatures: _sign(digest, from, signers)
        });
    }

    function _throttles() internal pure returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 50,
            maxMessagePayloadBytes: 6144,
            maxGasPerMessage: 2_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 1 << 20,
            maxLocalEndpoints: 8,
            maxPeerEndpoints: 8
        });
    }

    // EIP-712 config / manifest digests, recomputed independently of the verifier.

    function _domainSeparator(address verifier) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CLPR Canton Operators"),
                keccak256("1"),
                block.chainid,
                verifier
            )
        );
    }

    function _configDigest(
        address verifier,
        bytes32 party,
        uint64 epoch,
        bytes32 channelId,
        string memory chainId,
        bytes memory serviceAddress,
        uint96 nanos,
        ClprTypes.Throttles memory t
    ) internal view returns (bytes32) {
        bytes32 th = keccak256(
            abi.encode(
                keccak256(
                    "Throttles(uint32 maxMessagesPerBundle,uint64 maxMessagePayloadBytes,uint64 maxGasPerMessage,uint32 maxQueueDepth,uint64 maxSyncBytes,uint32 maxLocalEndpoints,uint32 maxPeerEndpoints)"
                ),
                t.maxMessagesPerBundle,
                t.maxMessagePayloadBytes,
                t.maxGasPerMessage,
                t.maxQueueDepth,
                t.maxSyncBytes,
                t.maxLocalEndpoints,
                t.maxPeerEndpoints
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                CantonAttestedVerifier(verifier).CONFIG_TYPEHASH(),
                party,
                epoch,
                channelId,
                keccak256(bytes(chainId)),
                keccak256(serviceAddress),
                nanos,
                th
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(verifier), structHash));
    }

    function _manifestDigest(address verifier, uint64 epoch, bytes32 channelId, bytes memory manifest)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("EndpointManifest(bytes32 cantonParty,uint64 epoch,bytes32 channelId,bytes manifest)"),
                _cantonParty(),
                epoch,
                channelId,
                keccak256(manifest)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(verifier), structHash));
    }

    function _configProof(
        CantonAttestedVerifier v,
        OperatorSet memory genesis,
        CantonAttestedVerifier.Rotation[] memory rotations,
        OperatorSet memory current,
        uint64 currentEpoch,
        bytes32 channelId,
        string memory chainId,
        bytes memory serviceAddress
    ) internal view returns (bytes memory) {
        ClprTypes.Throttles memory t = _throttles();
        bytes32 digest = _configDigest(
            address(v), _cantonParty(), currentEpoch, channelId, chainId, serviceAddress, 1_700_000_000_000_000_000, t
        );
        return abi.encode(
            CantonAttestedVerifier.ConfigProof({
                version: 1,
                genesis: _anchor(genesis, 0),
                rotations: rotations,
                chainId: chainId,
                serviceAddress: serviceAddress,
                peerConfigNanos: 1_700_000_000_000_000_000,
                throttles: t,
                signatures: _sign(digest, current, _firstN(current.threshold))
            })
        );
    }

    function _manifestProof(
        CantonAttestedVerifier v,
        OperatorSet memory s,
        uint64 epoch,
        bytes32 channelId,
        bytes memory manifest
    ) internal view returns (bytes memory) {
        bytes32 digest = _manifestDigest(address(v), epoch, channelId, manifest);
        return abi.encode(
            CantonAttestedVerifier.ManifestProof({
                manifest: manifest, signatures: _sign(digest, s, _firstN(s.threshold))
            })
        );
    }

    function _deploy(OperatorSet memory genesis) internal returns (CantonAttestedVerifier) {
        return new CantonAttestedVerifier(_anchor(genesis, 0), CANTON_CHAIN_ID);
    }
}
