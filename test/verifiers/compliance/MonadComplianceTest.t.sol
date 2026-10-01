// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {MonadSyntheticProofs} from "@test/verifiers/evm/monad/MonadSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {MonadVerifier} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadVerifier.sol";
import {MonadValsetRotation} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadValsetRotation.sol";
import {MonadPageProof} from "@hiero-ledger/clpr/libraries/proof/monad/MonadPageProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title MonadComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for MonadVerifier. Builds every vector in Solidity with {MonadSyntheticProofs}: a 4-validator set (all keys the G1
///      generator), real BLAKE3 header ids, a real BLS QC over a committed block, and MIP-8 page tries.
contract MonadComplianceTest is ClprEvmStorageComplianceTest, MonadSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(new MonadVerifier(new MonadValsetRotation()));
    }

    function _throttles() internal pure returns (bytes memory) {
        bytes[] memory t = new bytes[](5);
        t[0] = RLP.encode(uint256(10));
        t[1] = RLP.encode(uint256(4096));
        t[2] = RLP.encode(uint256(1_000_000));
        t[3] = RLP.encode(uint256(100));
        t[4] = RLP.encode(uint256(65536));
        return RLP.encode(t);
    }

    function _config(bytes memory valset) internal view returns (bytes memory) {
        bytes[] memory c = new bytes[](8);
        c[0] = RLP.encode(bytes("eip155:143"));
        c[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        c[2] = RLP.encode(SERVICE_CODE_HASH);
        c[3] = RLP.encode(uint256(1));
        c[4] = _throttles();
        c[5] = RLP.encode(uint256(SYN_EPOCH));
        c[6] = RLP.encode(valset);
        c[7] = _synFinality(keccak256("config-state"));
        return RLP.encode(c);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(_synValset()),
            channelId: CHANNEL_ID,
            expectedChainId: "eip155:143",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _ctx(bytes32 channelId) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
    }

    /// @dev Channel slots (+1, +2, +4, +5, +16) for `channelId` with `sentRunningHash` and nextMessageId.
    function _channelSlots(bytes32 channelId, uint64 nextMessageId, bytes32 sentHash)
        internal
        pure
        returns (Slot[] memory s)
    {
        uint256 b = uint256(keccak256(abi.encode(channelId, uint256(15))));
        s = new Slot[](5);
        s[0] = Slot(bytes32(b + 1), bytes32((uint256(nextMessageId) << 168) | (uint256(1) << 160) | 0xabc));
        s[1] = Slot(bytes32(b + 2), bytes32(uint256(1) << 64));
        s[2] = Slot(bytes32(b + 4), sentHash);
        s[3] = Slot(bytes32(b + 5), keccak256("recv"));
        s[4] = Slot(bytes32(b + 16), bytes32(uint256(1)));
    }

    function _bundle(Slot[] memory storageSlots, Slot[] memory provenSlots, address accountFor, bytes memory content)
        internal
        view
        returns (bytes memory)
    {
        (bytes32 sRoot,) = _pages(storageSlots);
        (, bytes memory pages) = _pages(provenSlots);
        if (provenSlots.length == storageSlots.length) (, pages) = _pages(storageSlots);
        (bytes32 stateRoot, bytes memory acct) = _account(accountFor, sRoot, SERVICE_CODE_HASH);
        bytes[] memory p = new bytes[](7);
        p[0] = RLP.encode(uint256(0));
        p[1] = _synFinality(stateRoot);
        p[2] = RLP.encode(_synValset());
        p[3] = acct;
        p[4] = pages;
        p[5] = RLP.encode(content);
        p[6] = RLP.encode(new bytes[](0));
        return RLP.encode(p);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        Slot[] memory s = _channelSlots(CHANNEL_ID, 0, bytes32(0));
        return BundleVector({
            proofBytes: _bundle(s, s, SERVICE_ADDR, ""),
            trustAnchor: _synAnchor(SERVICE_CODE_HASH),
            channelContext: _ctx(CHANNEL_ID),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummy;
        Slot[] memory s = _channelSlots(CHANNEL_ID, 2, sent);
        return RunningHashVector({
            proofBytes: _bundle(s, s, SERVICE_ADDR, ClprProtobuf.encodeBundleContent(dummy, payloads)),
            trustAnchor: _synAnchor(SERVICE_CODE_HASH),
            channelContext: _ctx(CHANNEL_ID),
            previousRunningHash: bytes32(0)
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        Slot[] memory s = new Slot[](1);
        s[0] = Slot(bytes32(MANIFEST_COMMITMENT_SLOT), keccak256(committedPreimage));
        (bytes32 sRoot, bytes memory pages) = _pages(s);
        (bytes32 stateRoot, bytes memory acct) = _account(SERVICE_ADDR, sRoot, SERVICE_CODE_HASH);
        bytes[] memory m = new bytes[](4);
        m[0] = _synFinality(stateRoot);
        m[1] = acct;
        m[2] = pages;
        m[3] = RLP.encode(carriedPreimage);
        return (_config(_synValset()), CHANNEL_ID, RLP.encode(m));
    }

    /// @dev Validator keys in compressed (48-byte) form — the format of a chain whose verifier would
    ///      decompress on-chain. MonadVerifier needs EIP-2537 (128-byte) keys → InvalidValidatorEntry.
    function _wrongChainConfigVector() internal view override returns (bytes memory configProof, bytes32 channelId) {
        return (_config(new bytes(48 * SYN_VALIDATORS)), CHANNEL_ID);
    }

    /// @dev Config with 4 of the 7 fields.
    function _partialSlotCoverageVector() internal pure override returns (bytes memory, bytes32) {
        bytes[] memory c = new bytes[](4);
        c[0] = RLP.encode(bytes("eip155:143"));
        c[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        c[2] = RLP.encode(SERVICE_CODE_HASH);
        c[3] = RLP.encode(uint256(1));
        return (RLP.encode(c), CHANNEL_ID);
    }

    /// @dev Pages proven for CHANNEL_ID, verified under another channel's context: that channel's page is
    ///      not in the batch.
    function _crossChannelVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory attackerContext, bytes memory)
    {
        bytes32 attacker = bytes32(uint256(0xDEADBEEF));
        Slot[] memory s = _channelSlots(CHANNEL_ID, 0, bytes32(0));
        bytes32 missingPage = bytes32((uint256(keccak256(abi.encode(attacker, uint256(15)))) + 1) >> 7);
        return (
            _bundle(s, s, SERVICE_ADDR, ""),
            _synAnchor(SERVICE_CODE_HASH),
            _ctx(attacker),
            abi.encodeWithSelector(MonadPageProof.PageNotProven.selector, missingPage)
        );
    }

    /// @dev Account proof for another address → the service account is absent from the state trie.
    function _wrongServiceAddressVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        Slot[] memory s = _channelSlots(CHANNEL_ID, 0, bytes32(0));
        address other = address(uint160(uint256(keccak256("different-service"))));
        return (_bundle(s, s, other, ""), _synAnchor(SERVICE_CODE_HASH), _ctx(CHANNEL_ID));
    }

    /// @dev The page proof omits 2 of the page's 5 non-zero slots → its commitment does not match.
    function _threeSlotStorageVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        Slot[] memory s = _channelSlots(CHANNEL_ID, 0, bytes32(0));
        Slot[] memory three = new Slot[](3);
        three[0] = s[0];
        three[1] = s[1];
        three[2] = s[2];
        return (_bundle(s, three, SERVICE_ADDR, ""), _synAnchor(SERVICE_CODE_HASH), _ctx(CHANNEL_ID));
    }

    /// @dev Pages of a different channel's slots under this channel's context.
    function _wrongSlotIndexVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        Slot[] memory s = _channelSlots(bytes32(uint256(0xBADC0DE)), 0, bytes32(0));
        return (_bundle(s, s, SERVICE_ADDR, ""), _synAnchor(SERVICE_CODE_HASH), _ctx(CHANNEL_ID));
    }
}
