// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic Clique-style headers (one ECDSA seal in extraData) for SignerReplayVerifier tests,
///      plus the bundle/config encodings. MPT helpers come from {QbftSyntheticProofs}.
abstract contract SignerReplaySynthetic is QbftSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    uint64 internal constant TEST_CHAIN_ID = 777;
    uint64 internal constant TEST_EPOCH = 100;

    struct Hdr {
        bytes rlp;
        bytes32 hash;
        uint64 number;
    }

    function _cliqueProfile() internal pure returns (SignerReplayVerifier.Profile memory) {
        return SignerReplayVerifier.Profile({
            chainId: TEST_CHAIN_ID,
            epochLength: TEST_EPOCH,
            boundaryOffset: 0,
            maxAnchorAge: 0,
            sealFields: 0,
            entrySize: 20,
            trailerSize: 0,
            trailerSignerOffset: type(uint8).max
        });
    }

    function _keys(uint256 n, string memory tag) internal pure returns (uint256[] memory pks) {
        pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = uint256(keccak256(abi.encode(tag, i)));
        }
    }

    /// @dev Ascending, de-duplicated signer addresses of `pks` (the anchor's canonical form).
    function _sortedAddrs(uint256[] memory pks) internal pure returns (address[] memory a) {
        a = new address[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            a[i] = vm.addr(pks[i]);
        }
        for (uint256 i = 1; i < a.length; i++) {
            for (uint256 j = i; j > 0 && uint160(a[j - 1]) > uint160(a[j]); j--) {
                (a[j - 1], a[j]) = (a[j], a[j - 1]);
            }
        }
    }

    function _packed(address[] memory a) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < a.length; i++) {
            out = bytes.concat(out, abi.encodePacked(a[i]));
        }
    }

    function _anchor(address[] memory set, uint64 setBlock) internal pure returns (bytes memory) {
        return abi.encodePacked(SERVICE_CODE_HASH, keccak256(_packed(set)), setBlock, uint16(set.length));
    }

    /// @dev A header sealed by `pk`. `listBody` goes between vanity and seal (signer list on boundary
    ///      blocks). `extraFields` appends that many trailing fields (e.g. baseFee); the seal covers the
    ///      first `sealFields` fields (0 = all).
    function _hdr(
        uint64 number,
        bytes32 parent,
        bytes32 stateRoot,
        bytes memory listBody,
        uint256 pk,
        uint256 extraFields,
        uint256 sealFields
    ) internal pure returns (Hdr memory h) {
        bytes memory unsealed = bytes.concat(new bytes(32), listBody);
        bytes[] memory f = _fields(number, parent, stateRoot, unsealed, extraFields);
        f[12] = RLP.encode(bytes.concat(unsealed, _seal(f, pk, sealFields)));
        h.rlp = RLP.encode(f);
        h.hash = keccak256(h.rlp);
        h.number = number;
    }

    function _fields(uint64 number, bytes32 parent, bytes32 stateRoot, bytes memory unsealed, uint256 extraFields)
        private
        pure
        returns (bytes[] memory f)
    {
        f = new bytes[](15 + extraFields);
        f[0] = RLP.encode(parent);
        f[1] = RLP.encode(bytes32(uint256(1)));
        f[2] = RLP.encode(address(0));
        f[3] = RLP.encode(stateRoot);
        f[4] = RLP.encode(bytes32(0));
        f[5] = RLP.encode(bytes32(0));
        f[6] = RLP.encode(new bytes(256));
        f[7] = RLP.encode(uint256(2));
        f[8] = RLP.encode(uint256(number));
        f[9] = RLP.encode(uint256(30_000_000));
        f[10] = RLP.encode(uint256(0));
        f[11] = RLP.encode(uint256(1_700_000_000 + number));
        f[12] = RLP.encode(unsealed);
        f[13] = RLP.encode(bytes32(0));
        f[14] = RLP.encode(new bytes(8));
        for (uint256 i = 15; i < f.length; i++) {
            f[i] = RLP.encode(uint256(7 + i));
        }
    }

    /// @dev Seal over the first `sealFields` fields (0 = all) with extra still unsealed.
    function _seal(bytes[] memory f, uint256 pk, uint256 sealFields) private pure returns (bytes memory) {
        uint256 k = sealFields == 0 ? f.length : sealFields;
        bytes[] memory s = new bytes[](k);
        for (uint256 i = 0; i < k; i++) {
            s[i] = f[i];
        }
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, keccak256(RLP.encode(s)));
        return abi.encodePacked(r, ss, v - 27);
    }

    function _simple(uint64 number, bytes32 parent, bytes32 stateRoot, uint256 pk) internal pure returns (Hdr memory) {
        return _hdr(number, parent, stateRoot, "", pk, 0, 0);
    }

    /// @dev A linked run from `start`, sealed by `pks` in order; header 0 commits to `stateRoot`.
    function _run(uint64 start, bytes32 stateRoot, uint256[] memory pks) internal pure returns (bytes[] memory hs) {
        hs = new bytes[](pks.length);
        bytes32 parent = keccak256("genesis-parent");
        for (uint256 i = 0; i < pks.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            (hs[i], parent) = _link(start + uint64(i), parent, i == 0 ? stateRoot : bytes32(uint256(i)), pks[i]);
        }
    }

    function _link(uint64 number, bytes32 parent, bytes32 root, uint256 pk)
        private
        pure
        returns (bytes memory, bytes32)
    {
        Hdr memory h = _simple(number, parent, root, pk);
        return (h.rlp, h.hash);
    }

    /// @dev Account + channel storage proofs for SERVICE_ADDR / SYNTHETIC_CHANNEL_ID (all slots zero).
    function _stateProofs()
        internal
        pure
        returns (bytes32 stateRoot, bytes memory accountProof, bytes memory storageRlp)
    {
        bytes32 storageRoot;
        (storageRoot, storageRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (stateRoot, accountProof) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
    }

    function _bundle(address[] memory set, bytes[] memory headers, bytes memory accountProof, bytes memory storageRlp)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](5);
        top[0] = RLP.encode(_packed(set));
        top[1] = RLP.encode(headers);
        top[2] = accountProof;
        top[3] = storageRlp;
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    /// @dev ClprMessagePayload{control{config_update{configuration}}} with chain id `caip2`.
    function _ledgerConfig(string memory caip2) internal pure returns (bytes memory) {
        bytes memory throttles = bytes.concat(
            _pbInt(1, 100), _pbInt(2, 10_000), _pbInt(3, 1_000_000), _pbInt(4, 1000), _pbInt(5, 1_000_000)
        );
        bytes memory config = bytes.concat(
            _pbInt(1, 1),
            _pbLen(2, bytes(caip2)),
            _pbLen(3, abi.encodePacked(SERVICE_ADDR)),
            _pbLen(4, _pbInt(1, 1_760_000_000)),
            _pbLen(5, throttles)
        );
        return _pbLen(3, _pbLen(1, _pbLen(1, config)));
    }

    /// @dev SignerReplayVerifier config: [ledgerConfiguration, headers (boundary first), codeHash].
    function _replayConfig(string memory caip2, bytes[] memory headers) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(_ledgerConfig(caip2));
        items[1] = RLP.encode(headers);
        items[2] = RLP.encode(SERVICE_CODE_HASH);
        return RLP.encode(items);
    }

    /// @dev Boundary block `number` listing `listBody`, sealed by `pkA`, followed by a child sealed by `pkB`.
    function _boundaryRun(uint64 number, bytes memory listBody, uint256 pkA, uint256 pkB)
        internal
        pure
        returns (bytes[] memory hs)
    {
        Hdr memory b = _hdr(number, keccak256("p"), bytes32(0), listBody, pkA, 0, 0);
        hs = new bytes[](2);
        hs[0] = b.rlp;
        hs[1] = _simple(number + 1, b.hash, bytes32(0), pkB).rlp;
    }

    /// @dev Config with a single embedded header (KaiaIstanbulVerifier).
    function _configProof(string memory caip2, bytes memory boundaryHeader) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(_ledgerConfig(caip2));
        items[1] = boundaryHeader;
        items[2] = RLP.encode(SERVICE_CODE_HASH);
        return RLP.encode(items);
    }

    function _pbVarint(uint256 v) internal pure returns (bytes memory out) {
        while (v >= 0x80) {
            // forge-lint: disable-next-line(unsafe-typecast)
            out = bytes.concat(out, bytes1(uint8(v & 0x7f) | 0x80));
            v >>= 7;
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        out = bytes.concat(out, bytes1(uint8(v)));
    }

    function _pbInt(uint256 field, uint256 v) internal pure returns (bytes memory) {
        return bytes.concat(_pbVarint(field << 3), _pbVarint(v));
    }

    function _pbLen(uint256 field, bytes memory data) internal pure returns (bytes memory) {
        return bytes.concat(_pbVarint((field << 3) | 2), _pbVarint(data.length), data);
    }
}
