// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SignerReplaySynthetic} from "@test/helpers/SignerReplaySynthetic.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic Kaia Istanbul headers for KaiaIstanbulVerifier tests: Kaia's header layout,
///      extra = vanity32 ‖ RLP([validators, seal, committedSeals]), block hash without committed
///      seals and round byte, committed seals over keccak256(hash ‖ 0x02), and Kaia's
///      SmartContractAccount leaf in the synthetic state trie.
abstract contract KaiaSynthetic is SignerReplaySynthetic {
    struct KHdr {
        bytes rlp;
        bytes32 hash;
    }

    function _kaiaFields(uint64 number, bytes32 stateRoot, bytes memory extra)
        internal
        pure
        returns (bytes[] memory f)
    {
        f = new bytes[](15);
        f[0] = RLP.encode(keccak256(abi.encode("parent", number)));
        f[1] = RLP.encode(address(0xBEEF)); // rewardbase
        f[2] = RLP.encode(stateRoot);
        f[3] = RLP.encode(bytes32(0));
        f[4] = RLP.encode(bytes32(0));
        f[5] = RLP.encode(new bytes(256));
        f[6] = RLP.encode(uint256(1)); // blockScore
        f[7] = RLP.encode(uint256(number));
        f[8] = RLP.encode(uint256(0));
        f[9] = RLP.encode(uint256(1_700_000_000 + number));
        f[10] = RLP.encode(uint256(0x3e)); // timeFoS
        f[11] = RLP.encode(extra);
        f[12] = RLP.encode(new bytes(0)); // governance
        f[13] = RLP.encode(new bytes(0)); // vote
        f[14] = RLP.encode(uint256(25 gwei)); // baseFee
    }

    function _addrList(address[] memory a) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            items[i] = RLP.encode(a[i]);
        }
        return RLP.encode(items);
    }

    function _extra(uint8 round, address[] memory validators, bytes memory seal, bytes[] memory committed)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory vanity = new bytes(32);
        vanity[31] = bytes1(round);
        bytes[] memory cs = new bytes[](committed.length);
        for (uint256 i = 0; i < committed.length; i++) {
            cs[i] = RLP.encode(committed[i]);
        }
        bytes[] memory items = new bytes[](3);
        items[0] = _addrList(validators);
        items[1] = RLP.encode(seal);
        items[2] = RLP.encode(cs);
        return bytes.concat(vanity, RLP.encode(items));
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v - 27);
    }

    /// @dev A Kaia header with `validators` as its qualified set, committed by `committerPks`.
    function _kaiaHeader(
        uint64 number,
        bytes32 stateRoot,
        address[] memory validators,
        uint256[] memory committerPks,
        uint8 round
    ) internal pure returns (KHdr memory h) {
        bytes memory proposerSeal = _sig(uint256(keccak256("proposer")), keccak256(abi.encode(number)));
        bytes[] memory none = new bytes[](0);
        // Block hash: committed seals empty, round byte 0.
        h.hash = keccak256(RLP.encode(_kaiaFields(number, stateRoot, _extra(0, validators, proposerSeal, none))));
        bytes32 digest = keccak256(abi.encodePacked(h.hash, uint8(2)));
        bytes[] memory committed = new bytes[](committerPks.length);
        for (uint256 i = 0; i < committerPks.length; i++) {
            committed[i] = _sig(committerPks[i], digest);
        }
        h.rlp = RLP.encode(_kaiaFields(number, stateRoot, _extra(round, validators, proposerSeal, committed)));
    }

    function _addrs(uint256[] memory pks) internal pure returns (address[] memory a) {
        a = new address[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            a[i] = vm.addr(pks[i]);
        }
    }

    function _prefix(uint256[] memory pks, uint256 n) internal pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = pks[i];
        }
    }

    function _kaiaAnchor(address[] memory set, uint64 setBlock) internal pure returns (bytes memory) {
        return _anchor(set, setBlock);
    }

    /// @dev Kaia SmartContractAccount leaf: 0x02 ‖ RLP([common, storageRoot, codeHash, codeInfo]).
    function _kaiaAccountLeaf(bytes32 storageRoot, bytes32 codeHash, uint8 accountType)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory common = new bytes[](5);
        common[0] = RLP.encode(uint256(1)); // nonce
        common[1] = RLP.encode(uint256(0)); // balance
        common[2] = RLP.encode(uint256(0)); // humanReadable
        common[3] = RLP.encode(uint256(3)); // key type
        common[4] = RLP.encode(new bytes[](0));
        bytes[] memory f = new bytes[](4);
        f[0] = RLP.encode(common);
        f[1] = RLP.encode(storageRoot);
        f[2] = RLP.encode(codeHash);
        f[3] = RLP.encode(uint256(0x10));
        return bytes.concat(bytes1(accountType), RLP.encode(f));
    }

    function _kaiaStateProofs(uint8 accountType)
        internal
        pure
        returns (bytes32 stateRoot, bytes memory accountProof, bytes memory storageRlp)
    {
        bytes32 storageRoot;
        (storageRoot, storageRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (stateRoot, accountProof) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(SERVICE_ADDR)), _kaiaAccountLeaf(storageRoot, SERVICE_CODE_HASH, accountType)
        );
    }

    function _kaiaBundle(
        address[] memory set,
        bytes[] memory headers,
        bytes memory accountProof,
        bytes memory storageRlp
    ) internal pure returns (bytes memory) {
        return _bundle(set, headers, accountProof, storageRlp);
    }

    function _kaiaConfig(string memory caip2, bytes memory header) internal pure returns (bytes memory) {
        return _configProof(caip2, header);
    }
}
