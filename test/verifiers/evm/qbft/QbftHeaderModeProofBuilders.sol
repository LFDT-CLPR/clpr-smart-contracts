// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {QbftValidators} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";

/// @dev Assembles complete header-mode bundles: sets, sealed headers listing them, hops, anchors
///      and config proofs — one construction point for the unit, gas-baseline and report suites.
abstract contract QbftHeaderModeProofBuilders is QbftContractProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    /// @dev The current block's header plus the service-account and channel proofs under its state.
    struct HeaderBlock {
        bytes header;
        bytes svcAccountProof;
        bytes channelProofRlp;
    }

    /// @dev An `n`-member set from one seed: member i is vm.addr(keccak256(seed, i)). A larger `n`
    ///      with the same seed is a superset, so `_setN(seed, n + 1)` models adding one validator.
    function _setN(string memory seed, uint256 n) internal pure returns (address[] memory s) {
        s = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = vm.addr(uint256(keccak256(abi.encodePacked(seed, i))));
        }
    }

    /// @dev The first `count` sealer private keys from the same seed sequence as _setN.
    function _pksN(string memory seed, uint256 count) internal pure returns (uint256[] memory p) {
        p = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            p[i] = uint256(keccak256(abi.encodePacked(seed, i)));
        }
    }

    function _syntheticChannelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    /// @dev A header-mode trust anchor: abi.encode(mode=0, setCommitment, codeHash, anchorBlockNumber).
    function _headerAnchor(address[] memory validators, uint64 blockNo) internal pure returns (bytes memory) {
        return abi.encode(uint8(0), _commit(validators), SERVICE_CODE_HASH, blockNo);
    }

    /// @dev Payload field 1: RLP([trustedSet, hops]). Each hop is a bare block header.
    function _headerSourceField(address[] memory trustedSet, bytes[] memory hops) internal pure returns (bytes memory) {
        bytes[] memory source = new bytes[](2);
        source[0] = _memberListRlp(trustedSet);
        source[1] = RLP.encode(hops);
        return RLP.encode(source);
    }

    /// @dev A change block: a header at `blockNo` listing `listed` and sealed by `sealerPks`.
    function _hopHeader(address[] memory listed, uint256[] memory sealerPks, uint64 blockNo)
        internal
        pure
        returns (bytes memory)
    {
        return _buildListedSealedHeader(blockNo, bytes32(0), listed, sealerPks);
    }

    /// @dev The current block at `blockNo`: header listing `listed`, sealed by `sealerPks`, whose
    ///      state holds the service account and the channel slots.
    function _currentBlock(address[] memory listed, uint256[] memory sealerPks, uint64 blockNo)
        internal
        pure
        returns (HeaderBlock memory b)
    {
        bytes32 storageRoot;
        (storageRoot, b.channelProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        bytes32 stateRoot;
        (stateRoot, b.svcAccountProof) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        b.header = _buildListedSealedHeader(blockNo, stateRoot, listed, sealerPks);
    }

    /// @dev The 5-field bundle proof from a current block, the trusted set and the hops.
    function _topProof(HeaderBlock memory b, address[] memory trustedSet, bytes[] memory hops)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](5);
        top[0] = b.header;
        top[1] = _headerSourceField(trustedSet, hops);
        top[2] = b.svcAccountProof;
        top[3] = b.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    /// @dev A steady-state bundle over an `n`-member set derived from `seed`, sealed by quorum(n).
    function _steadyScenario(string memory seed, uint256 n)
        internal
        pure
        returns (bytes memory proof, bytes memory anchor)
    {
        address[] memory set = _setN(seed, n);
        HeaderBlock memory b = _currentBlock(set, _pksN(seed, QbftValidators.quorum(n)), 100);
        proof = _topProof(b, set, new bytes[](0));
        anchor = _headerAnchor(set, 0);
    }

    /// @dev A one-hop rotation `n -> n+1`: the change block 300 lists the new set and is sealed by
    ///      a quorum of the new list drawn from the old members; the current block 301 lists and is
    ///      sealed by the new set.
    function _rotationScenario(string memory seed, uint256 n)
        internal
        pure
        returns (bytes memory proof, bytes memory anchor)
    {
        address[] memory oldSet = _setN(seed, n);
        address[] memory newSet = _setN(seed, n + 1);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hopHeader(newSet, _pksN(seed, QbftValidators.quorum(n + 1)), 300);
        HeaderBlock memory b = _currentBlock(newSet, _pksN(seed, QbftValidators.quorum(n + 1)), 301);
        proof = _topProof(b, oldSet, hops);
        anchor = _headerAnchor(oldSet, 0);
    }

    /// @dev A config proof over a 3-member set derived from `seed`: block 500 lists the set and is
    ///      sealed by a quorum of it.
    function _configScenario(string memory seed) internal pure returns (bytes memory) {
        address[] memory set = _setN(seed, 3);
        bytes memory header = _buildListedSealedHeader(500, bytes32(0), set, _pksN(seed, 2));
        return _buildHeaderModeConfigProof(header, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1");
    }
}
