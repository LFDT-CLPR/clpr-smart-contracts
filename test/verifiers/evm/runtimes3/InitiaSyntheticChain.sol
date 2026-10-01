// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Runtimes3TestBase} from "./Runtimes3TestBase.sol";
import {MockCometBftHeaderSource} from "./MockCometBftHeaderSource.sol";
import {InitiaMoveVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/InitiaMoveVerifier.sol";
import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ICometBftHeaderSource} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/ICometBftHeaderSource.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic-chain builders shared by the unit tests and the IClprVerifier compliance adapter.
abstract contract InitiaSyntheticChain is Runtimes3TestBase {
    MockCometBftHeaderSource internal source;
    InitiaMoveVerifier internal initia;

    bytes32 internal constant SET_A = keccak256("validator set A");
    bytes32 internal constant SET_B = keccak256("validator set B");
    bytes32 internal constant SERVICE = bytes32(uint256(0xc1a9));
    bytes32 internal constant HANDLE = keccak256("channels table handle");
    uint64 internal constant ANCHOR_HEIGHT = 1000;

    function _deployInitia() internal {
        source = new MockCometBftHeaderSource();
        initia = new InitiaMoveVerifier(source, SET_A, ANCHOR_HEIGHT);
    }

    // ── Builders ─────────────────────────────────────────────────────────────

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    function _anchor(bytes32 setHash, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(setHash, height, HANDLE);
    }

    function _headerRef(bytes32 headerHash) internal pure returns (bytes memory) {
        return PB.encodeBytesField(3, abi.encodePacked(headerHash));
    }

    function _register(bytes32 headerHash, bytes32 setHash, bytes32 nextSet, bytes32 appHash, uint64 height) internal {
        source.setFinalized(
            headerHash,
            ICometBftHeaderSource.Header({
                validatorsHash: setHash, nextValidatorsHash: nextSet, appHash: appHash, height: height
            })
        );
    }

    struct Built {
        bytes multistore;
        bytes entry;
        bytes32 appHash;
    }

    function _proofs(bytes memory key, bytes memory value) internal pure returns (Built memory b) {
        Ics23Proof memory iavl = _iavlProof(key, value, keccak256("right sibling"));
        Ics23Proof memory ms = _multistoreProof("move", iavl.root, keccak256("acc store"));
        b.multistore = ms.encoded;
        b.entry = iavl.encoded;
        b.appHash = ms.root;
    }

    function _bundle(
        bytes[] memory hops,
        bytes32 headerHash,
        Built memory b,
        bytes memory record,
        bytes memory manifest
    ) internal pure returns (bytes memory) {
        bytes[] memory hopItems = new bytes[](hops.length);
        for (uint256 i; i < hops.length; ++i) {
            hopItems[i] = RLP.encode(hops[i]);
        }
        bytes[] memory items = new bytes[](manifest.length == 0 ? 6 : 7);
        items[0] = RLP.encode(hopItems);
        items[1] = RLP.encode(_headerRef(headerHash));
        items[2] = RLP.encode(b.multistore);
        items[3] = RLP.encode(b.entry);
        items[4] = RLP.encode(record);
        items[5] = RLP.encode(_bundleContent());
        if (manifest.length != 0) items[6] = RLP.encode(manifest);
        return RLP.encode(items);
    }

    function _recordKey() internal view returns (bytes memory) {
        return initia.tableEntryKey(HANDLE, abi.encodePacked(CHANNEL_ID));
    }

    function _simpleBundle(bytes memory record, bytes32 nextSet) internal returns (bytes memory) {
        Built memory b = _proofs(_recordKey(), record);
        bytes32 hh = keccak256("header 1200");
        _register(hh, SET_A, nextSet, b.appHash, 1200);
        return _bundle(new bytes[](0), hh, b, record, "");
    }

    function _config(string memory chainId, bytes memory resource) internal returns (bytes memory) {
        bytes memory key = initia.resourceKey(SERVICE, "clpr", "Service");
        Built memory b = _proofs(key, resource);
        bytes32 hh = keccak256("config header");
        _register(hh, SET_A, SET_A, b.appHash, 1500);
        bytes[] memory items = new bytes[](6);
        items[0] = RLP.encode(_controlMessage(chainId, abi.encodePacked(SERVICE)));
        items[1] = RLP.encode(new bytes[](0));
        items[2] = RLP.encode(_headerRef(hh));
        items[3] = RLP.encode(b.multistore);
        items[4] = RLP.encode(b.entry);
        items[5] = RLP.encode(resource);
        return RLP.encode(items);
    }
}
