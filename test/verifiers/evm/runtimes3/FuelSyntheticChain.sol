// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Runtimes3TestBase} from "./Runtimes3TestBase.sol";
import {MockEthL1StateVerifier} from "./MockEthL1StateVerifier.sol";
import {FuelVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/FuelVerifier.sol";
import {FuelBlockProof} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/FuelBlockProof.sol";
import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Synthetic-chain builders shared by the unit tests and the IClprVerifier compliance adapter.
abstract contract FuelSyntheticChain is Runtimes3TestBase {
    using Memory for Memory.Slice;

    MockEthL1StateVerifier internal l1;
    FuelVerifier internal fuel;

    address internal constant CHAIN_STATE = address(0xF0E1);
    bytes32 internal constant CODE_HASH = keccak256("FuelChainState proxy code");
    address internal constant IMPL = address(0x1111);
    bytes32 internal constant RECIPIENT = bytes32(uint256(0xC1C1));
    bytes32 internal constant SERVICE = keccak256("fuel clpr contract id");
    uint64 internal constant COMMIT_TS = 1_000_000;
    uint64 internal constant TTF = 3600;
    uint64 internal constant FINAL_SLOT = (COMMIT_TS + TTF) / 12 + 1;

    function _deployFuel() internal {
        l1 = new MockEthL1StateVerifier();
        fuel = new FuelVerifier(_profile(TTF, IMPL));
    }

    function _profile(uint64 ttf, address impl) internal view returns (FuelVerifier.Profile memory p) {
        p = FuelVerifier.Profile({
            l1StateVerifier: IEthL1StateVerifier(address(l1)),
            l1GenesisTime: 0,
            l1SecondsPerSlot: 12,
            chainState: CHAIN_STATE,
            chainStateCodeHash: CODE_HASH,
            chainStateImplementation: impl,
            commitSlotsBase: 301,
            pausedSlot: 51,
            numCommitSlots: 240,
            blocksPerCommitInterval: 1,
            timeToFinalize: ttf,
            messageRecipient: RECIPIENT
        });
    }

    // ── Synthetic Fuel chain ─────────────────────────────────────────────────

    struct Msg {
        bytes32 sender;
        bytes32 recipient;
        bytes32 nonce;
        uint64 amount;
        bytes data;
    }

    struct FuelChain {
        bytes commitHeader;
        bytes messageHeader;
        bytes blockProof;
        bytes messageProof;
        bytes message;
        bytes32 commitId;
    }

    function _msg(bytes memory record) internal pure returns (Msg memory) {
        return Msg({
            sender: SERVICE,
            recipient: RECIPIENT,
            nonce: keccak256("nonce"),
            amount: 0,
            data: abi.encodePacked(CHANNEL_ID, record)
        });
    }

    function _merkle(uint256 index, bytes32[] memory siblings) internal pure returns (bytes memory) {
        bytes[] memory s = new bytes[](siblings.length);
        for (uint256 i; i < siblings.length; ++i) {
            s[i] = RLP.encode(siblings[i]);
        }
        bytes[] memory f = new bytes[](2);
        f[0] = RLP.encode(index);
        f[1] = RLP.encode(s);
        return RLP.encode(f);
    }

    /// @dev Message block at height 1 (one message), committed block at height 2 whose prevRoot
    ///      covers blocks 0 and 1.
    function _chain(Msg memory m) internal pure returns (FuelChain memory c) {
        bytes32 id = FuelBlockProof.messageId(m.sender, m.recipient, m.nonce, m.amount, m.data);
        c.messageHeader = abi.encodePacked(
            keccak256("prev root of block 1"),
            uint32(1),
            uint64(4611686020218000000),
            uint64(7),
            uint32(1),
            uint32(1),
            uint16(1),
            uint32(1),
            keccak256("tx root"),
            FuelBlockProof.leafDigest(id),
            keccak256("event inbox root")
        );
        bytes32 messageBlockId = FuelBlockProof.fullHeader(c.messageHeader).id;
        bytes32 block0Leaf = FuelBlockProof.leafDigest(keccak256("block 0 id"));
        bytes32 prevRoot = FuelBlockProof.nodeDigest(block0Leaf, FuelBlockProof.leafDigest(messageBlockId));
        c.commitHeader = abi.encodePacked(prevRoot, uint32(2), uint64(4611686020218000100), keccak256("app hash 2"));
        c.commitId = sha256(c.commitHeader);
        bytes32[] memory sib = new bytes32[](1);
        sib[0] = block0Leaf;
        c.blockProof = _merkle(1, sib);
        c.messageProof = _merkle(0, new bytes32[](0));
        bytes[] memory mf = new bytes[](5);
        mf[0] = RLP.encode(m.sender);
        mf[1] = RLP.encode(m.recipient);
        mf[2] = RLP.encode(m.nonce);
        mf[3] = RLP.encode(uint256(m.amount));
        mf[4] = RLP.encode(m.data);
        c.message = RLP.encode(mf);
    }

    // ── Synthetic FuelChainState storage (MPT: one branch, four leaves) ─────

    function _leaf(bytes32 slot, bytes32 value) internal pure returns (bytes memory) {
        bytes32 k = keccak256(abi.encodePacked(slot));
        bytes memory compact = new bytes(32);
        compact[0] = bytes1(0x30 | (uint8(k[0]) & 0x0f));
        for (uint256 i = 1; i < 32; i++) {
            compact[i] = k[i];
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(compact);
        items[1] = RLP.encode(RLP.encode(uint256(value)));
        return RLP.encode(items);
    }

    function _storage(bytes32[] memory slots, bytes32[] memory values)
        internal
        pure
        returns (bytes32 root, bytes memory storageProof)
    {
        bytes[] memory leaves = new bytes[](slots.length);
        bytes[] memory branch = new bytes[](17);
        for (uint256 n; n < 17; ++n) {
            branch[n] = RLP.encode(new bytes(0));
        }
        for (uint256 i; i < slots.length; ++i) {
            leaves[i] = _leaf(slots[i], values[i]);
            uint8 nib = uint8(keccak256(abi.encodePacked(slots[i]))[0]) >> 4;
            require(keccak256(branch[nib]) == keccak256(RLP.encode(new bytes(0))), "nibble collision");
            branch[nib] = RLP.encode(abi.encodePacked(keccak256(leaves[i])));
        }
        bytes memory branchNode = RLP.encode(branch);
        root = keccak256(branchNode);
        bytes[] memory entries = new bytes[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            bytes[] memory nodes = new bytes[](2);
            nodes[0] = RLP.encode(branchNode);
            nodes[1] = RLP.encode(leaves[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slots[i]));
            entry[1] = RLP.encode(nodes);
            entries[i] = RLP.encode(entry);
        }
        storageProof = RLP.encode(entries);
    }

    function _account(bytes32 storageRoot, bytes32 codeHash) internal pure returns (bytes32 root, bytes memory proof) {
        bytes32 k = keccak256(abi.encodePacked(CHAIN_STATE));
        bytes memory path = abi.encodePacked(bytes1(0x20), k);
        bytes[] memory acct = new bytes[](4);
        acct[0] = RLP.encode(uint256(1));
        acct[1] = RLP.encode(uint256(0));
        acct[2] = RLP.encode(storageRoot);
        acct[3] = RLP.encode(codeHash);
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = RLP.encode(RLP.encode(acct));
        bytes memory leaf = RLP.encode(items);
        root = keccak256(leaf);
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(leaf);
        proof = RLP.encode(nodes);
    }

    struct L1Opts {
        bytes32 committedId;
        uint64 commitTs;
        bool paused;
        address impl;
        bytes32 codeHash;
    }

    function _l1(FuelChain memory c) internal pure returns (L1Opts memory) {
        return L1Opts({committedId: c.commitId, commitTs: COMMIT_TS, paused: false, impl: IMPL, codeHash: CODE_HASH});
    }

    function _bundle(FuelChain memory c, L1Opts memory o, uint64 slot, bytes memory manifest)
        internal
        returns (bytes memory)
    {
        bytes32[] memory slots = fuel.chainStateSlots(2);
        bytes32[] memory values = new bytes32[](4);
        values[0] = o.committedId;
        values[1] = bytes32(uint256(o.commitTs));
        values[2] = o.paused ? bytes32(uint256(1)) : bytes32(0);
        values[3] = bytes32(uint256(uint160(o.impl)));
        (bytes32 storageRoot, bytes memory storageProof) = _storage(slots, values);
        (bytes32 stateRoot, bytes memory accountProof) = _account(storageRoot, o.codeHash);
        l1.set(stateRoot, slot, "");

        bytes[] memory items = new bytes[](manifest.length == 0 ? 9 : 10);
        items[0] = RLP.encode(bytes("light client proof (mocked)"));
        items[1] = accountProof;
        items[2] = storageProof;
        items[3] = RLP.encode(c.commitHeader);
        items[4] = RLP.encode(c.messageHeader);
        items[5] = c.blockProof;
        items[6] = c.messageProof;
        items[7] = c.message;
        items[8] = RLP.encode(_bundleContent());
        if (manifest.length != 0) items[9] = RLP.encode(manifest);
        return RLP.encode(items);
    }

    /// @dev The 8-item `verifyFuelMessage` proof of `c`'s message (sets the mock L1 state root).
    function _messageProof(FuelChain memory c) internal returns (bytes memory) {
        bytes memory full = _bundle(c, _l1(c), FINAL_SLOT, "");
        Memory.Slice[] memory all = RLP.decodeList(full);
        bytes[] memory items = new bytes[](8);
        for (uint256 i; i < 8; ++i) {
            items[i] = _raw(all[i]);
        }
        return RLP.encode(items);
    }

    /// @dev The full RLP encoding of an item (header and payload).
    function _raw(Memory.Slice item) internal pure returns (bytes memory) {
        return item.toBytes();
    }

    function _anchor(bytes32 channelId) internal pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("gvr"), bytes4(0x06000000), channelId, new bytes(128), keccak256("committee root"), CODE_HASH
        );
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    function _default() internal returns (bytes memory) {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        return _bundle(c, _l1(c), FINAL_SLOT, "");
    }
}
