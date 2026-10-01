// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ZkSyncEraVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/ZkSyncEraVerifier.sol";
import {IZkSyncStateTreeVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/lib/IZkSyncStateTreeVerifier.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Blake2sHarness compiles in the legacy profile (see foundry.toml), so it is reached by interface.
interface IBlake2s {
    function hash64(bytes32 left, bytes32 right) external pure returns (bytes32);
    function hash40(bytes32 left, bytes32 right) external pure returns (bytes32);
}

/// @title ZkSyncEraComplianceTest
/// @notice The shared verifier compliance suite against {ZkSyncEraVerifier} with the real
///         {EthL1StateVerifier} and a generator sync committee (every member's sk = 1).
/// @dev Bundles come from the synthetic fixture (anvil L1 diamond + in-memory Blake2s tree,
///      test/e2e/relay/buildZkSyncSyntheticFixture.ts). Manifest vectors are built here for any preimage:
///      a one-leaf Blake2s tree (the commitment slot; the config pins no code hash, so no code entry is
///      needed), and an L1 state of one diamond account whose storage trie is a branch over the three
///      ZKChainStorage slots.
contract ZkSyncEraComplianceTest is ClprVerifierComplianceTest, EthCommitteeFixtures {
    bytes4 internal constant FORK_VERSION = 0x06000000;
    bytes32 internal constant GVR = bytes32(uint256(0x5e9011a));
    uint64 internal constant SLOT = 8192 * 3 + 5;
    uint256 internal constant PROTOCOL_VERSION = (29 << 32) | 1;
    /// Diamond used by the generated manifest vectors (the fixture's diamond is another address).
    address internal constant VECTOR_DIAMOND = 0xD1A0000000000000000000000000000000000999;

    string internal json;
    bytes32 internal l1StateRoot;
    address internal service;
    bytes32 internal channelId;
    IZkSyncStateTreeVerifier internal tree;
    EthL1StateVerifier internal l1;
    IBlake2s internal blake;
    bytes32[] internal emptyHashes;

    function setUp() public override(ClprVerifierComplianceTest, EthCommitteeFixtures) {
        EthCommitteeFixtures.setUp();
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/zksync/fixtures/synthetic.json"));
        l1StateRoot = vm.parseJsonBytes32(json, ".l1.stateRoot");
        service = vm.parseJsonAddress(json, ".l2.service");
        channelId = vm.parseJsonBytes32(json, ".l2.channelId");
        tree = IZkSyncStateTreeVerifier(deployCode("ZkSyncStateTreeVerifier.sol:ZkSyncStateTreeVerifier"));
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        blake = IBlake2s(deployCode("out/Blake2sHarness.sol/Blake2sHarness.json"));
        ClprVerifierComplianceTest.setUp();
    }

    /// A verifier pins one diamond: bundle vectors use the fixture's, manifest vectors redeploy for theirs.
    function _deployVerifier() internal override returns (IClprVerifier) {
        return
            IClprVerifier(address(new ZkSyncEraVerifier(l1, tree, _profile(vm.parseJsonAddress(json, ".l1.diamond")))));
    }

    function _profile(address diamond) internal pure returns (ZkSyncEraVerifier.Profile memory) {
        return ZkSyncEraVerifier.Profile({
            diamondProxy: diamond,
            totalBatchesExecutedSlot: 11,
            storedBatchHashesSlot: 14,
            protocolVersionSlot: 33,
            minProtocolVersion: PROTOCOL_VERSION,
            maxProtocolVersion: PROTOCOL_VERSION
        });
    }

    // ── Config ─────────────────────────────────────────────────────────────────

    function _config(bytes32 codeHash) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "eip155:300";
        lc.serviceAddress = abi.encodePacked(service);
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(SLOT));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), _committeeAggregate());
        cfg[2] = RLP.encode(GVR);
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(codeHash);
        return RLP.encode(cfg);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(vm.parseJsonBytes32(json, ".l2.serviceCodeHash")),
            channelId: channelId,
            expectedChainId: "eip155:300",
            expectedServiceAddress: abi.encodePacked(service)
        });
    }

    /// Compressed keys where the transport requires uncompressed ones: the config is for no chain this
    /// light client can follow.
    function _wrongChainConfigVector() internal pure override returns (bytes memory configProof, bytes32 cid) {
        ClprTypes.LedgerConfiguration memory lc;
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(_compressedKeys(SYNC_COMMITTEE_SIZE), G1_GEN_COMPRESSED);
        cfg[2] = RLP.encode(GVR);
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(bytes32(0));
        return (RLP.encode(cfg), bytes32(uint256(0xC0FFEE)));
    }

    // ── Bundles (fixture) ──────────────────────────────────────────────────────

    function _anchor() internal view returns (bytes memory) {
        return EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            _committeeAggregate(),
            GVR,
            abi.encodePacked(FORK_VERSION),
            channelId,
            vm.parseJsonBytes32(json, ".l2.serviceCodeHash")
        );
    }

    function _ctx() internal view returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(service)})
        );
    }

    function _bundle(string memory l2Path, bytes memory bundleContent) internal view returns (bytes memory) {
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(_lightClientProof(l1StateRoot));
        items[1] = vm.parseJsonBytes(json, ".batches.current.diamondProof");
        items[2] = RLP.encode(vm.parseJsonBytes(json, ".batches.current.info"));
        items[3] = RLP.encode(vm.parseJsonBytes(json, string.concat(".proofs.current.", l2Path)));
        items[4] = RLP.encode(bundleContent);
        return RLP.encode(items);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle("ack", ""),
            trustAnchor: _anchor(),
            channelContext: _ctx(),
            expectedNextMessageId: uint64(vm.parseJsonUint(json, ".l2.expected.nextMessageId")),
            expectedPayloadCount: 0
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        return RunningHashVector({
            proofBytes: _bundle("withMessage", vm.parseJsonBytes(json, ".l2.bundleContent")),
            trustAnchor: _anchor(),
            channelContext: _ctx(),
            previousRunningHash: bytes32(0)
        });
    }

    // ── Manifest vectors (built here) ──────────────────────────────────────────

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 cid, bytes memory manifestProof)
    {
        verifier = IClprVerifier(address(new ZkSyncEraVerifier(l1, tree, _profile(VECTOR_DIAMOND))));
        configProof = _config(bytes32(0)); // no code-hash pin: the tree holds only the commitment
        cid = channelId;

        // L2: a one-leaf tree holding slot 18 = keccak256(preimage) at leaf index 1.
        bytes32 commitment = keccak256(committedPreimage);
        bytes32 l2Root = _oneLeafRoot(service, bytes32(uint256(18)), commitment, 1);
        bytes memory l2Proof = abi.encodePacked(commitment, uint64(1), uint16(0));

        // L1: the diamond's three ZKChainStorage slots for batch `n`.
        (uint256 n, bytes32[3] memory slots) = _distinctNibbleBatch();
        bytes memory info = abi.encode(
            uint64(n), l2Root, uint64(7), uint256(0), bytes32(0), bytes32(0), bytes32(0), uint256(1), bytes32(0)
        );
        uint256[3] memory values = [n, uint256(keccak256(info)), PROTOCOL_VERSION];
        (bytes32 storageRoot, bytes[3] memory slotProofs) = _branchTrie(slots, values);
        (bytes32 stateRoot, bytes memory accountProof) = _oneLeafAccountTrie(VECTOR_DIAMOND, storageRoot);

        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(slots[i]);
            e[1] = slotProofs[i];
            entries[i] = RLP.encode(e);
        }
        bytes[] memory dp = new bytes[](2);
        dp[0] = accountProof;
        dp[1] = RLP.encode(entries);

        bytes[] memory p = new bytes[](5);
        p[0] = RLP.encode(_lightClientProof(stateRoot));
        p[1] = RLP.encode(dp);
        p[2] = RLP.encode(info);
        p[3] = RLP.encode(l2Proof);
        p[4] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(p);
    }

    // ── Light client ───────────────────────────────────────────────────────────

    /// Header at SLOT whose body commits `executionStateRoot`, signed by the full generator committee.
    function _lightClientProof(bytes32 executionStateRoot) internal view returns (bytes memory) {
        bytes32[] memory branch = new bytes32[](9);
        bytes32 bodyRoot = executionStateRoot;
        uint256 idx = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY;
        for (uint256 i = 0; i < 9; i++) {
            bodyRoot = idx & 1 == 1
                ? sha256(abi.encodePacked(branch[i], bodyRoot))
                : sha256(abi.encodePacked(bodyRoot, branch[i]));
            idx >>= 1;
        }
        bytes32 headerRoot = ClprBeaconSsz.beaconBlockHeaderRoot(SLOT, 7, bytes32(uint256(1)), bytes32(0), bodyRoot);
        bytes32 signingRoot =
            ClprBeaconSsz.computeSigningRoot(headerRoot, ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR));
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(SLOT));
        header[1] = RLP.encode(uint256(7));
        header[2] = RLP.encode(bytes32(uint256(1)));
        header[3] = RLP.encode(bytes32(0));
        header[4] = RLP.encode(bodyRoot);
        bytes memory bits = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            bits[i] = 0xff;
        }
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(_aggSig(signingRoot, SYNC_COMMITTEE_SIZE));
        bytes[] memory br = new bytes[](9);
        for (uint256 i = 0; i < 9; i++) {
            br[i] = RLP.encode(branch[i]);
        }
        bytes[] memory lc = new bytes[](7);
        lc[0] = RLP.encode(header);
        lc[1] = RLP.encode(agg);
        lc[2] = RLP.encode(executionStateRoot);
        lc[3] = RLP.encode(br);
        lc[4] = RLP.encode(bytes(""));
        lc[5] = RLP.encode(new bytes[](0));
        lc[6] = RLP.encode(new bytes[](0));
        return RLP.encode(lc);
    }

    // ── Blake2s tree (one leaf) ────────────────────────────────────────────────

    /// Root of a ZKsync tree whose only entry is (account, key) → value at `leafIndex`: the leaf folded up
    /// all 256 levels with empty-subtree siblings (so `zks_getProof` would return an empty path).
    function _oneLeafRoot(address account, bytes32 key, bytes32 value, uint64 leafIndex) internal returns (bytes32 h) {
        if (emptyHashes.length == 0) {
            bytes32 e = blake.hash40(0, 0);
            for (uint256 d = 0; d < 256; d++) {
                emptyHashes.push(e);
                e = blake.hash64(e, e);
            }
        }
        bytes32 k = blake.hash64(bytes32(uint256(uint160(account))), key);
        h = blake.hash40(bytes32((uint256(leafIndex) << 192) | (uint256(value) >> 64)), bytes32(uint256(value) << 192));
        for (uint256 d = 0; d < 256; d++) {
            // Bit d of the key read as a little-endian integer.
            bool bit = (uint8(k[d >> 3]) >> (d & 7)) & 1 == 1;
            h = bit ? blake.hash64(emptyHashes[d], h) : blake.hash64(h, emptyHashes[d]);
        }
    }

    // ── L1 tries ───────────────────────────────────────────────────────────────

    /// A batch number whose storedBatchHashes slot hashes to a first nibble different from those of
    /// slots 11 and 33, so the storage trie is one branch over three leaves.
    function _distinctNibbleBatch() internal pure returns (uint256 n, bytes32[3] memory slots) {
        slots[0] = bytes32(uint256(11));
        slots[2] = bytes32(uint256(33));
        uint8 a = _nibble0(slots[0]);
        uint8 c = _nibble0(slots[2]);
        require(a != c, "slots 11 and 33 share a first nibble");
        for (n = 1000;; n++) {
            slots[1] = keccak256(abi.encode(n, uint256(14)));
            uint8 b = _nibble0(slots[1]);
            if (b != a && b != c) return (n, slots);
        }
    }

    function _nibble0(bytes32 slot) internal pure returns (uint8) {
        return uint8(keccak256(abi.encodePacked(slot))[0]) >> 4;
    }

    /// Storage trie: a branch node whose children are leaves keyed by the remaining 63 nibbles.
    function _branchTrie(bytes32[3] memory slots, uint256[3] memory values)
        internal
        pure
        returns (bytes32 root, bytes[3] memory proofs)
    {
        bytes[] memory branch = new bytes[](17);
        for (uint256 i = 0; i < 17; i++) {
            branch[i] = RLP.encode(bytes(""));
        }
        bytes[3] memory leaves;
        for (uint256 i = 0; i < 3; i++) {
            bytes32 keyHash = keccak256(abi.encodePacked(slots[i]));
            bytes memory path = new bytes(32); // odd leaf: 0x3 ‖ nibble 1, then bytes 1..31
            path[0] = bytes1(0x30 | (uint8(keyHash[0]) & 0x0f));
            for (uint256 j = 1; j < 32; j++) {
                path[j] = keyHash[j];
            }
            bytes[] memory leaf = new bytes[](2);
            leaf[0] = RLP.encode(path);
            leaf[1] = RLP.encode(RLP.encode(values[i]));
            leaves[i] = RLP.encode(leaf);
            branch[uint8(keyHash[0]) >> 4] = RLP.encode(keccak256(leaves[i]));
        }
        bytes memory branchNode = RLP.encode(branch);
        root = keccak256(branchNode);
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory nodes = new bytes[](2);
            nodes[0] = RLP.encode(branchNode);
            nodes[1] = RLP.encode(leaves[i]);
            proofs[i] = RLP.encode(nodes);
        }
    }

    /// State trie with one account (nonce 0, balance 0, `storageRoot`, empty code hash).
    function _oneLeafAccountTrie(address account, bytes32 storageRoot)
        internal
        pure
        returns (bytes32 root, bytes memory proof)
    {
        bytes32 keyHash = keccak256(abi.encodePacked(account));
        bytes memory path = new bytes(33);
        path[0] = 0x20; // even leaf
        for (uint256 i = 0; i < 32; i++) {
            path[i + 1] = keyHash[i];
        }
        bytes[] memory acct = new bytes[](4);
        acct[0] = RLP.encode(uint256(0));
        acct[1] = RLP.encode(uint256(0));
        acct[2] = RLP.encode(storageRoot);
        acct[3] = RLP.encode(keccak256(""));
        bytes[] memory leaf = new bytes[](2);
        leaf[0] = RLP.encode(path);
        leaf[1] = RLP.encode(RLP.encode(acct));
        bytes memory leafNode = RLP.encode(leaf);
        root = keccak256(leafNode);
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(leafNode);
        proof = RLP.encode(nodes);
    }
}
