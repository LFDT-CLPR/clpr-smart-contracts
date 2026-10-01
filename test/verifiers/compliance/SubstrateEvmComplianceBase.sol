// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {SubstrateSyntheticProofs} from "@test/helpers/SubstrateSyntheticProofs.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";

/// @notice Exposes SubstrateTrie.get so the cross-channel vector can name the exact node the
///         verifier must report missing.
contract SubstrateTrieProbe {
    function get(bytes32 root, bytes[] calldata nodes, bytes calldata key) external view returns (bool, bytes memory) {
        return SubstrateTrie.get(SubstrateTrie.load(nodes), root, key);
    }
}

/// @title SubstrateEvmComplianceBase
/// @notice Shared ClprVerifierComplianceTest (+ ClprEvmStorageComplianceTest) vectors for the
///         Substrate verifiers (GrandpaVerifier, BeefyParachainVerifier). The ClprService storage is
///         a synthetic Frontier `AccountStorages` trie built per vector, so any manifest commitment
///         or running hash can be proven. Concrete adapters only wrap a state root in their
///         finality proof (a GRANDPA justification, or BEEFY → relay state → para head).
///
///         The trie proofs carry only the nodes on the paths of the slots a vector intends to prove
///         (as `state_getReadProof` does). Vectors that must fail because a slot is "not proven"
///         keep that slot in the trie but out of the proof, so the verifier hits `MissingProofNode`
///         instead of proving the slot absent.
abstract contract SubstrateEvmComplianceBase is ClprEvmStorageComplianceTest, SubstrateSyntheticProofs {
    address internal constant SERVICE = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    address internal constant OTHER_SERVICE = 0x0000000000000000000000000000000000000Bad;
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant OTHER_CHANNEL_ID = bytes32(uint256(0xDEADBEEF));
    uint96 internal constant NANOS = 1_750_000_000_000_000_001;
    uint64 internal constant NEXT_MESSAGE_ID = 4;

    // ── Adapter hooks ────────────────────────────────────────────────────────

    function _chainId() internal pure virtual returns (string memory);
    function _anchor() internal view virtual returns (bytes memory);
    function _bundleProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory content)
        internal
        virtual
        returns (bytes memory);
    function _configProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory ledgerConfig)
        internal
        virtual
        returns (bytes memory);

    // ── Storage builders ─────────────────────────────────────────────────────

    function _channelBase(bytes32 channelId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(channelId, CHANNELS_BASE_SLOT)));
    }

    /// @dev The five Channel slots (+1, +2, +4, +5, +16) of `channelId` under `svc`.
    function _channelEntries(address svc, bytes32 channelId, bytes32 sentHash, bool prove)
        internal
        view
        returns (Entry[] memory e)
    {
        uint256 b = _channelBase(channelId);
        e = new Entry[](5);
        e[0] = _evmEntry(svc, bytes32(b + 1), bytes32((uint256(NEXT_MESSAGE_ID) << 168) | (1 << 160) | 0xbeef), prove);
        e[1] = _evmEntry(svc, bytes32(b + 2), bytes32(uint256(2) << 64), prove);
        e[2] = _evmEntry(svc, bytes32(b + 4), sentHash, prove);
        e[3] = _evmEntry(svc, bytes32(b + 5), keccak256("received"), prove);
        e[4] = _evmEntry(svc, bytes32(b + 16), bytes32(uint256(1)), prove);
    }

    function _concat(Entry[] memory a, Entry[] memory b) internal pure returns (Entry[] memory c) {
        c = new Entry[](a.length + b.length);
        for (uint256 i; i < a.length; ++i) {
            c[i] = a[i];
        }
        for (uint256 i; i < b.length; ++i) {
            c[a.length + i] = b[i];
        }
    }

    function _bundleFrom(Entry[] memory entries, bytes memory content) internal returns (bytes memory) {
        (bytes32 root, bytes[] memory nodes) = _buildTrie(entries);
        return _bundleProof(root, nodes, content);
    }

    /// @dev `_config.serviceAddress` (slot 25), `_config.nanosSinceEpoch` (26) and, if given, the
    ///      manifest commitment (18).
    function _configEntries(bool proveService, bytes memory committedManifest)
        internal
        view
        returns (Entry[] memory e)
    {
        e = new Entry[](committedManifest.length > 0 ? 3 : 2);
        e[0] =
            _evmEntry(SERVICE, bytes32(uint256(25)), bytes32(uint256(bytes32(bytes20(SERVICE))) | 0x28), proveService);
        e[1] = _evmEntry(SERVICE, bytes32(uint256(26)), bytes32(uint256(NANOS)), true);
        if (committedManifest.length > 0) {
            e[2] = _evmEntry(SERVICE, bytes32(MANIFEST_COMMITMENT_SLOT), keccak256(committedManifest), true);
        }
    }

    function _ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = NANOS;
        lc.throttles = ClprTypes.Throttles(10, 1024, 1_000_000, 100, 4096, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _configFrom(Entry[] memory entries, string memory chainId) internal returns (bytes memory) {
        (bytes32 root, bytes[] memory nodes) = _buildTrie(entries);
        return _configProof(root, nodes, _ledgerConfig(chainId));
    }

    function _ctx(bytes32 channelId, address svc) internal pure returns (bytes memory) {
        return abi.encodePacked(channelId, svc);
    }

    // ── ClprVerifierComplianceTest hooks ─────────────────────────────────────

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configFrom(_configEntries(true, ""), _chainId()),
            channelId: CHANNEL_ID,
            expectedChainId: _chainId(),
            expectedServiceAddress: abi.encodePacked(SERVICE)
        });
    }

    function _validBundle() internal override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundleFrom(_channelEntries(SERVICE, CHANNEL_ID, keccak256("sent"), true), ""),
            trustAnchor: _anchor(),
            channelContext: _ctx(CHANNEL_ID, SERVICE),
            expectedNextMessageId: NEXT_MESSAGE_ID,
            expectedPayloadCount: 0
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configFrom(_configEntries(true, committedPreimage), _chainId());
        channelId = CHANNEL_ID;
        // The manifest proof is the preimage; its commitment is proven against the config's state root.
        manifestProof = carriedPreimage;
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes[2] memory payloads = [bytes("payload-one"), bytes("payload-two")];
        bytes32 h;
        bytes memory content;
        for (uint256 i; i < payloads.length; ++i) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
            content = abi.encodePacked(content, hex"12", uint8(payloads[i].length), payloads[i]);
        }
        return RunningHashVector({
            proofBytes: _bundleFrom(_channelEntries(SERVICE, CHANNEL_ID, h, true), content),
            trustAnchor: _anchor(),
            channelContext: _ctx(CHANNEL_ID, SERVICE),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_configFrom(_configEntries(true, ""), "eip155:1"), CHANNEL_ID);
    }

    // ── ClprEvmStorageComplianceTest hooks ───────────────────────────────────

    function _crossChannelVector()
        internal
        override
        returns (
            bytes memory proofBytes,
            bytes memory trustAnchor,
            bytes memory attackerContext,
            bytes memory expectedRevert
        )
    {
        // Both channels exist in the trie; only CHANNEL_ID's slots are in the proof.
        Entry[] memory entries = _concat(
            _channelEntries(SERVICE, CHANNEL_ID, keccak256("sent"), true),
            _channelEntries(SERVICE, OTHER_CHANNEL_ID, keccak256("other"), false)
        );
        (bytes32 root, bytes[] memory nodes) = _buildTrie(entries);
        proofBytes = _bundleProof(root, nodes, "");
        trustAnchor = _anchor();
        attackerContext = _ctx(OTHER_CHANNEL_ID, SERVICE);
        // The verifier derives OTHER_CHANNEL_ID's first slot and walks into a node the proof omits.
        SubstrateTrieProbe probe = new SubstrateTrieProbe();
        try probe.get(root, nodes, _evmKey(SERVICE, bytes32(_channelBase(OTHER_CHANNEL_ID) + 1))) {
            revert("cross-channel vector: slot unexpectedly provable");
        } catch (bytes memory err) {
            require(bytes4(err) == SubstrateTrie.MissingProofNode.selector, "cross-channel vector: wrong probe error");
            expectedRevert = err;
        }
    }

    function _partialSlotCoverageVector() internal override returns (bytes memory, bytes32) {
        // serviceAddress (slot 25) is in the trie but not in the proof.
        return (_configFrom(_configEntries(false, ""), _chainId()), CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        Entry[] memory entries = _concat(
            _channelEntries(SERVICE, CHANNEL_ID, keccak256("sent"), true),
            _channelEntries(OTHER_SERVICE, CHANNEL_ID, keccak256("other"), false)
        );
        return (_bundleFrom(entries, ""), _anchor(), _ctx(CHANNEL_ID, OTHER_SERVICE));
    }

    function _threeSlotStorageVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        Entry[] memory entries = _channelEntries(SERVICE, CHANNEL_ID, keccak256("sent"), true);
        entries[3].prove = false;
        entries[4].prove = false;
        return (_bundleFrom(entries, ""), _anchor(), _ctx(CHANNEL_ID, SERVICE));
    }

    function _wrongSlotIndexVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        // The proof covers cBase+3 instead of cBase+4; cBase+4 is in the trie but unproven.
        Entry[] memory entries = _channelEntries(SERVICE, CHANNEL_ID, keccak256("sent"), true);
        entries[2].prove = false;
        Entry[] memory extra = new Entry[](1);
        extra[0] = _evmEntry(SERVICE, bytes32(_channelBase(CHANNEL_ID) + 3), keccak256("decoy"), true);
        return (_bundleFrom(_concat(entries, extra), ""), _anchor(), _ctx(CHANNEL_ID, SERVICE));
    }
}
