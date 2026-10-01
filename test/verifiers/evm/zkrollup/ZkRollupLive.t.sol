// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {L1RollupStateRoot} from "@hiero-ledger/clpr/libraries/proof/zkrollup/L1RollupStateRoot.sol";
import {L1RollupVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/L1RollupVerifierBase.sol";
import {L1RollupMptVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/L1RollupMptVerifier.sol";
import {LineaRollupVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/LineaRollupVerifier.sol";
import {LineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/LineaStateTrieVerifier.sol";
import {ILineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/lib/ILineaStateTrieVerifier.sol";
import {ZkRollupProfiles} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/profiles/ZkRollupProfiles.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {LineaPoseidon2Code} from "@hiero-ledger/clpr/libraries/proof/linea/LineaPoseidon2Code.sol";

/// @notice Shared deployment helpers: the Electra/Fulu L1 light client and the LineaPoseidon2 hasher.
abstract contract ZkRollupTestBase is Test {
    function _deployL1() internal returns (EthL1StateVerifier) {
        return new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
    }

    function _deployPoseidon2() internal returns (address) {
        return LineaPoseidon2Code.deploy();
    }
}

/// @notice The L1-settled rollup verifiers against REAL Ethereum-mainnet data: the mainnet sync
///         committee's signature (with its real non-signers), the rollup contract's storage at that L1
///         block, and the rollup's L2 state at the finalized root. Inputs: `fixtures/<chain>-live.json`,
///         written by `npm run zkrollup-live:forge` from test/e2e/fixtures/<chain>-live/capture.json.
///         Verifiers are deployed from the PINNED profiles in {ZkRollupProfiles}, never from captured values.
abstract contract ZkRollupLiveTest is ZkRollupTestBase {
    string internal json;
    EthL1StateVerifier internal l1;
    L1RollupVerifierBase internal verifier;
    bytes internal anchor;
    bytes internal ctx;

    function _chain() internal pure virtual returns (string memory);
    function _profile() internal pure virtual returns (L1RollupStateRoot.Profile memory);
    function _deploy(L1RollupStateRoot.Profile memory p) internal virtual returns (L1RollupVerifierBase);

    function setUp() public virtual {
        json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/verifiers/evm/zkrollup/fixtures/", _chain(), "-live.json")
        );
        l1 = _deployL1();
        verifier = _deploy(_profile());
        anchor = vm.parseJsonBytes(json, ".trustAnchor");
        ctx = vm.parseJsonBytes(json, ".channelContext");
    }

    function _bytes(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", key));
    }

    function _key() internal view returns (uint256) {
        return vm.parseJsonUint(json, ".key");
    }

    function test_profileMatchesLiveChain() public view {
        L1RollupStateRoot.Profile memory p = _profile();
        assertEq(p.rollup, vm.parseJsonAddress(json, ".rollup"));
        assertEq(p.stateRootsSlot, vm.parseJsonUint(json, ".stateRootsSlot"));
        assertEq(p.implementation, vm.parseJsonAddress(json, ".implementation"));
        assertEq(verifier.ROLLUP(), p.rollup);
    }

    function test_l2StateRoot() public view {
        (uint256 key, bytes32 root, bytes memory na, bytes memory naId) =
            verifier.verifyL2StateRoot(_bytes("l2StateRootProof"), anchor);
        assertEq(key, _key());
        assertEq(root, vm.parseJsonBytes32(json, ".l2StateRoot"));
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    function test_fullBundle() public {
        bytes memory bundle = _bytes("bundle");
        uint256 g = gasleft();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory msgs,
            bytes memory na,,
            ClprTypes.ClprEndpointManifest memory em
        ) = verifier.verifyBundle(bundle, anchor, ctx);
        console.log("verifyBundle execution gas", g - gasleft());
        console.log("bundle bytes", bundle.length);
        // The stand-in account has no channel: every slot is a genuine exclusion proof.
        assertEq(m.nextMessageId, 0);
        assertEq(m.receivedMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
        assertEq(msgs.length, 0);
        assertEq(na.length, 0);
        assertEq(em.version, 0);
    }

    function test_rejectsNotFinalizedKey() public {
        vm.expectRevert(abi.encodeWithSelector(L1RollupStateRoot.StateRootNotFinalized.selector, _key() + 1));
        verifier.verifyL2StateRoot(_bytes("notFinalizedProof"), anchor);
    }

    function test_rejectsBelowThreshold() public {
        vm.expectRevert(abi.encodeWithSelector(EthBeaconLightClient.InsufficientParticipation.selector, 341, 512));
        verifier.verifyL2StateRoot(_bytes("belowThresholdProof"), anchor);
    }

    function test_rejectsBadSignatureDomain() public {
        bytes memory bad = bytes.concat(anchor);
        bad[EthBeaconLightClient.ANCHOR_OFF_FORK_VERSION] ^= 0x01; // the real signature no longer verifies
        vm.expectRevert();
        verifier.verifyBundle(_bytes("bundle"), bad, ctx);
    }

    function test_rejectsWrongCommittee() public {
        bytes memory bad = bytes.concat(anchor);
        bad[EthBeaconLightClient.ANCHOR_OFF_COMMITTEE_ROOT] ^= 0x01;
        vm.expectRevert();
        verifier.verifyBundle(_bytes("bundle"), bad, ctx);
    }

    function test_rejectsWrongCodeHash() public {
        bytes memory bad = bytes.concat(anchor);
        bad[EthBeaconLightClient.ANCHOR_OFF_CODE_HASH] ^= 0x01;
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(_bytes("bundle"), bad, ctx);
    }

    function test_rejectsOtherChannel() public {
        bytes memory bad = bytes.concat(anchor);
        bad[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID] ^= 0x01; // other channelId → other derived slots
        vm.expectRevert();
        verifier.verifyBundle(_bytes("bundle"), bad, ctx);
    }

    function test_rejectsOtherServiceAddress() public {
        bytes memory bad = bytes.concat(ctx);
        bad[bad.length - 1] ^= 0x01;
        vm.expectRevert();
        verifier.verifyBundle(_bytes("bundle"), anchor, bad);
    }

    function test_failsClosedAfterRollupUpgrade() public {
        L1RollupStateRoot.Profile memory p = _profile();
        address actual = p.implementation;
        p.implementation = address(0xdEaD);
        L1RollupVerifierBase other = _deploy(p);
        vm.expectRevert(
            abi.encodeWithSelector(L1RollupStateRoot.ImplementationMismatch.selector, p.implementation, actual)
        );
        other.verifyL2StateRoot(_bytes("l2StateRootProof"), anchor);
    }

    function test_rejectsOtherRollupContract() public {
        L1RollupStateRoot.Profile memory p = _profile();
        p.rollup = address(0xBEEF);
        L1RollupVerifierBase other = _deploy(p);
        vm.expectRevert();
        other.verifyL2StateRoot(_bytes("l2StateRootProof"), anchor);
    }

    function test_rejectsOtherMappingSlot() public {
        L1RollupStateRoot.Profile memory p = _profile();
        p.stateRootsSlot += 1;
        L1RollupVerifierBase other = _deploy(p);
        vm.expectRevert(
            abi.encodeWithSelector(
                ClprEvmStateProof.SlotNotProven.selector, L1RollupStateRoot.stateRootSlot(p.stateRootsSlot, _key())
            )
        );
        other.verifyL2StateRoot(_bytes("l2StateRootProof"), anchor);
    }

    function test_rejectsKeyBelowMinimum() public {
        L1RollupStateRoot.Profile memory p = _profile();
        p.minKey = _key() + 1;
        L1RollupVerifierBase other = _deploy(p);
        vm.expectRevert(abi.encodeWithSelector(L1RollupStateRoot.KeyBelowMinimum.selector, _key(), p.minKey));
        other.verifyL2StateRoot(_bytes("l2StateRootProof"), anchor);
    }

    /// @notice A real sync-committee rotation from the capture: the L1 half returns the successor anchor,
    ///         and the original bundle no longer verifies under it (its header was signed by the old
    ///         committee), so a proof cannot be replayed against the rotated channel.
    function test_rotationAndStaleAnchor() public {
        bytes memory rot = _bytes("rotationLightClientProof");
        vm.skip(rot.length == 0);
        bytes memory plainProof = _bytes("lightClientProof");
        uint256 g = gasleft();
        l1.verifyL1State(plainProof, anchor);
        uint256 plain = g - gasleft();
        g = gasleft();
        (,, bytes memory na, bytes memory naId) = l1.verifyL1State(rot, anchor);
        uint256 rotation = g - gasleft();
        console.log("verifyL1State gas: plain", plain, "with rotation", rotation);
        assertEq(na.length, EthBeaconLightClient.TRUST_ANCHOR_LENGTH);
        assertEq(uint64(bytes8(naId)), vm.parseJsonUint(json, ".rotationNextPeriod"));
        bytes32 nextRoot;
        uint256 off = 0x20 + EthBeaconLightClient.ANCHOR_OFF_COMMITTEE_ROOT;
        assembly {
            nextRoot := mload(add(na, off))
        }
        assertEq(nextRoot, vm.parseJsonBytes32(json, ".rotationNextCommitteeRoot"));
        vm.expectRevert();
        verifier.verifyBundle(_bytes("bundle"), na, ctx);
    }
}

contract ScrollLiveTest is ZkRollupLiveTest {
    function _chain() internal pure override returns (string memory) {
        return "scroll";
    }

    function _profile() internal pure override returns (L1RollupStateRoot.Profile memory) {
        return ZkRollupProfiles.scroll();
    }

    function _deploy(L1RollupStateRoot.Profile memory p) internal override returns (L1RollupVerifierBase) {
        return new L1RollupMptVerifier(IEthL1StateVerifier(address(l1)), p);
    }

    function test_rejectsTamperedL2StorageProof() public {
        vm.expectRevert();
        verifier.verifyBundle(_bytes("tamperedStorageBundle"), anchor, ctx);
    }
}

contract MorphLiveTest is ZkRollupLiveTest {
    function _chain() internal pure override returns (string memory) {
        return "morph";
    }

    function _profile() internal pure override returns (L1RollupStateRoot.Profile memory) {
        return ZkRollupProfiles.morph();
    }

    function _deploy(L1RollupStateRoot.Profile memory p) internal override returns (L1RollupVerifierBase) {
        return new L1RollupMptVerifier(IEthL1StateVerifier(address(l1)), p);
    }

    function test_rejectsTamperedL2StorageProof() public {
        vm.expectRevert();
        verifier.verifyBundle(_bytes("tamperedStorageBundle"), anchor, ctx);
    }
}

contract LineaLiveTest is ZkRollupLiveTest {
    LineaStateTrieVerifier internal trie;
    address internal poseidon2;
    uint256 internal constant P = 2130706433;

    function _chain() internal pure override returns (string memory) {
        return "linea";
    }

    function _profile() internal pure override returns (L1RollupStateRoot.Profile memory) {
        return ZkRollupProfiles.linea();
    }

    function _deploy(L1RollupStateRoot.Profile memory p) internal override returns (L1RollupVerifierBase) {
        if (address(trie) == address(0)) {
            poseidon2 = _deployPoseidon2();
            trie = new LineaStateTrieVerifier(poseidon2);
        }
        return new LineaRollupVerifier(IEthL1StateVerifier(address(l1)), p, trie);
    }

    function _storageRoot() internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, ".lineaStorageRoot");
    }

    function _decodeStorage()
        internal
        view
        returns (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims)
    {
        (mp, claims) = abi.decode(
            _bytes("lineaStorageProof"), (ILineaStateTrieVerifier.MultiProof, ILineaStateTrieVerifier.SlotClaim[])
        );
    }

    function test_linea_storageMultiProof() public view {
        bytes memory proof = _bytes("lineaStorageProof");
        bytes32 root = _storageRoot();
        uint256 g = gasleft();
        (bytes32[] memory slots, bytes32[] memory values) = trie.verifyStorage(proof, root);
        console.log("verifyStorage gas (5 absent slots)", g - gasleft());
        console.log("  leaves", vm.parseJsonUint(json, ".lineaStorageLeaves"));
        console.log("  siblings", vm.parseJsonUint(json, ".lineaStorageSiblings"));
        assertEq(slots.length, 5);
        for (uint256 i = 0; i < values.length; ++i) {
            assertEq(values[i], bytes32(0));
        }
    }

    function test_linea_accountProof() public view {
        bytes memory proof = _bytes("lineaAccountProof");
        bytes32 root = vm.parseJsonBytes32(json, ".l2StateRoot");
        address account = vm.parseJsonAddress(json, ".l2Account");
        uint256 g = gasleft();
        (bytes32 storageRoot, bytes32 codeHash) = trie.verifyAccount(proof, root, account);
        console.log("verifyAccount gas", g - gasleft());
        assertEq(storageRoot, _storageRoot());
        assertEq(codeHash, vm.parseJsonBytes32(json, ".l2CodeHash"));
    }

    function test_linea_rejectsOtherAccount() public {
        vm.expectRevert(LineaStateTrieVerifier.AccountKeyMismatch.selector);
        trie.verifyAccount(_bytes("lineaAccountProof"), vm.parseJsonBytes32(json, ".l2StateRoot"), address(0xBEEF));
    }

    function test_linea_rejectsWrongSibling() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        mp.siblings[mp.siblings.length - 1] ^= 1;
        vm.expectRevert(); // RootMismatch(root, computed)
        trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
    }

    /// @notice An hKey with a limb shifted by p hashes like the stored one (the hash reduces limbs), but
    ///         compares differently. Such aliases must be rejected wherever hKeys are ordered.
    function test_linea_rejectsNonCanonicalKeyAlias() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        ILineaStateTrieVerifier.Leaf memory r = mp.leaves[claims[0].right];
        uint256 top = r.hKey >> 224;
        assertLt(top + P, 1 << 32);
        r.hKey += P << 224;
        vm.expectRevert(LineaStateTrieVerifier.NonCanonicalKey.selector);
        trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
    }

    function test_linea_rejectsNonAdjacentLeaves() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        // Find a claim whose bracket is not the widest possible and swap in another leaf above it.
        for (uint256 i = 0; i < mp.leaves.length; ++i) {
            ILineaStateTrieVerifier.Leaf memory cand = mp.leaves[i];
            ILineaStateTrieVerifier.Leaf memory right = mp.leaves[claims[0].right];
            if (i != claims[0].right && cand.hKey > right.hKey) {
                claims[0].right = i;
                vm.expectRevert(); // LeavesNotAdjacent
                trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
                return;
            }
        }
        vm.skip(true);
    }

    function test_linea_rejectsAbsentSlotClaimedPresent() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        claims[0].absent = false;
        vm.expectRevert(
            abi.encodeWithSelector(LineaStateTrieVerifier.SlotKeyMismatch.selector, bytes32(claims[0].slot))
        );
        trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
    }

    function test_linea_rejectsUnsortedLeaves() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        assertGt(mp.leaves.length, 1);
        (mp.leaves[0], mp.leaves[1]) = (mp.leaves[1], mp.leaves[0]);
        for (uint256 i = 0; i < claims.length; ++i) {
            claims[i].leaf = _swap01(claims[i].leaf);
            claims[i].right = _swap01(claims[i].right);
        }
        vm.expectRevert(LineaStateTrieVerifier.LeavesNotSorted.selector);
        trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
    }

    function test_linea_rejectsExtraSibling() public {
        (ILineaStateTrieVerifier.MultiProof memory mp, ILineaStateTrieVerifier.SlotClaim[] memory claims) =
            _decodeStorage();
        uint256[] memory s = new uint256[](mp.siblings.length + 1);
        for (uint256 i = 0; i < mp.siblings.length; ++i) {
            s[i] = mp.siblings[i];
        }
        mp.siblings = s;
        vm.expectRevert(LineaStateTrieVerifier.SiblingCountMismatch.selector);
        trie.verifyStorage(abi.encode(mp, claims), _storageRoot());
    }

    /// @notice LineaPoseidon2 against vectors from the TypeScript reference (test/e2e/relay/linea.ts),
    ///         which reproduces Linea mainnet state roots.
    function test_linea_poseidon2Vectors() public view {
        assertEq(
            _h(abi.encode(uint256(1), uint256(2))), 0x1ebf1f467e2a6251254aa79674484a9e5b58b56041d8d67e3656cd5325148d91
        );
        assertEq(_h(abi.encode(uint256(0))), 0x0656ab853b3f52840362a8177e217b630c3f876b11e848365145aa24220647fc);
        uint256[] memory w = new uint256[](100);
        for (uint256 i = 0; i < 100; ++i) {
            w[i] = i;
        }
        uint256 g = gasleft();
        bytes32 h100 = _h(abi.encodePacked(w));
        console.log("LineaPoseidon2: 100 blocks gas", g - gasleft());
        assertEq(h100, 0x751dc9d21881948158db19f6132b49854c2e199363e290a76202c86c35bc892c);
        // Non-canonical limbs (>= p) hash like their reductions.
        assertEq(
            _h(abi.encode(P - 1, type(uint256).max)), 0x33028ce103e679d42cc0c34015b9f6a21515bf5f1d9d3f0c7ca50c536ca113e6
        );
    }

    function test_linea_poseidon2RejectsBadLength() public {
        (bool ok,) = poseidon2.staticcall("");
        assertFalse(ok);
        (ok,) = poseidon2.staticcall(new bytes(33));
        assertFalse(ok);
    }

    function _swap01(uint256 i) internal pure returns (uint256) {
        return i == 0 ? 1 : i == 1 ? 0 : i;
    }

    function _h(bytes memory data) internal view returns (bytes32) {
        (bool ok, bytes memory r) = poseidon2.staticcall(data);
        require(ok && r.length == 32, "hash failed");
        return bytes32(r);
    }
}
