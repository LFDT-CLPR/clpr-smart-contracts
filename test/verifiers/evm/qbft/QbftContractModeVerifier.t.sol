// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QBFTVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QBFTVerifier.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {QbftContractValidatorSource} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftContractValidatorSource.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";
import {ContractSourceHarness} from "@test/helpers/QbftContractHarness.sol";

contract QbftContractModeVerifierTest is QbftContractProofs {
    QBFTVerifier internal verifier;

    uint256 internal constant VALIDATOR_PK = uint256(keccak256("qbft-validator"));
    address internal validatorAddr;
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    address internal constant VALIDATOR_CONTRACT = address(0xC04511AC);

    struct CurrentBlock {
        bytes32 arraySlot;
        bytes header;
        bytes svcAccountProof;
        bytes channelProofRlp;
        bytes currentVcProof;
    }

    function setUp() public {
        validatorAddr = vm.addr(VALIDATOR_PK);
        verifier = _qbftVerifier(2);
    }

    function _qbftVerifier(uint8 n) private returns (QBFTVerifier) {
        return QBFTVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(n)));
    }

    // ── Shared builders ──────────────────────────────────────────────────────

    /// @dev ChannelContext matching the storage/account proofs built by _buildChannelStorageProof
    ///      and _buildSyntheticAccountProof (both keyed by SYNTHETIC_CHANNEL_ID / SERVICE_ADDR).
    function _syntheticChannelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    /// @dev A Contract-mode trust anchor:
    ///      abi.encode(mode=1, setCommitment, codeHash, validatorContract, arraySlot, anchorBlockNumber).
    function _contractAnchor(address[] memory validators, address validatorContract, bytes32 arraySlot, uint64 blockNo)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(uint8(1), _commit(validators), SERVICE_CODE_HASH, validatorContract, arraySlot, blockNo);
    }

    /// @dev Build an 8-field Contract-mode config proof: descriptor [mode=1, service, codeHash,
    ///      validatorContract, arraySlot], the validator-contract proof at field 5, the header at field 6.
    function _buildContractConfigProof(
        address validatorContract,
        bytes32 arraySlot,
        bytes memory vcProof,
        bytes memory header
    ) internal pure returns (bytes memory) {
        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](5);
        taItems[0] = RLP.encode(uint256(1)); // mode = Contract
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        taItems[3] = RLP.encode(validatorContract);
        taItems[4] = RLP.encode(arraySlot);

        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        items[1] = RLP.encode(bytes("eip155:1"));
        items[2] = RLP.encode(uint256(0));
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = RLP.encode(vcProof);
        items[6] = header;
        items[7] = RLP.encode(uint256(30000));
        return RLP.encode(items);
    }

    /// @dev A 3-member set built from key seeds (each member is vm.addr(keccak256(seed))).
    function _set3(string memory s0, string memory s1, string memory s2) internal pure returns (address[] memory s) {
        s = new address[](3);
        s[0] = vm.addr(uint256(keccak256(bytes(s0))));
        s[1] = vm.addr(uint256(keccak256(bytes(s1))));
        s[2] = vm.addr(uint256(keccak256(bytes(s2))));
    }

    /// @dev The two sealer private keys for a 2-of-3 quorum, from the same seeds as _set3.
    function _pks2(string memory s0, string memory s1) internal pure returns (uint256[] memory p) {
        p = new uint256[](2);
        p[0] = uint256(keccak256(bytes(s0)));
        p[1] = uint256(keccak256(bytes(s1)));
    }

    function _buildHop(address validatorContract, address[] memory nextSet, uint256[] memory sealers, uint64 blockNo)
        internal
        pure
        returns (bytes memory)
    {
        (bytes32 hopStateRoot,, bytes memory hopVcProof) = _validatorContractProof(validatorContract, nextSet);
        return _hop(_buildListedSealedHeader(blockNo, hopStateRoot, new address[](0), sealers), hopVcProof);
    }

    /// @dev The current block at `blockNo`: header sealed by `sealers`, two-account state (service +
    ///      validator contract) whose validator array holds `currentSet`, plus the channel proof.
    function _buildCurrentBlock(
        address validatorContract,
        address[] memory currentSet,
        uint256[] memory sealers,
        uint64 blockNo
    ) internal pure returns (CurrentBlock memory cb) {
        bytes32 vcStorageRoot;
        (cb.arraySlot, vcStorageRoot,) = _validatorStorageProof(currentSet);
        bytes32 svcStorageRoot;
        (svcStorageRoot, cb.channelProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        bytes32 stateRoot;
        bytes memory vcAccountProof;
        (stateRoot, cb.svcAccountProof, vcAccountProof) =
            _buildTwoAccountState(SERVICE_ADDR, svcStorageRoot, SERVICE_CODE_HASH, validatorContract, vcStorageRoot);
        cb.currentVcProof = _wrapVcProof(validatorContract, vcAccountProof, cb.arraySlot, currentSet);
        cb.header = _buildListedSealedHeader(blockNo, stateRoot, new address[](0), sealers);
    }

    /// @dev Assemble the 5-field bundle proof from a current block, a trusted set, and the hops.
    function _topProof(CurrentBlock memory cb, address[] memory trustedSet, bytes[] memory hops)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](5);
        top[0] = cb.header;
        top[1] = _contractSourceField(trustedSet, hops, cb.currentVcProof);
        top[2] = cb.svcAccountProof;
        top[3] = cb.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    function test_revertWhen_SealSignatureIsZero() public {
        bytes memory code = abi.encodePacked(vm.getCode("QBFTVerifier.sol:QBFTVerifier"), abi.encode(uint8(0)));
        vm.expectRevert(QBFTVerifier.InvalidNumberOfSealSignatures.selector);
        assembly {
            let addr := create(0, add(code, 0x20), mload(code))
            if iszero(addr) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function test_revertWhen_TrustAnchorWrongLength() public {
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(hex"c0", hex"deadbeef", "");
    }

    /// @dev A 5-word mode-0 anchor is not forwarded. The legacy path rejects its length.
    function test_revertWhen_HeaderModeAnchor_staysOnLegacyPath() public {
        bytes memory anchor = abi.encode(uint8(0), bytes32(0), SERVICE_CODE_HASH, uint64(0), uint64(30000));
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    /// @dev A 6-word anchor whose mode word is not 1 is not forwarded. The legacy path rejects it.
    function test_revertWhen_UnknownModeAnchor_staysOnLegacyPath() public {
        bytes memory anchor = abi.encode(uint8(2), bytes32(0), SERVICE_CODE_HASH, address(0), bytes32(0), uint64(0));
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    function test_revertWhen_WrongSetCommitment() public {
        address[] memory anchored = new address[](1);
        anchored[0] = validatorAddr;
        address[] memory submitted = new address[](1);
        submitted[0] = address(0xBAD);

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = _contractSourceField(submitted, new bytes[](0), hex"");
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        bytes memory anchor = _contractAnchor(anchored, address(0x1234), bytes32(uint256(1)), 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                QbftContractModeVerifier.WrongSetCommitment.selector, _commit(submitted), _commit(anchored)
            )
        );
        verifier.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());
    }

    function test_revertWhen_ValidatorSetTooLarge() public {
        address[] memory bigSet = new address[](257);
        for (uint256 i = 0; i < 257; i++) {
            // casting to 'uint160' is safe because i + 1 is at most 257
            // forge-lint: disable-next-line(unsafe-typecast)
            bigSet[i] = address(uint160(i + 1));
        }

        bytes[] memory top = new bytes[](5);
        top[0] = _buildListedSealedHeader(1, bytes32(0), new address[](0), new uint256[](0));
        top[1] = _contractSourceField(bigSet, new bytes[](0), hex"");
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        bytes memory anchor = _contractAnchor(bigSet, address(0x1234), bytes32(uint256(1)), 0);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftQuorum.ValidatorSetTooLarge.selector, 257));
        verifier.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());
    }

    /// @dev The contract source proves the array and returns it sorted ascending and deduped, whatever
    ///      order the contract stores it in.
    function test_contractSource_resolvesSortedSet() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory vals = new address[](3);
        vals[0] = address(0xAAA1);
        vals[1] = address(0x0002);
        vals[2] = address(0xBBB3);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), vals);

        address[] memory got = cs.resolve(proof, stateRoot, address(0x1234), arraySlot);
        assertEq(got.length, 3);
        assertEq(got[0], address(0x0002));
        assertEq(got[1], address(0xAAA1));
        assertEq(got[2], address(0xBBB3));
    }

    function test_contractSource_emptyValidatorSet_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory none = new address[](0);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), none);
        vm.expectRevert(QbftContractValidatorSource.EmptyValidatorSet.selector);
        cs.resolve(proof, stateRoot, address(0x1234), arraySlot);
    }

    function test_contractSource_zeroValidator_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory vals = new address[](3);
        vals[0] = address(0xAAA1);
        vals[1] = address(0); // zeroed element
        vals[2] = address(0xBBB3);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), vals);
        vm.expectRevert(QbftContractValidatorSource.ZeroValidator.selector);
        cs.resolve(proof, stateRoot, address(0x1234), arraySlot);
    }

    function test_contractSource_duplicateValidator_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory vals = new address[](3);
        vals[0] = address(0xAAA1);
        vals[1] = address(0xAAA1); // duplicate: distinct size (2) != proven length (3)
        vals[2] = address(0xBBB3);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), vals);
        vm.expectRevert(abi.encodeWithSelector(QbftContractValidatorSource.DuplicateValidator.selector, 3, 2));
        cs.resolve(proof, stateRoot, address(0x1234), arraySlot);
    }

    function test_contractSource_wrongProofShape_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(address(0x1234));
        items[1] = hex"c0";
        items[2] = RLP.encode(bytes32(0));
        vm.expectRevert(QbftContractValidatorSource.InvalidProofShape.selector);
        cs.resolve(RLP.encode(items), bytes32(0), address(0x1234), bytes32(0));
    }

    function test_contractSource_wrongContract_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory vals = new address[](3);
        vals[0] = address(0xAAA1);
        vals[1] = address(0x0002);
        vals[2] = address(0xBBB3);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), vals);
        vm.expectRevert(
            abi.encodeWithSelector(
                QbftContractValidatorSource.WrongValidatorContract.selector, address(0x1234), address(0x5678)
            )
        );
        cs.resolve(proof, stateRoot, address(0x5678), arraySlot);
    }

    function test_contractSource_wrongSlot_reverts() public {
        ContractSourceHarness cs = new ContractSourceHarness();
        address[] memory vals = new address[](3);
        vals[0] = address(0xAAA1);
        vals[1] = address(0x0002);
        vals[2] = address(0xBBB3);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory proof) = _validatorContractProof(address(0x1234), vals);
        bytes32 otherSlot = bytes32(uint256(arraySlot) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(QbftContractValidatorSource.WrongArraySlot.selector, arraySlot, otherSlot)
        );
        cs.resolve(proof, stateRoot, address(0x1234), otherSlot);
    }

    /// @dev verifyConfig reads the set from the validator contract, checks the header seal against
    ///      a quorum of it, and returns a Contract-mode anchor keyed by block number.
    function test_verifyConfig_anchorsContractSet() public {
        _checkVerifyConfigAnchorsContractSet(IClprVerifier(address(_qbftVerifier(2)))); // quorum(3) = 2
    }

    function _checkVerifyConfigAnchorsContractSet(IClprVerifier v) private view {
        uint256 pk1 = uint256(keccak256("cm-1"));
        uint256 pk2 = uint256(keccak256("cm-2"));
        uint256 pk3 = uint256(keccak256("cm-3"));
        address[] memory vals = new address[](3);
        vals[0] = vm.addr(pk1);
        vals[1] = vm.addr(pk2);
        vals[2] = vm.addr(pk3);

        address validatorContract = address(0xC04511AC);
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof) = _validatorContractProof(validatorContract, vals);
        bytes memory header = _buildMultiSealedHeaderAtBlock(500, stateRoot, 0, pk1, pk2);

        bytes memory configProof = _buildContractConfigProof(validatorContract, arraySlot, vcProof, header);
        (,,,,, bytes memory initialTrustAnchor, bytes memory initialTrustAnchorId,) =
            v.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, "");

        (uint8 mode, bytes32 anchorCommitment,, address vc, bytes32 slot, uint64 anchorBlock) =
            abi.decode(initialTrustAnchor, (uint8, bytes32, bytes32, address, bytes32, uint64));
        assertEq(mode, 1, "contract mode");
        assertEq(anchorCommitment, _commit(vals), "commitment of the proven set");
        assertEq(vc, validatorContract);
        assertEq(slot, arraySlot);
        assertEq(anchorBlock, 500, "anchor pinned to the config block");
        assertEq(initialTrustAnchorId, abi.encodePacked(uint64(500)), "anchor id is the block number");
    }

    /// @dev A Header-mode (0) descriptor reverts: this verifier serves Contract mode only.
    function test_verifyConfig_headerModeDescriptor_reverts() public {
        bytes memory header = _buildMultiSealedHeaderAtBlock(500, bytes32(0), 0, VALIDATOR_PK, 0);

        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](5);
        taItems[0] = RLP.encode(uint256(0)); // mode = Header
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        taItems[3] = RLP.encode(address(0xC04511AC));
        taItems[4] = RLP.encode(bytes32(uint256(1)));

        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        items[1] = RLP.encode(bytes("eip155:1"));
        items[2] = RLP.encode(uint256(0));
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = RLP.encode(new bytes(0));
        items[6] = header;
        items[7] = RLP.encode(uint256(30000));

        vm.expectRevert(abi.encodeWithSelector(QbftContractModeVerifier.UnknownValidatorMode.selector, uint8(0)));
        verifier.verifyConfig(RLP.encode(items), SYNTHETIC_CHANNEL_ID, "");
    }

    /// @dev verifyBundle checks the current block against the trusted set, reads the set the
    ///      contract now holds, and rotates the anchor to it (keyed by block number).
    function test_verifyBundle_rotatesToContractSet() public {
        _checkVerifyBundleRotates(IClprVerifier(address(_qbftVerifier(2)))); // quorum(3) = 2
    }

    function _checkVerifyBundleRotates(IClprVerifier v) private view {
        uint256 a1 = uint256(keccak256("cm-a1"));
        uint256 a2 = uint256(keccak256("cm-a2"));
        address[] memory oldSet = new address[](3);
        oldSet[0] = vm.addr(a1);
        oldSet[1] = vm.addr(a2);
        oldSet[2] = vm.addr(uint256(keccak256("cm-a3")));
        address[] memory newSet = new address[](3);
        newSet[0] = vm.addr(uint256(keccak256("cm-b1")));
        newSet[1] = vm.addr(uint256(keccak256("cm-b2")));
        newSet[2] = vm.addr(uint256(keccak256("cm-b3")));

        address validatorContract = address(0xC04511AC);
        (bytes32 vcStorageRoot, bytes32 arraySlot, bytes memory vcProof) = _validatorStorageProofAndVcProof(newSet);
        (bytes32 svcStorageRoot, bytes memory channelProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory svcAccountProof, bytes memory vcAccountProof) =
            _buildTwoAccountState(SERVICE_ADDR, svcStorageRoot, SERVICE_CODE_HASH, validatorContract, vcStorageRoot);

        // The vcProof account proof must be against `stateRoot`. Rebuild it with the two-account state.
        vcProof = _wrapVcProof(validatorContract, vcAccountProof, arraySlot, newSet);

        // Current block sealed by 2 of the OLD (trusted) set.
        bytes memory header = _buildMultiSealedHeaderAtBlock(777, stateRoot, 0, a1, a2);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = _contractSourceField(oldSet, new bytes[](0), vcProof);
        top[2] = svcAccountProof;
        top[3] = channelProofRlp;
        top[4] = RLP.encode(new bytes(0));

        bytes memory anchor = _contractAnchor(oldSet, validatorContract, arraySlot, 0);
        (,, bytes memory newTrustAnchor, bytes memory newTrustAnchorId,) =
            v.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());

        (uint8 mode, bytes32 rotatedCommitment,,,, uint64 anchorBlock) =
            abi.decode(newTrustAnchor, (uint8, bytes32, bytes32, address, bytes32, uint64));
        assertEq(mode, 1, "contract mode");
        assertEq(rotatedCommitment, _commit(newSet), "commitment of the harvested set");
        assertEq(anchorBlock, 777, "anchor pinned to the proven block");
        assertEq(newTrustAnchorId, abi.encodePacked(uint64(777)), "rotation id is block number");
    }

    /// @dev A hop at a change block advances the walk as well. Old set A seals the hop at block 300
    ///      whose state holds mid set B; the current block 301 is sealed by B and its state holds B.
    function test_hopWalk_crossesRotation() public {
        QBFTVerifier v = _qbftVerifier(2); // quorum(3) = 2
        address[] memory oldSet = _set3("hop-o1", "hop-o2", "hop-o3");
        address[] memory midSet = _set3("hop-m1", "hop-m2", "hop-m3");

        bytes[] memory hops = new bytes[](1);
        hops[0] = _buildHop(VALIDATOR_CONTRACT, midSet, _pks2("hop-o1", "hop-o2"), 300);
        CurrentBlock memory cb = _buildCurrentBlock(VALIDATOR_CONTRACT, midSet, _pks2("hop-m1", "hop-m2"), 301);

        bytes memory anchor = _contractAnchor(oldSet, VALIDATOR_CONTRACT, cb.arraySlot, 0);
        (,, bytes memory newTrustAnchor, bytes memory newTrustAnchorId,) =
            v.verifyBundle(_topProof(cb, oldSet, hops), anchor, _syntheticChannelContext());

        (, bytes32 rotatedCommitment,,,, uint64 anchorBlock) =
            abi.decode(newTrustAnchor, (uint8, bytes32, bytes32, address, bytes32, uint64));
        assertEq(rotatedCommitment, _commit(midSet), "commitment of the harvested set");
        assertEq(anchorBlock, 301);
        assertEq(newTrustAnchorId, abi.encodePacked(uint64(301)));
    }

    /// @dev A round trip A -> B -> A crossed in one bundle nets to no set change, but the anchor
    ///      block-number floor MUST still advance to the current block; otherwise the retired set
    ///      B's change block stays replayable in a later bundle. Also asserts the replay is then
    ///      rejected against the advanced anchor.
    function test_verifyBundle_roundTripAdvancesFloorAndBlocksReplay() public {
        QBFTVerifier v = _qbftVerifier(2); // quorum(3) = 2
        address[] memory setA = _set3("rt-a1", "rt-a2", "rt-a3");
        address[] memory setB = _set3("rt-b1", "rt-b2", "rt-b3");

        bytes[] memory hops = new bytes[](2);
        hops[0] = _buildHop(VALIDATOR_CONTRACT, setB, _pks2("rt-a1", "rt-a2"), 200); // sealed by A, state -> B
        hops[1] = _buildHop(VALIDATOR_CONTRACT, setA, _pks2("rt-b1", "rt-b2"), 300); // sealed by B, state -> A
        CurrentBlock memory cb = _buildCurrentBlock(VALIDATOR_CONTRACT, setA, _pks2("rt-a1", "rt-a2"), 400);

        bytes memory proof = _topProof(cb, setA, hops);
        (,, bytes memory newTrustAnchor, bytes memory newTrustAnchorId,) = v.verifyBundle(
            proof, _contractAnchor(setA, VALIDATOR_CONTRACT, cb.arraySlot, 100), _syntheticChannelContext()
        );

        assertGt(newTrustAnchor.length, 0, "floor must advance even without a net rotation");
        (uint8 mode, bytes32 commitment,,,, uint64 anchorBlock) =
            abi.decode(newTrustAnchor, (uint8, bytes32, bytes32, address, bytes32, uint64));
        assertEq(mode, 1);
        assertEq(commitment, _commit(setA), "commitment stays the trusted set A");
        assertEq(anchorBlock, 400, "anchor floor advanced to the current block");
        assertEq(newTrustAnchorId, abi.encodePacked(uint64(400)));

        // The advanced anchor (floor 400) must now reject a replay of hop1 @200.
        vm.expectRevert(
            abi.encodeWithSelector(
                QbftContractModeVerifier.HandoffHeaderNotAscending.selector, uint64(200), uint64(400)
            )
        );
        v.verifyBundle(proof, _contractAnchor(setA, VALIDATOR_CONTRACT, cb.arraySlot, 400), _syntheticChannelContext());
    }

    function test_sourceNotThreeItems_reverts() public {
        address[] memory oldSet = new address[](1);
        oldSet[0] = validatorAddr;
        bytes memory anchor = _contractAnchor(oldSet, address(0x1234), bytes32(uint256(1)), 0);

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = hex"c0"; // 0 items, not 3
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QbftContractModeVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());
    }

    function test_hopNotTwoItems_reverts() public {
        address[] memory oldSet = new address[](1);
        oldSet[0] = validatorAddr;
        bytes memory anchor = _contractAnchor(oldSet, address(0x1234), bytes32(uint256(1)), 0);

        bytes[] memory badHop = new bytes[](1);
        badHop[0] = _emptyHeader(15);
        bytes[] memory hops = new bytes[](1);
        hops[0] = RLP.encode(badHop);

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = _contractSourceField(oldSet, hops, hex"");
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QbftContractModeVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());
    }

    function test_hopNotAscending_reverts() public {
        address[] memory oldSet = new address[](1);
        oldSet[0] = validatorAddr;
        bytes memory anchor = _contractAnchor(oldSet, address(0x1234), bytes32(uint256(1)), 0);

        bytes[] memory hops = new bytes[](1);
        hops[0] = _hop(_emptyHeader(15), hex""); // block number 0 <= anchor block 0

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = _contractSourceField(oldSet, hops, hex"");
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(
            abi.encodeWithSelector(QbftContractModeVerifier.HandoffHeaderNotAscending.selector, uint64(0), uint64(0))
        );
        verifier.verifyBundle(RLP.encode(top), anchor, _syntheticChannelContext());
    }
}
