// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console2} from "forge-std/console2.sol";
import {QBFTVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QBFTVerifier.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {QbftContractValidatorSource} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftContractValidatorSource.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftContractModeProofBuilders} from "@test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol";
import {CalldataGas} from "@test/helpers/CalldataGas.sol";

contract QbftGasReportTest is QbftContractModeProofBuilders {
    using Memory for bytes;

    uint256 internal constant HEADER_MODE_PK = uint256(keccak256("gas-report-hm"));

    QBFTVerifier internal headerMode;
    QbftContractModeVerifier internal contractMode;

    function setUp() public {
        headerMode = QBFTVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(uint8(1))));
        contractMode = new QbftContractModeVerifier();
    }

    function test_report_headerMode_steadyState() public view {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, HEADER_MODE_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0"; // no epoch headers
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        bytes memory anchor = abi.encode(vm.addr(HEADER_MODE_PK), SERVICE_CODE_HASH, uint64(30000), uint64(0));
        _measureBundle("header mode, steady state (1 validator, 1 seal)", address(headerMode), RLP.encode(top), anchor);
    }

    // ── Contract mode: steady state by validator-set size ────────────────────

    function test_report_contractMode_steadyStateBySetSize() public view {
        _steady(3);
        _steady(10);
        _steady(25);
        _steady(52);
    }

    function _steady(uint256 n) private view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("gas-s", n);
        console2.log("contract mode, steady state, validators:", n);
        _measureBundle("", address(contractMode), proof, anchor);
    }

    // ── Contract mode: rotation (one hop) ────────────────────────────────────

    function test_report_contractMode_rotations() public view {
        _rotation(10);
        _rotation(51);
    }

    function _rotation(uint256 n) private view {
        (bytes memory proof, bytes memory anchor) = _rotationScenario("gas-rot", n);
        console2.log("contract mode, rotation, validators (n -> n+1), n:", n);
        _measureBundle("", address(contractMode), proof, anchor);
    }

    // ── Contract mode: verifyConfig ──────────────────────────────────────────

    function test_report_contractMode_verifyConfig() public view {
        bytes memory configProof = _configScenario("gas-c");

        contractMode.verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, "");
        uint256 used = vm.lastCallGas().gasTotalUsed;
        console2.log("contract mode, verifyConfig (3 validators)");
        console2.log("  execution   :", used);
        console2.log("  proof bytes :", configProof.length);
        console2.log("  calldata gas:", _calldataGas(configProof));
    }

    // ── Contract mode: rotation 51 -> 52 step breakdown ──────────────────────

    /// @dev Re-runs the verification steps over the same inputs the full call consumes
    ///      ({_buildHopParts} is {_rotationScenario}'s own construction, same seed), each as its own
    ///      call frame through {BreakdownHarness}. The submitted trusted set is the UNSORTED
    ///      `_setN` order, exactly as {_rotationScenario} submits it: `_contractAnchor` sorts its
    ///      argument in place, so it gets a copy. The remainder row holds what is not replayed:
    ///      payload decode, the trusted-set list parse, the service-account and channel proofs.
    function test_report_contractMode_rotation51Breakdown() public {
        uint256 n = 51;
        address[] memory oldSet = _setN("gas-rot", n);
        address[] memory newSet = _setN("gas-rot", n + 1);

        (bytes memory hopHeader, bytes32 hopStateRoot, bytes32 arraySlot, bytes memory hopVcProof) =
            _buildHopParts(newSet, _pksN("gas-rot", QbftValidators.quorum(n)), 300);
        CurrentBlock memory cb = _buildCurrentBlock(newSet, _pksN("gas-rot", QbftValidators.quorum(n + 1)), 301);

        // The full call, for the total — assembled from the parts above (the same construction
        // _rotationScenario performs; building it twice would inflate the replay figures below
        // through memory-expansion costs).
        uint256 total;
        {
            bytes[] memory hops = new bytes[](1);
            hops[0] = _hop(hopHeader, hopVcProof);
            bytes memory proof = _topProof(cb, oldSet, hops);
            bytes memory anchor = _contractAnchor(_copy(oldSet), VALIDATOR_CONTRACT, cb.arraySlot, 0);
            contractMode.verifyBundle(proof, anchor, _syntheticChannelContext());
            total = vm.lastCallGas().gasTotalUsed;
        }

        // Component replays, each its own call frame.
        BreakdownHarness bh = new BreakdownHarness();

        bh.openCommitment(_copy(oldSet));
        uint256 gasOpenCommitment = vm.lastCallGas().gasTotalUsed;
        address[] memory trusted = _copy(oldSet);
        QbftValidators.sortInPlace(trusted);

        bh.quorum(trusted, hopHeader);
        uint256 gasHopQuorum = vm.lastCallGas().gasTotalUsed;

        bh.resolveSet(hopVcProof, hopStateRoot, VALIDATOR_CONTRACT, arraySlot);
        uint256 gasHopResolve = vm.lastCallGas().gasTotalUsed;

        address[] memory hopSet = _copy(newSet);
        QbftValidators.sortInPlace(hopSet);
        bh.quorum(hopSet, cb.header);
        uint256 gasCurQuorum = vm.lastCallGas().gasTotalUsed;

        bytes32 curStateRoot = RLP.readBytes32(RLP.decodeList(cb.header)[3]);
        bh.resolveSet(cb.currentVcProof, curStateRoot, VALIDATOR_CONTRACT, cb.arraySlot);
        uint256 gasCurResolve = vm.lastCallGas().gasTotalUsed;

        uint256 sum = gasOpenCommitment + gasHopQuorum + gasHopResolve + gasCurQuorum + gasCurResolve;
        console2.log("contract mode, rotation 51 -> 52 breakdown");
        console2.log("  full verifyBundle          :", total);
        console2.log("  open set commitment        :", gasOpenCommitment);
        console2.log("  hop quorum (34 seals)      :", gasHopQuorum);
        console2.log("  hop resolveSet (52 slots)  :", gasHopResolve);
        console2.log("  current quorum (35 seals)  :", gasCurQuorum);
        console2.log("  final resolveSet (52 slots):", gasCurResolve);
        console2.log("  measured steps sum         :", sum);
        console2.log("  remainder (decode + set parse + svc acct + channel slots):", total - sum);
    }

    function _copy(address[] memory a) private pure returns (address[] memory b) {
        b = new address[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
    }

    // ── plumbing ─────────────────────────────────────────────────────────────

    function _measureBundle(string memory label, address verifier, bytes memory proof, bytes memory anchor)
        private
        view
    {
        bytes memory ctx = _syntheticChannelContext();
        IClprVerifier(verifier).verifyBundle(proof, anchor, ctx);
        uint256 used = vm.lastCallGas().gasTotalUsed;
        if (bytes(label).length > 0) console2.log(label);
        console2.log("  execution   :", used);
        console2.log("  proof bytes :", proof.length + anchor.length + ctx.length);
        console2.log("  calldata gas:", _calldataGas(proof) + _calldataGas(anchor) + _calldataGas(ctx));
    }

    function _calldataGas(bytes memory b) private pure returns (uint256) {
        return CalldataGas.eip2028(b);
    }
}

/// @dev The rotation-breakdown steps as external functions, so each replay is measured as its own
///      call frame (`vm.lastCallGas()`) exactly like the full `verifyBundle` call — not as a
///      `gasleft()` delta inside the test contract, whose codegen and memory state inflate the
///      figures. The `bytes memory` arguments are copied from calldata on entry (a few k gas each).
contract BreakdownHarness {
    using Memory for bytes;

    /// @dev Mirrors `_openCommitment` minus the list parse: sort in place, then commit.
    function openCommitment(address[] memory members) external pure returns (bytes32) {
        QbftValidators.sortInPlace(members);
        return QbftValidators.commit(ValidatorSet({members: members}));
    }

    /// @dev Header decode + quorum check, as the verifier does per header.
    function quorum(address[] memory members, bytes memory header) external pure {
        ClprQbftQuorum.verifyQuorum(ValidatorSet({members: members}), RLP.decodeList(header));
    }

    function resolveSet(bytes memory vcProof, bytes32 stateRoot, address validatorContract, bytes32 arraySlot)
        external
        pure
        returns (uint256)
    {
        return QbftContractValidatorSource.resolveSet(vcProof.asSlice(), stateRoot, validatorContract, arraySlot)
            .members.length;
    }
}
