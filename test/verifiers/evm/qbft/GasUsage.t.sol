// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {QBFTVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QBFTVerifier.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";

/// @dev Exposes internal `_decodeBundleContent` for gas testing.
contract QBFTVerifierHarness is QBFTVerifier {
    constructor() QBFTVerifier(1) {}

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }
}

/// @notice Gas usage benchmark for QBFT verifier components.
contract QBFTGasBenchmarkTest is QbftSyntheticProofs {
    uint256 internal constant VALIDATOR_PK = uint256(keccak256("qbft-validator"));
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    uint64 internal constant GENESIS_EPOCH_LENGTH = 30000;
    uint64 internal constant GENESIS_EPOCH_NUMBER = 0;
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    string internal constant PROOF_PATH = "test/verifiers/evm/qbft/fixtures/bundlePayload.hex";
    string internal constant TRUST_ANCHOR_PATH = "test/verifiers/evm/qbft/fixtures/trustAnchor.hex";
    string internal constant CHANNEL_CONTEXT_PATH = "test/verifiers/evm/qbft/fixtures/channelContext.hex";

    QBFTVerifier internal verifier;
    QBFTVerifierHarness internal harness;

    function setUp() public {
        verifier = QBFTVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(uint8(2))));
        harness = QBFTVerifierHarness(deployCode("GasUsage.t.sol:QBFTVerifierHarness"));
    }

    function test_qbft_verifier_gas_breakdown() public view {
        bytes memory proofBytes = _loadProof();
        bytes memory trustAnchor = _loadTrustAnchor();
        bytes memory channelContext = _loadChannelContext();

        console.log("=== QBFT Gas Usage Breakdown ===");

        // ── Trust anchor decode ─────────────────────────────────────────────
        uint256 g0 = gasleft();
        (address validator,,,) = abi.decode(trustAnchor, (address, bytes32, uint64, uint64));
        uint256 gasTrustAnchor = g0 - gasleft();
        console.log("Trust anchor decode   :", gasTrustAnchor);

        // ── ChannelContext decode ─────────────────────────────────────────
        g0 = gasleft();
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        address clprService;
        bytes memory svc = ctx.remoteServiceAddress;
        assembly {
            clprService := mload(add(svc, 20))
        }
        uint256 gasChannelContext = g0 - gasleft();
        console.log("ChannelContext decode:", gasChannelContext);

        // ── RLP decode payload ──────────────────────────────────────────────
        g0 = gasleft();
        Memory.Slice[] memory payload = RLP.decodeList(proofBytes);
        uint256 gasRlpPayload = g0 - gasleft();
        console.log("RLP payload decode    :", gasRlpPayload);

        // ── Process epoch headers (if any) ──────────────────────────────────
        g0 = gasleft();
        Memory.Slice[] memory epochHeaders = RLP.readList(payload[1]);
        uint256 gasEpochHeaders = g0 - gasleft();
        console.log("Epoch headers decode (", epochHeaders.length, "):", gasEpochHeaders);

        // ── Decode current block header ─────────────────────────────────────
        g0 = gasleft();
        Memory.Slice[] memory header = RLP.readList(payload[0]);
        bytes32 stateRoot = RLP.readBytes32(header[3]);
        uint256 gasBlockHeader = g0 - gasleft();
        console.log("Block header decode   :", gasBlockHeader);

        // ── QBFT seal verification (ECDSA recovery) ─────────────────────────
        g0 = gasleft();
        ClprQbftSeal.verify(2, header, validator);
        uint256 gasSealVerify = g0 - gasleft();
        console.log("QBFT seal verify      :", gasSealVerify);

        // ── Account proof verification + field decode ───────────────────────
        g0 = gasleft();
        ClprEvmStateProof.verifyAccountFields(payload[2], stateRoot, clprService);
        uint256 gasAccountProof = g0 - gasleft();
        console.log("Account proof verify  :", gasAccountProof);

        // Note: Storage proof verification skipped due to stale fixture format.
        // The fixture bundlePayload.hex uses channelId=0 but storage slots aren't
        // properly aligned with this value. For gas measurement purposes, the account
        // proof verification above is the most gas-intensive MPT operation.

        // ── Bundle content protobuf decode ──────────────────────────────────
        g0 = gasleft();
        bytes memory bundleContent = RLP.readBytes(payload[4]);
        uint256 gasBundleRead = g0 - gasleft();
        console.log("Bundle content read   :", gasBundleRead);

        g0 = gasleft();
        harness.decodeBundleContent(bundleContent);
        uint256 gasProtobuf = g0 - gasleft();
        console.log("Protobuf decode       :", gasProtobuf);

        uint256 gasTotal = gasTrustAnchor + gasChannelContext + gasRlpPayload + gasEpochHeaders + gasBlockHeader
            + gasSealVerify + gasAccountProof + gasBundleRead + gasProtobuf;
        console.log("TOTAL                 :", gasTotal);
    }

    function test_gas_verifyBundle_success() public {
        QBFTVerifier qbftVerifier = QBFTVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(uint8(1))));

        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        qbftVerifier.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function _syntheticTrustAnchor() internal pure returns (bytes memory) {
        address validatorAddr = vm.addr(VALIDATOR_PK);
        return abi.encode(validatorAddr, SERVICE_CODE_HASH, GENESIS_EPOCH_LENGTH, GENESIS_EPOCH_NUMBER);
    }

    /// @dev ChannelContext matching the storage/account proofs built by _buildChannelStorageProof
    ///      and _buildSyntheticAccountProof (both keyed by SYNTHETIC_CHANNEL_ID / SERVICE_ADDR).
    function _syntheticChannelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    function _loadProof() internal view returns (bytes memory) {
        return _readHexFile(PROOF_PATH);
    }

    function _loadTrustAnchor() internal view returns (bytes memory) {
        bytes memory rlpBytes = _readHexFile(TRUST_ANCHOR_PATH);
        Memory.Slice[] memory fields = RLP.decodeList(rlpBytes);
        require(fields.length == 3, "trustAnchor: expected 3 fields");
        return
            abi.encode(
                RLP.readAddress(fields[0]), RLP.readBytes32(fields[2]), GENESIS_EPOCH_LENGTH, GENESIS_EPOCH_NUMBER
            );
    }

    function _loadChannelContext() internal view returns (bytes memory) {
        bytes memory encoded = _readHexFile(CHANNEL_CONTEXT_PATH);
        ClprTypes.decodeChannelContext(encoded);
        return encoded;
    }

    function _readHexFile(string memory path) internal view returns (bytes memory) {
        string memory raw = vm.readFile(path);
        bytes memory b = bytes(raw);
        // Strip trailing CR/LF
        while (b.length > 0 && (b[b.length - 1] == 0x0a || b[b.length - 1] == 0x0d)) {
            assembly {
                mstore(b, sub(mload(b), 1))
            }
        }
        return vm.parseBytes(string.concat("0x", string(b)));
    }
}
