// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {QbftValidatorMode} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QBFTVerifier
/// @notice One deployable entry point for both Besu QBFT verifiers. It reads the mode byte — word 0
///         of the trust anchor, item 0 of the config descriptor — and forwards the call unchanged
///         to {QbftHeaderModeVerifier} (mode 0) or {QbftContractModeVerifier} (mode 1). All
///         verification, and every revert, comes from the mode verifier.
contract QBFTVerifier is IClprVerifier {
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidProofPayloadShape();
    error InvalidTrustAnchorFields();
    error UnknownValidatorMode(uint8 mode);

    IClprVerifier public immutable HEADER_MODE;
    IClprVerifier public immutable CONTRACT_MODE;

    constructor() {
        HEADER_MODE = new QbftHeaderModeVerifier();
        CONTRACT_MODE = new QbftContractModeVerifier();
    }

    /// @inheritdoc IClprVerifier
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory,
            bytes[] memory,
            bytes memory,
            bytes memory,
            ClprTypes.ClprEndpointManifest memory
        )
    {
        if (trustAnchor.length < 32) revert InvalidTrustAnchor();
        return _byMode(uint256(bytes32(trustAnchor[:32]))).verifyBundle(proofBytes, trustAnchor, channelContext);
    }

    /// @inheritdoc IClprVerifier
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory,
            string memory,
            bytes memory,
            uint96,
            ClprTypes.Throttles memory,
            bytes memory,
            bytes memory,
            ClprTypes.ClprEndpointManifest memory
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        Memory.Slice[] memory proof = RLP.decodeList(configProofBytes);
        // Both modes carry the descriptor at index 4; the mode verifier checks the full field count.
        if (proof.length <= 4) revert InvalidProofPayloadShape();
        Memory.Slice[] memory descriptor = RLP.decodeList(RLP.readBytes(proof[4]));
        if (descriptor.length == 0) revert InvalidTrustAnchorFields();
        return
            _byMode(RLP.readUint256(descriptor[0]))
                .verifyConfig(configProofBytes, channelId, endpointManifestProofBytes);
    }

    function _byMode(uint256 mode) private view returns (IClprVerifier) {
        if (mode == uint256(uint8(QbftValidatorMode.Header))) return HEADER_MODE;
        if (mode == uint256(uint8(QbftValidatorMode.Contract))) return CONTRACT_MODE;
        // The truncation only shapes the error argument; the comparison above used the full word.
        // forge-lint: disable-next-line(unsafe-typecast)
        revert UnknownValidatorMode(uint8(mode));
    }
}
