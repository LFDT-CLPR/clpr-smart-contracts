// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ICometBftHeaderSource} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/ICometBftHeaderSource.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";

/// @title MockCometBftHeaderSource
/// @notice TEST ONLY. Stands in for the CometBFT family's `CometBftCommitAccumulator` (PR #6), which
///         this branch does not contain. It does NOT check commit signatures:
///         - `finalizedHeader` returns headers a test registered with {setFinalized};
///         - `checkHeader` parses a real signed header, recomputes the CometBFT header hash and checks
///           the set hash and height floor, but not the commit. The live fixture's commit signatures
///           are checked off-chain when it is built (test/e2e/relay/cometbft.ts encodeSignedHeader).
contract MockCometBftHeaderSource is ICometBftHeaderSource {
    mapping(bytes32 => Header) internal _headers;
    mapping(bytes32 => bool) internal _final;

    error NotFinalized();
    error ValidatorSetHashMismatch();
    error HeightTooOld();

    function setFinalized(bytes32 headerHash, Header calldata h) external {
        _headers[headerHash] = h;
        _final[headerHash] = true;
    }

    function finalizedHeader(bytes32 headerHash) external view returns (Header memory h) {
        if (!_final[headerHash]) revert NotFinalized();
        h = _headers[headerHash];
    }

    function checkHeader(bytes calldata, bytes calldata signedHeader, bytes32 setHash, uint64 minHeight)
        external
        pure
        returns (bytes32 headerHash, Header memory h)
    {
        (CometBftLib.SeiHeader memory header,) = Codec.parseSignedHeader(signedHeader);
        if (header.validatorsHash != setHash) revert ValidatorSetHashMismatch();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint64(header.height) < minHeight) revert HeightTooOld();
        headerHash = CometBftLib.headerHash(header);
        h = Header({
            validatorsHash: header.validatorsHash,
            nextValidatorsHash: header.nextValidatorsHash,
            appHash: header.appHash,
            // forge-lint: disable-next-line(unsafe-typecast)
            height: uint64(header.height)
        });
    }
}
