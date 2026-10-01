// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {StellarTestBuilder} from "@test/verifiers/evm/stellar/StellarTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {StellarScpVerifier} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarScpVerifier.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @title StellarComplianceTest
/// @dev IClprVerifier compliance for StellarScpVerifier over the synthetic Stellar chain (real Ed25519
///      SCP signatures and XDR; test/verifiers/evm/stellar/fixtures/synthetic.json). Signatures cannot
///      be made in-test, so every manifest the suite commits to is pre-published as a
///      `clpr_manifest` event in ledger 100, and the running-hash vector as a `clpr_queue` event in 103.
contract StellarComplianceTest is ClprVerifierComplianceTest, StellarTestBuilder {
    string internal constant CHAIN = "stellar:testnet";

    function _deployVerifier() internal override returns (IClprVerifier) {
        _loadFixture();
        return IClprVerifier(address(new StellarScpVerifier(new Ed25519Verifier(), NETWORK_ID, CHAIN)));
    }

    function _config(string memory chainId) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        bytes[] memory items = new bytes[](3);
        items[0] = _str(Q1);
        items[1] = _scpStd(101);
        items[2] = _str(ClprProtobuf.encodeControlMessage(lc));
        return _list(items);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(CHAIN),
            channelId: CHANNEL,
            expectedChainId: CHAIN,
            expectedServiceAddress: abi.encodePacked(SERVICE)
        });
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_config("stellar:pubnet"), CHANNEL);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        string[6] memory names = ["cm_3_2", "cm_1_1", "cm_foreign", "cm_0_1", "cm_1_0", "cm_7_0"];
        string memory name;
        for (uint256 i = 0; i < names.length; ++i) {
            bytes memory m = vm.parseJsonBytes(fx, string.concat(".complianceManifests.", names[i]));
            if (keccak256(m) == keccak256(committedPreimage)) name = names[i];
        }
        require(bytes(name).length != 0, "no pre-published clpr_manifest event for this preimage");
        bytes[] memory p = new bytes[](3);
        p[0] = _headers(100, 100);
        p[1] = _attItem(_att(name));
        p[2] = _str(carriedPreimage);
        return (_config(CHAIN), CHANNEL, _list(p));
    }

    /// The attestation re-proves the anchor's last metadata from its checkpoint, so nothing advances.
    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", "", ""),
            trustAnchor: _anchor(Q1_HASH, 105, 104, _headerHash(104), keccak256(abi.encode(_fixtureMeta()))),
            channelContext: _context(CHANNEL, SERVICE),
            expectedNextMessageId: 3,
            expectedPayloadCount: 0
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        ClprTypes.QueueMetadata memory meta;
        return RunningHashVector({
            proofBytes: _bundle(
                Q1,
                _scpStd(105),
                _headers(104, 103),
                _attItem(_att("queueRunningHash")),
                "",
                ClprProtobuf.encodeBundleContent(meta, payloads),
                ""
            ),
            trustAnchor: _anchor(Q1_HASH, 101, 100, _headerHash(100), bytes32(0)),
            channelContext: _context(CHANNEL, SERVICE),
            previousRunningHash: bytes32(0)
        });
    }
}
