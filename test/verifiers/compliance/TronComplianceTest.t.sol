// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {TronTestBuilder} from "@test/verifiers/evm/tron/TronTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {TronVerifier} from "@hiero-ledger/clpr/verifiers/evm/tron/TronVerifier.sol";
import {IClprTronAttestor} from "@hiero-ledger/clpr/verifiers/evm/tron/ClprTronAttestor.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title TronComplianceTest
/// @dev IClprVerifier compliance for TronVerifier over synthetic SR-signed TRON chains (the same
///      encodings as the live Nile/mainnet fixtures; see test/verifiers/evm/tron).
contract TronComplianceTest is ClprVerifierComplianceTest, TronTestBuilder {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    address internal constant ATTESTOR = address(0xA77E5700);
    bytes32 internal constant CHANNEL = bytes32(uint256(0xC0FFEE));
    uint64 internal constant PERIOD = 994_901;
    uint64 internal constant T0 = OFFSET + PERIOD * INTERVAL + 60_000;
    uint64 internal constant N0 = 71_431_000;

    function _deployVerifier() internal override returns (IClprVerifier) {
        _initSrs();
        return IClprVerifier(address(new TronVerifier(N, T, INTERVAL, OFFSET, NILE)));
    }

    function _config(string memory chainId) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE_ADDR);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        Hdr memory first =
            Hdr({number: N0, timestamp: T0, parentHash: keccak256("g"), txTrieRoot: 0, witness: address(0)});
        (bytes memory headers,) = _chain(first, _firstN(T), _noModes());
        bytes[] memory items = new bytes[](4);
        items[0] = _setRlp(_set());
        items[1] = RLP.encode(abi.encodePacked(ATTESTOR));
        items[2] = headers;
        items[3] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        return _rlpList(items);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(NILE),
            channelId: CHANNEL,
            expectedChainId: NILE,
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_config("tron:0x2b6653dc"), CHANNEL); // a mainnet config for a Nile verifier
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        bytes memory data =
            abi.encodeCall(IClprTronAttestor.attestManifest, (SERVICE_ADDR, keccak256(committedPreimage)));
        bytes[] memory p = new bytes[](2);
        p[0] = _txProof(_triggerTx(address(7), ATTESTOR, data, 1), N0 + 40, T0 + 120_000, _firstN(T), _noModes());
        p[1] = RLP.encode(carriedPreimage);
        return (_config(NILE), CHANNEL, _rlpList(p));
    }

    function _bundleProof(bytes[] memory payloads, uint64 nextMessageId, bytes32 sentRunningHash)
        internal
        view
        returns (bytes memory)
    {
        bytes memory data = abi.encodeCall(
            IClprTronAttestor.attestQueue,
            (SERVICE_ADDR, CHANNEL, 1, nextMessageId, sentRunningHash, 0, bytes32(0), 0, bytes32(0))
        );
        ClprTypes.QueueMetadata memory meta;
        bytes[] memory items = new bytes[](6);
        items[0] = _setRlp(_set());
        items[1] = _rlpEmptyList();
        items[2] = _rlpEmptyList();
        items[3] = _txProof(_triggerTx(address(7), ATTESTOR, data, 1), N0 + 100, T0 + 300_000, _firstN(T), _noModes());
        items[4] = RLP.encode(ClprProtobuf.encodeBundleContent(meta, payloads));
        items[5] = RLP.encode(bytes(""));
        return _rlpList(items);
    }

    function _anchor() internal view returns (bytes memory) {
        return abi.encode(PERIOD, _setHash(_set()), ATTESTOR, N0);
    }

    function _context() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundleProof(new bytes[](0), 1, bytes32(0)),
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 1,
            expectedPayloadCount: 0
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(payloads[0])));
        return RunningHashVector({
            proofBytes: _bundleProof(payloads, 2, h),
            trustAnchor: _anchor(),
            channelContext: _context(),
            previousRunningHash: bytes32(0)
        });
    }
}
