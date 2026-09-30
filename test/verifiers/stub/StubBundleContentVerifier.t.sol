// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StubBundleContentVerifier} from "@test/verifiers/stub/StubBundleContentVerifier.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

contract StubBundleContentVerifierTest is Test {
    StubBundleContentVerifier internal verifier;

    function setUp() public {
        verifier = new StubBundleContentVerifier();
    }

    function test_verifyBundle_decodesProtobufBundleContent() public view {
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 11,
            sentRunningHash: bytes32(uint256(0xC0FFEE)),
            receivedMessageId: 4,
            receivedRunningHash: bytes32(uint256(0xBADF00D)),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 10,
            lastMessageRunningHash: bytes32(uint256(0xC0FFEE))
        });
        bytes[] memory msgs = new bytes[](2);
        msgs[0] = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        msgs[1] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"05");
        bytes memory proof = ClprProtobuf.encodeBundleContent(meta, msgs);

        (ClprTypes.QueueMetadata memory outMeta, bytes[] memory outMsgs, bytes memory anchor,,) =
            verifier.verifyBundle(proof, "", "");

        assertEq(outMeta.nextMessageId, meta.nextMessageId);
        assertEq(outMeta.sentRunningHash, meta.sentRunningHash);
        assertEq(outMeta.receivedMessageId, meta.receivedMessageId);
        assertEq(outMeta.receivedRunningHash, meta.receivedRunningHash);
        assertEq(uint8(outMeta.state), uint8(meta.state));
        assertEq(outMsgs.length, 2);
        assertEq(outMsgs[0], msgs[0]);
        assertEq(outMsgs[1], msgs[1]);
        assertEq(anchor.length, 0);
    }

    function test_verifyBundle_emptyProofYieldsDefaults() public view {
        (ClprTypes.QueueMetadata memory outMeta, bytes[] memory outMsgs, bytes memory anchor,,) =
            verifier.verifyBundle("", "", "");
        assertEq(outMeta.nextMessageId, 0);
        assertEq(uint8(outMeta.state), uint8(ClprTypes.ChannelStatus.PENDING));
        assertEq(outMsgs.length, 0);
        assertEq(anchor.length, 0);
    }

    function test_verifyConfig_returnsZeroValues() public view {
        (, string memory chainId, bytes memory svc, uint96 ts,,,,) = verifier.verifyConfig("", bytes32(0), "");
        assertEq(bytes(chainId).length, 0);
        assertEq(svc.length, 0);
        assertEq(ts, 0);
    }
}
