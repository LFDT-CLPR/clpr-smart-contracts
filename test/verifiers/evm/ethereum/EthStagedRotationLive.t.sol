// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {HederaTraceEstimate} from "@test/verifiers/evm/ethereum/HederaTraceEstimate.sol";

/// @notice A real Sepolia sync-committee rotation (period 1377 -> 1378) through the full `verifyBundle`: the real
///         header, sync-committee BLS signature, execution branch, account and storage proofs of the CLPR Service,
///         with the next committee in staged form, as submitted to the Sepolia -> Hedera testnet Channel
///         (fixtures/sepolia-rotation-1377-1378.json). Checks the successor anchor, parity with the same bundle
///         carrying the full 512-key committee, and the Hedera trace size of both.
contract EthStagedRotationLiveTest is HederaTraceEstimate {
    string internal constant FIXTURE = "test/verifiers/evm/ethereum/fixtures/sepolia-rotation-1377-1378.json";
    uint256 internal constant IDX_NEXT_COMMITTEE = 4;

    EthMainnetVerifier internal verifier;
    bytes internal proof;
    bytes internal anchor;
    bytes internal ctx;
    bytes internal keys;
    bytes internal aggregate;
    bytes internal expectedAnchor;
    bytes internal expectedAnchorId;

    function setUp() public {
        string memory j = vm.readFile(FIXTURE);
        proof = vm.parseJsonBytes(j, ".proof");
        anchor = vm.parseJsonBytes(j, ".trustAnchor");
        ctx = vm.parseJsonBytes(j, ".channelContext");
        keys = vm.parseJsonBytes(j, ".nextCommitteeKeys");
        aggregate = vm.parseJsonBytes(j, ".nextCommitteeAggregate");
        expectedAnchor = vm.parseJsonBytes(j, ".expectedTrustAnchor");
        expectedAnchorId = vm.parseJsonBytes(j, ".expectedTrustAnchorId");
        verifier = new EthMainnetVerifier();
    }

    function test_liveStagedRotation_verifiesAndRotates() public {
        _stage();
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(proof, anchor, ctx);
        assertEq(newAnchor, expectedAnchor, "successor anchor");
        assertEq(newId, expectedAnchorId, "successor anchor id (period 1378)");
        assertEq(msgs.length, 0, "rotation-only bundle");
        assertEq(m.nextMessageId, 1, "no message sent on the Channel yet at that block");
    }

    function test_liveStagedRotation_revertsUnstaged() public {
        vm.expectPartialRevert(EthMainnetVerifier.CommitteeChunkNotStaged.selector);
        verifier.verifyBundle(proof, anchor, ctx);
    }

    /// The same real bundle with the full 512-key committee in item 4 yields the same successor anchor.
    function test_liveStagedRotation_parityWithFullCommittee() public {
        _stage();
        (,, bytes memory staged, bytes memory stagedId,) = verifier.verifyBundle(proof, anchor, ctx);
        (,, bytes memory full, bytes memory fullId,) = verifier.verifyBundle(_withFullCommittee(), anchor, ctx);
        assertEq(staged, full, "anchor parity");
        assertEq(stagedId, fullId, "anchor id parity");
    }

    /// submitBundle on Hedera with this bundle: the verifier frames plus the Service call and its logic
    /// delegatecall. The staged form stays at most half of the trace cap; the full form exceeds it.
    function test_liveStagedRotation_traceSize() public {
        _stage();
        (uint256 stagedEst, uint256 stagedGas) = _measure(
            address(verifier), abi.encodeCall(verifier.verifyBundle, (proof, anchor, ctx)), SERVICE_WRAPPER_FRAMES
        );
        console.log("verifyBundle, staged rotation: gas", stagedGas);
        console.log("submitBundle, staged rotation: trace estimate (B)", stagedEst);
        assertLt(stagedEst, HEDERA_TRACE_LIMIT / 2, "staged rotation bundle trace");

        (uint256 fullEst, uint256 fullGas) = _measure(
            address(verifier),
            abi.encodeCall(verifier.verifyBundle, (_withFullCommittee(), anchor, ctx)),
            SERVICE_WRAPPER_FRAMES
        );
        console.log("verifyBundle, full rotation: gas", fullGas);
        console.log("submitBundle, full rotation: trace estimate (B)", fullEst);
        assertGt(fullEst, HEDERA_TRACE_LIMIT, "full rotation bundle exceeds the cap");
    }

    function _stage() internal {
        bytes memory k = keys;
        for (uint256 c = 0; c < 16; c++) {
            bytes memory chunk = new bytes(32 * 128);
            assembly ("memory-safe") {
                mcopy(add(chunk, 32), add(add(k, 32), mul(c, 4096)), 4096)
            }
            verifier.stageCommitteeChunk(chunk);
        }
    }

    function _withFullCommittee() internal view returns (bytes memory) {
        bytes memory p = proof;
        Memory.Slice[] memory items = RLP.decodeList(p);
        bytes[] memory enc = new bytes[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            enc[i] = Memory.toBytes(items[i]);
        }
        bytes[] memory k = new bytes[](512);
        bytes memory all = keys;
        for (uint256 i = 0; i < 512; i++) {
            bytes memory key = new bytes(128);
            assembly ("memory-safe") {
                mcopy(add(key, 32), add(add(all, 32), mul(i, 128)), 128)
            }
            k[i] = RLP.encode(key);
        }
        bytes[] memory committee = new bytes[](2);
        committee[0] = RLP.encode(k);
        committee[1] = RLP.encode(aggregate);
        enc[IDX_NEXT_COMMITTEE] = RLP.encode(committee);
        return RLP.encode(enc);
    }
}
