// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {RootstockVerifier} from "@hiero-ledger/clpr/verifiers/evm/rootstock/RootstockVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title RootstockComplianceTest
/// @dev IClprVerifier compliance for RootstockVerifier on a real RSKj 9.0.4 regtest chain
///      (test/e2e/fixtures/rootstock-live/compliance.json, re-captured by
///      `test/e2e/relay/rootstock/refresh-regtest.sh compliance`). One service contract holds a CLPR
///      Channel record whose sent running hash chains the two bundle payloads, and its manifest
///      commitment slot takes a new value in each of six blocks: one per manifest the suite asks for.
///      Every proof is a real merged-mined header chain and real Unitrie nodes from the node's store.
contract RootstockComplianceTest is ClprVerifierComplianceTest {
    string internal constant FIXTURE = "test/e2e/fixtures/rootstock-live/compliance.json";
    uint256 internal constant K = 3;

    string internal json;

    function _deployVerifier() internal override returns (IClprVerifier) {
        json = vm.readFile(FIXTURE);
        RootstockVerifier.Params memory p = RootstockVerifier.Params({
            chainId: "eip155:33",
            confirmations: uint64(K),
            minDifficulty: 1,
            difficultyDivisor: 2048,
            durationLimit: 10,
            forkDetectionFrom: 0,
            maxBtcTimestampDiff: 0
        });
        return IClprVerifier(address(new RootstockVerifier(p, _checkpoint())));
    }

    function _checkpoint() internal view returns (RootstockVerifier.Checkpoint memory c) {
        c.blockHash = vm.parseJsonBytes32(json, ".checkpoint.hash");
        c.number = vm.parseJsonUint(json, ".checkpoint.number");
        c.difficulty = vm.parseUint(vm.parseJsonString(json, ".checkpoint.difficulty"));
        c.timestamp = vm.parseJsonUint(json, ".checkpoint.timestamp");
    }

    function _service() internal view returns (address) {
        return vm.parseJsonAddress(json, ".service");
    }

    function _headers(string memory j, uint256 count)
        internal
        pure
        returns (RootstockVerifier.MinedHeader[] memory hs)
    {
        hs = new RootstockVerifier.MinedHeader[](count);
        for (uint256 i = 0; i < count; ++i) {
            string memory k = string.concat(".headers[", vm.toString(i), "]");
            hs[i].header = vm.parseJsonBytes(j, string.concat(k, ".header"));
            hs[i].coinbase = vm.parseJsonBytes(j, string.concat(k, ".coinbase"));
            hs[i].merkleProof = vm.parseJsonBytes(j, string.concat(k, ".merkleProof"));
        }
    }

    /// @dev Stage `s`'s state block index in `headers`, and the header count that makes it k-final.
    function _stateIndex(uint256 s) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(".stages[", vm.toString(s), "].block"))
            - vm.parseJsonUint(json, ".checkpoint.number") - 1;
    }

    function _stage(string memory field, uint256 s) internal pure returns (string memory) {
        return string.concat(".stages[", vm.toString(s), "].", field);
    }

    function _config(uint256 s) internal view returns (bytes memory) {
        uint256 si = _stateIndex(s);
        RootstockVerifier.ConfigProof memory c;
        c.headers = _headers(json, si + K);
        c.stateIndex = si;
        c.service = _service();
        c.codeProof = vm.parseJsonBytesArray(json, _stage("proofs.code", s));
        c.peerConfigNanos = 1;
        c.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        return abi.encode(c);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(0),
            channelId: vm.parseJsonBytes32(json, ".channelId"),
            expectedChainId: "eip155:33",
            expectedServiceAddress: abi.encodePacked(_service())
        });
    }

    /// Real Rootstock mainnet headers: valid merged mining, but they do not descend from this
    /// regtest verifier's deployment checkpoint.
    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        string memory mainnet = vm.readFile("test/e2e/fixtures/rootstock-live/mainnet.json");
        RootstockVerifier.ConfigProof memory c;
        c.headers = _headers(mainnet, 12);
        c.stateIndex = 0;
        c.service = _service();
        c.codeProof = vm.parseJsonBytesArray(json, _stage("proofs.code", 0));
        return (abi.encode(c), vm.parseJsonBytes32(json, ".channelId"));
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        for (uint256 s = 0; s < 6; ++s) {
            if (keccak256(vm.parseJsonBytes(json, _stage("manifestPreimage", s))) != keccak256(committedPreimage)) {
                continue;
            }
            configProof = _config(s);
            channelId = vm.parseJsonBytes32(json, ".channelId");
            manifestProof = abi.encode(
                RootstockVerifier.ConfigManifestProof({
                    manifestPreimage: carriedPreimage,
                    manifestProof: vm.parseJsonBytesArray(json, _stage("proofs.manifest", s))
                })
            );
            return (configProof, channelId, manifestProof);
        }
        revert("no recorded regtest state commits to this manifest; re-capture compliance.json");
    }

    function _anchor() internal view returns (bytes memory) {
        RootstockVerifier.Anchor memory a;
        a.checkpoint = _checkpoint();
        a.codeHash = keccak256(_runtime());
        return abi.encode(a);
    }

    /// @dev The setter runtime of the fixture (SSTORE each calldata pair), padded to 64 bytes.
    function _runtime() internal pure returns (bytes memory r) {
        r = new bytes(64);
        bytes memory code = hex"60005b3681101560185780602001358135556040016002565b00";
        for (uint256 i = 0; i < 64; ++i) {
            r[i] = i < code.length ? code[i] : bytes1(0xff);
        }
    }

    function _bundle() internal view returns (bytes memory) {
        uint256 si = _stateIndex(0);
        RootstockVerifier.BundleProof memory p;
        p.headers = _headers(json, si + K);
        p.stateIndex = si;
        p.codeProof = vm.parseJsonBytesArray(json, _stage("proofs.code", 0));
        p.slotProofs = new bytes[][](6);
        for (uint256 i = 0; i < 6; ++i) {
            p.slotProofs[i] =
                vm.parseJsonBytesArray(json, _stage(string.concat("proofs.slots[", vm.toString(i), "]"), 0));
        }
        p.bundleContent = vm.parseJsonBytes(json, ".bundleContent");
        return abi.encode(p);
    }

    function _context() internal view returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: vm.parseJsonBytes32(json, ".channelId"), remoteServiceAddress: abi.encodePacked(_service())
            })
        );
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(),
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        return RunningHashVector({
            proofBytes: _bundle(), trustAnchor: _anchor(), channelContext: _context(), previousRunningHash: bytes32(0)
        });
    }

    /// The checkpoint is the anchor and it advances with every bundle (to the k-final block), so a
    /// valid bundle always returns one. The pinned code hash does not change.
    function test_compliance_verifyBundle_noRotation_returnsEmptyNewAnchor() public override {
        BundleVector memory v = _validBundle();
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        RootstockVerifier.Anchor memory a = abi.decode(newAnchor, (RootstockVerifier.Anchor));
        assertEq(a.codeHash, keccak256(_runtime()), "code hash stays pinned");
        assertEq(a.checkpoint.number, vm.parseJsonUint(json, ".stages[0].block"), "anchor = k-final state block");
        assertEq(bytes32(newAnchorId), a.checkpoint.blockHash, "anchor id = checkpoint hash");
    }
}
