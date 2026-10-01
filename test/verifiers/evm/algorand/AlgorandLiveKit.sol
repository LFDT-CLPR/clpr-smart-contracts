// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    AlgorandStateProofAccumulator as Acc
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofAccumulator.sol";
import {ClprAlgorandStateProof as SP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprAlgorandStateProof.sol";
import {ClprFalconDet1024Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprFalconDet1024Engine.sol";
import {AlgorandEngines} from "@test/verifiers/evm/algorand/AlgorandEngines.sol";
import {
    AlgorandStateProofVerifier as V
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofVerifier.sol";

/// @notice Loads the REAL mainnet state proof in test/e2e/fixtures/algorand-live/vectors.json
///         (refresh: `npx tsx test/e2e/relay/buildAlgorandLiveProof.ts --refresh`).
abstract contract AlgorandLiveKit is Test {
    string internal json;
    address internal shake;
    address internal sumhash;
    ClprFalconDet1024Engine internal falcon;
    Acc internal acc;

    function _initLive() internal {
        json = vm.readFile("test/e2e/fixtures/algorand-live/vectors.json");
        (shake, sumhash) = AlgorandEngines.deploy();
        falcon = new ClprFalconDet1024Engine(shake);
        acc = new Acc(sumhash, shake, falcon);
    }

    function _u(string memory k) internal view returns (uint64) {
        return uint64(vm.parseJsonUint(json, k));
    }

    function _b(string memory k) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, k);
    }

    function _msg(string memory p) internal view returns (SP.Message memory m) {
        m.blockHeadersCommitment = vm.parseJsonBytes32(json, string.concat(p, ".blockHeadersCommitment"));
        m.votersCommitment = _b(string.concat(p, ".votersCommitment"));
        m.lnProvenWeight = _u(string.concat(p, ".lnProvenWeight"));
        m.firstAttestedRound = _u(string.concat(p, ".firstAttestedRound"));
        m.lastAttestedRound = _u(string.concat(p, ".lastAttestedRound"));
    }

    function _header(bytes32 root) internal view returns (Acc.SessionHeader memory h) {
        SP.Message memory prev = _msg(".prev");
        h.root = root;
        h.prevLastRound = prev.lastAttestedRound;
        h.message = _msg(".msg");
        h.sigCommit = _b(".sigCommit");
        h.signedWeight = _u(".signedWeight");
        h.saltVersion = uint8(vm.parseJsonUint(json, ".saltVersion"));
        h.treeDepth = uint8(vm.parseJsonUint(json, ".sigDepth"));
    }

    function _revealCount() internal view returns (uint256) {
        return _countArray(".reveals");
    }

    function _countArray(string memory k) internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, string.concat(k, "[", vm.toString(n), "]"))) {
            n++;
        }
    }

    function _reveal(uint256 i) internal view returns (Acc.Reveal memory r) {
        string memory p = string.concat(".reveals[", vm.toString(i), "].");
        r.pos = _u(string.concat(p, "pos"));
        r.l = _u(string.concat(p, "l"));
        r.weight = _u(string.concat(p, "weight"));
        r.keyLifetime = _u(string.concat(p, "keyLifetime"));
        r.commitment = _b(string.concat(p, "commitment"));
        r.sigCT = _b(string.concat(p, "sigCT"));
        r.vkey = _b(string.concat(p, "vkey"));
        r.vcIdx = _u(string.concat(p, "vcIdx"));
        r.keyPath = _b(string.concat(p, "keyPath"));
        r.sigPath = _b(string.concat(p, "sigPath"));
        r.partPath = _b(string.concat(p, "partPath"));
    }

    function _positions() internal view returns (uint64[] memory out) {
        uint256[] memory p = vm.parseJsonUintArray(json, ".positions");
        out = new uint64[](p.length);
        for (uint256 i = 0; i < p.length; i++) {
            out[i] = uint64(p[i]);
        }
    }

    /// @dev The live block's light-header and SHA-256 transaction proofs as a verifier TxProof.
    function _txProof() internal view returns (bytes memory) {
        return abi.encode(
            V.TxProof({
                intervalLastRound: _u(".msg.lastAttestedRound"),
                blockHash: vm.parseJsonBytes32(json, ".header.blockHash"),
                round: _u(".header.round"),
                txnCommitment: vm.parseJsonBytes32(json, ".header.txnCommitment"),
                headerPath: _b(".header.path"),
                txIndex: _u(".tx.index"),
                txPath: _b(".tx.path"),
                txid: vm.parseJsonBytes32(json, ".tx.txid"),
                stib: _b(".tx.stib")
            })
        );
    }

    function _liveAnchor(bytes32 r) internal view returns (bytes memory) {
        return abi.encodePacked(r, vm.parseJsonBytes32(json, ".header.genesisHash"));
    }

    function _one(Acc.Reveal memory r) internal pure returns (Acc.Reveal[] memory rs) {
        rs = new Acc.Reveal[](1);
        rs[0] = r;
    }
}
