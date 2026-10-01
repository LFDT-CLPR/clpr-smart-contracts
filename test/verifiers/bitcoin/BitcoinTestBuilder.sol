// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";
import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";

/// @notice External wrappers so tests can call (and gas-measure) BitcoinLib directly.
contract BitcoinLibHarness {
    function hash256(bytes memory d) external pure returns (bytes32) {
        return BitcoinLib.hash256(d);
    }

    function bitsToTarget(uint32 bits) external pure returns (uint256) {
        return BitcoinLib.bitsToTarget(bits);
    }

    function targetToBits(uint256 t) external pure returns (uint32) {
        return BitcoinLib.targetToBits(t);
    }

    function retarget(uint32 lastBits, uint32 start, uint32 last, uint256 powLimit) external pure returns (uint32) {
        return BitcoinLib.retarget(lastBits, start, last, powLimit);
    }

    function work(uint256 target) external pure returns (uint256) {
        return BitcoinLib.work(target);
    }

    function parseTx(bytes memory raw) external pure returns (BitcoinLib.Tx memory) {
        return BitcoinLib.parseTx(raw);
    }

    function computeMerkleRoot(bytes32 leaf, uint256 index, bytes32[] memory branch) external pure returns (bytes32) {
        return BitcoinLib.computeMerkleRoot(leaf, index, branch);
    }

    function reverse256(uint256 v) external pure returns (uint256) {
        return BitcoinLib.reverse256(v);
    }
}

/// @notice Deterministic regtest-style chain builder: real 80-byte headers with real (regtest)
///         proof-of-work, real transaction serializations, real Bitcoin Merkle trees.
abstract contract BitcoinTestBuilder is Test {
    uint256 internal constant REGTEST_POW_LIMIT = uint256(0x7fffff) << 232;
    uint32 internal constant REGTEST_BITS = 0x207fffff;
    string internal constant REGTEST_CHAIN_ID = "bip122:0f9188f13cb7b2c71f2a335e3a4fc328";

    // Chain state (a single linear chain above the deployment checkpoint).
    bytes32 internal cpHash = keccak256("regtest checkpoint");
    uint32 internal cpHeight = 100;
    uint32 internal cpTime = 1_700_000_000;

    bytes[] internal chainHeaders; // headers at heights cpHeight+1, cpHeight+2, ...
    bytes32 internal tipHash;
    uint32 internal tipTime;
    // txids per block (index = height - cpHeight - 1), for Merkle branches
    bytes32[][] internal blockTxids;

    uint256 private fillerNonce;

    function _initChain() internal {
        tipHash = cpHash;
        tipTime = cpTime;
        delete chainHeaders;
        delete blockTxids;
    }

    function _deployRegtestVerifier(uint8 k) internal returns (BitcoinVerifier) {
        return new BitcoinVerifier(REGTEST_POW_LIMIT, true, true, k, 4096, REGTEST_CHAIN_ID, _deploymentCheckpoint());
    }

    function _deploymentCheckpoint() internal view returns (BitcoinVerifier.Checkpoint memory) {
        return BitcoinVerifier.Checkpoint({
            blockHash: cpHash, height: cpHeight, chainWork: 0, bits: REGTEST_BITS, time: cpTime, periodStartTime: cpTime
        });
    }

    function _tipHeight() internal view returns (uint32) {
        return cpHeight + uint32(blockTxids.length);
    }

    // ── Blocks ───────────────────────────────────────────────────────────────

    /// @dev Mine a block containing a coinbase placeholder plus `txs` (raw serializations).
    function _mine(bytes[] memory txs) internal returns (uint32 height) {
        bytes32[] memory ids = new bytes32[](txs.length + 1);
        ids[0] = keccak256(abi.encode("coinbase", fillerNonce++)); // stands in for the coinbase txid
        for (uint256 i = 0; i < txs.length; ++i) {
            ids[i + 1] = _txid(txs[i]);
        }
        return _mineTxids(ids);
    }

    function _mineEmpty(uint256 count) internal {
        for (uint256 i = 0; i < count; ++i) {
            _mine(new bytes[](0));
        }
    }

    function _mineTxids(bytes32[] memory ids) internal returns (uint32 height) {
        blockTxids.push(ids);
        tipTime += 600;
        bytes memory header = _grind(tipHash, _merkleRoot(ids), tipTime, REGTEST_BITS);
        chainHeaders.push(header);
        tipHash = BitcoinLib.hash256(header);
        return _tipHeight();
    }

    /// @dev Find a nonce such that hash256(header) ≤ target(bits).
    function _grind(bytes32 prev, bytes32 root, uint32 time, uint32 bits) internal pure returns (bytes memory h) {
        uint256 target = BitcoinLib.bitsToTarget(bits);
        for (uint32 nonce = 0;; ++nonce) {
            h = abi.encodePacked(_le32(0x20000000), prev, root, _le32(time), _le32(bits), _le32(nonce));
            if (BitcoinLib.reverse256(uint256(BitcoinLib.hash256(h))) <= target) return h;
        }
    }

    /// @dev Headers at heights [from, to] of the built chain.
    function _headers(uint32 from, uint32 to) internal view returns (bytes memory out) {
        out = new bytes(uint256(to - from + 1) * 80);
        for (uint32 h = from; h <= to; ++h) {
            bytes memory hdr = chainHeaders[h - cpHeight - 1];
            uint256 off = uint256(h - from) * 80;
            assembly ("memory-safe") {
                mcopy(add(add(out, 0x20), off), add(hdr, 0x20), 80)
            }
        }
    }

    function _headerAt(uint32 height) internal view returns (bytes memory) {
        return chainHeaders[height - cpHeight - 1];
    }

    // ── Transactions ─────────────────────────────────────────────────────────

    function _txid(bytes memory raw) internal pure returns (bytes32) {
        return BitcoinLib.parseTx(raw).txid;
    }

    /// @dev A CLPR tx: input 0 spends (prevTxid, prevVout); vout 0 = OP_RETURN commitment;
    ///      vout 1 = cursor to `cursorScript`; optional extra change output.
    function _clprTx(
        bytes32 prevTxid,
        uint32 prevVout,
        bytes memory opReturnData,
        bytes memory cursorScript,
        bool segwit
    ) internal pure returns (bytes memory) {
        bytes memory opReturn = abi.encodePacked(bytes1(0x6a), uint8(opReturnData.length), opReturnData);
        bytes memory inputs = abi.encodePacked(
            uint8(1),
            prevTxid,
            _le32(prevVout),
            uint8(0),
            _le32(0xfffffffd) // empty scriptSig (segwit spend)
        );
        bytes memory outputs = abi.encodePacked(
            uint8(3),
            _le64(0),
            uint8(opReturn.length),
            opReturn,
            _le64(546),
            uint8(cursorScript.length),
            cursorScript,
            _le64(99_000),
            uint8(22),
            hex"0014",
            bytes20(keccak256("change"))
        );
        if (segwit) {
            // One witness stack for the single input: [72-byte sig, 33-byte pubkey] (dummy bytes).
            bytes memory witness = abi.encodePacked(uint8(2), uint8(72), new bytes(72), uint8(33), new bytes(33));
            return abi.encodePacked(_le32(2), hex"0001", inputs, outputs, witness, _le32(0));
        }
        return abi.encodePacked(_le32(2), inputs, outputs, _le32(0));
    }

    function _commitment(bytes8 tag, bytes32 payloadHash, uint64 id) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes4("CLPR"), uint8(1), tag, payloadHash, id);
    }

    // ── Merkle ───────────────────────────────────────────────────────────────

    function _merkleRoot(bytes32[] memory ids) internal pure returns (bytes32) {
        bytes32[] memory level = ids;
        while (level.length > 1) {
            level = _nextLevel(level);
        }
        return level[0];
    }

    function _nextLevel(bytes32[] memory level) private pure returns (bytes32[] memory next) {
        next = new bytes32[]((level.length + 1) / 2);
        for (uint256 i = 0; i < next.length; ++i) {
            bytes32 l = level[2 * i];
            bytes32 r = 2 * i + 1 < level.length ? level[2 * i + 1] : l; // duplicate last if odd
            next[i] = BitcoinLib.hash256Pair(l, r);
        }
    }

    function _branch(bytes32[] memory ids, uint256 index) internal pure returns (bytes32[] memory branch) {
        uint256 depth = 0;
        for (uint256 n = ids.length; n > 1; n = (n + 1) / 2) {
            ++depth;
        }
        branch = new bytes32[](depth);
        bytes32[] memory level = ids;
        for (uint256 d = 0; d < depth; ++d) {
            uint256 sib = index ^ 1;
            branch[d] = sib < level.length ? level[sib] : level[index];
            level = _nextLevel(level);
            index >>= 1;
        }
    }

    /// @dev A TxProof for tx `txPos` (1-based within the block; 0 is the coinbase) at `height`,
    ///      with `startHeight` the height of the first header in the proof.
    function _txProof(uint32 height, uint32 startHeight, uint256 txPos, bytes memory raw, bytes memory payload)
        internal
        view
        returns (BitcoinVerifier.TxProof memory p)
    {
        bytes32[] memory ids = blockTxids[height - cpHeight - 1];
        p.headerIndex = height - startHeight;
        // casting to 'uint32' is safe: test blocks hold a handful of txs.
        // forge-lint: disable-next-line(unsafe-typecast)
        p.txIndex = uint32(txPos);
        p.merkleBranch = _branch(ids, txPos);
        p.rawTx = raw;
        p.payload = payload;
    }

    // ── Little-endian encoders ───────────────────────────────────────────────

    function _le32(uint32 v) internal pure returns (bytes4) {
        return bytes4(
            (uint32(uint8(v)) << 24) | (uint32(uint8(v >> 8)) << 16) | (uint32(uint8(v >> 16)) << 8)
                | uint32(uint8(v >> 24))
        );
    }

    function _le64(uint64 v) internal pure returns (bytes8) {
        return bytes8(uint64(BitcoinLib.reverse256(uint256(v)) >> 192));
    }
}
