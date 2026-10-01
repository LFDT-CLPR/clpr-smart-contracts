// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TonCells} from "@hiero-ledger/clpr/libraries/proof/ton/TonCells.sol";

/// @title TonBlocks
/// @notice TL-B readers for the TON structures a masterchain light client and an account-state proof
///         need. Layouts follow ton-blockchain/ton `crypto/block/block.tlb` (master `3d478cb`):
///         `block#11ef55aa`, `block_info#9bc7a987`, `!merkle_update#04`, `block_extra`,
///         `masterchain_block_extra#cca5` (config in key blocks), `validators_ext#12` (ConfigParam 34),
///         `shard_state#9023afe2`, `masterchain_state_extra#cc26` (ShardHashes), `shard_descr#b/#a`,
///         `ShardAccounts` (HashmapAugE 256 ShardAccount DepthBalanceInfo) and `account$1`.
library TonBlocks {
    using TonCells for TonCells.Boc;

    uint256 internal constant BLOCK_TAG = 0x11ef55aa;
    uint256 internal constant BLOCK_INFO_TAG = 0x9bc7a987;
    uint256 internal constant BLOCK_EXTRA_TAG = 0x4a33f6fd;
    uint256 internal constant MC_BLOCK_EXTRA_TAG = 0xcca5;
    uint256 internal constant SHARD_STATE_TAG = 0x9023afe2;
    uint256 internal constant MC_STATE_EXTRA_TAG = 0xcc26;
    uint256 internal constant SIG_PUBKEY_TAG = 0x8e81278a;
    uint256 internal constant CONFIG_VALIDATORS = 34;

    struct BlockInfo {
        bool notMaster;
        bool keyBlock;
        uint32 seqno;
        int32 workchain;
        uint8 shardPfxBits;
        uint64 shardPrefix;
        uint32 prevKeyBlockSeqno;
    }

    error BadTag(uint256 tag);
    error NotAccountActive();
    error AccountAddressMismatch();
    error BadValidatorSet();
    error ShardNotFound();
    error UnsupportedAddress();

    /// @notice Decode the header fields of a block (`Block.info`).
    function blockInfo(TonCells.Boc memory b, uint256 blockCell) internal pure returns (BlockInfo memory info) {
        TonCells.Slice memory s = b.open(blockCell);
        if (b.loadUint(s, 32) != BLOCK_TAG) revert BadTag(1);
        TonCells.Slice memory i = b.open(b.ref(blockCell, 0));
        if (b.loadUint(i, 32) != BLOCK_INFO_TAG) revert BadTag(2);
        b.skip(i, 32); // version
        info.notMaster = b.loadBit(i);
        b.skip(i, 5); // after_merge before_split after_split want_split want_merge
        info.keyBlock = b.loadBit(i);
        b.skip(i, 1 + 8); // vert_seqno_incr flags
        info.seqno = uint32(b.loadUint(i, 32));
        b.skip(i, 32); // vert_seq_no
        if (b.loadUint(i, 2) != 0) revert BadTag(3); // shard_ident$00
        info.shardPfxBits = uint8(b.loadUint(i, 6));
        info.workchain = int32(uint32(b.loadUint(i, 32)));
        info.shardPrefix = uint64(b.loadUint(i, 64));
        b.skip(i, 32 + 64 + 64 + 32 + 32 + 32); // gen_utime start_lt end_lt vset_hash cc_seqno min_ref_mc
        info.prevKeyBlockSeqno = uint32(b.loadUint(i, 32));
    }

    /// @notice `Block.state_update` new state hash (the MERKLE_UPDATE cell must be in the proof).
    function newStateHash(TonCells.Boc memory b, uint256 blockCell) internal pure returns (bytes32) {
        uint256 su = b.ref(blockCell, 2);
        if (b.cells[su].cellType != TonCells.MERKLE_UPDATE) revert BadTag(4);
        return b.exoticWord(su, 33); // type(1) old_hash(32) new_hash(32)
    }

    /// @notice Packed (pubkey ‖ uint64 weight) list of the masterchain validators — the first `main`
    ///         entries of ConfigParam 34 — and their total weight, read from a key block's config.
    function keyBlockValidators(TonCells.Boc memory b, uint256 blockCell)
        internal
        pure
        returns (bytes memory packed, uint256 total)
    {
        uint256 extra = b.ref(blockCell, 3);
        TonCells.Slice memory e = b.open(extra);
        if (b.loadUint(e, 32) != BLOCK_EXTRA_TAG) revert BadTag(5);
        b.skip(e, 512); // rand_seed created_by
        if (!b.loadBit(e)) revert BadTag(6);
        uint256 mce = b.ref(extra, 3);
        TonCells.Slice memory m = b.open(mce);
        if (b.loadUint(m, 16) != MC_BLOCK_EXTRA_TAG) revert BadTag(7);
        if (!b.loadBit(m)) revert BadTag(8); // key_block
        if (b.loadBit(m)) b.loadRef(m); // shard_hashes
        if (b.loadBit(m)) b.loadRef(m); // shard_fees root
        b.skipCurrencyCollection(m); // shard_fees extra: fees
        b.skipCurrencyCollection(m); // create
        b.loadRef(m); // ^[ prev_blk_signatures recover_create_msg mint_msg ]
        b.skip(m, 256); // config_addr
        uint256 cfg = b.loadRef(m);
        TonCells.Slice memory leaf = b.lookup(cfg, CONFIG_VALIDATORS, 32);
        uint256 vsCell = b.loadRef(leaf);
        return _validatorSet(b, vsCell);
    }

    function _validatorSet(TonCells.Boc memory b, uint256 vsCell)
        private
        pure
        returns (bytes memory packed, uint256 total)
    {
        TonCells.Slice memory v = b.open(vsCell);
        uint256 tag = b.loadUint(v, 8);
        if (tag != 0x11 && tag != 0x12) revert BadValidatorSet();
        b.skip(v, 64); // utime_since utime_until
        uint256 totalCount = b.loadUint(v, 16);
        uint256 main = b.loadUint(v, 16);
        if (main == 0 || main > totalCount) revert BadValidatorSet();
        uint256 listRoot;
        if (tag == 0x12) {
            b.skip(v, 64); // total_weight (of all validators; the masterchain total is recomputed)
            if (!b.loadBit(v)) revert BadValidatorSet();
        }
        listRoot = b.loadRef(v);
        packed = new bytes(main * 40);
        uint256 count;
        (count, total) = _collect(b, listRoot, 0, 16, main, packed, 0, 0);
        if (count != main) revert BadValidatorSet();
    }

    /// @dev In-order walk of `Hashmap 16 ValidatorDescr`, keeping keys 0..main-1 (they must be
    ///      contiguous). A pruned subtree is allowed only if every key under it is ≥ main.
    function _collect(
        TonCells.Boc memory b,
        uint256 cell,
        uint256 prefix,
        uint256 m,
        uint256 main,
        bytes memory packed,
        uint256 count,
        uint256 total
    ) private pure returns (uint256, uint256) {
        if (b.cells[cell].cellType == TonCells.PRUNED) {
            if ((prefix << m) < main) revert BadValidatorSet();
            return (count, total);
        }
        TonCells.Slice memory s = b.open(cell);
        (uint256 len, uint256 val) = b.loadLabel(s, m);
        prefix = (prefix << len) | val;
        m -= len;
        if (m == 0) {
            if (prefix >= main) return (count, total);
            if (prefix != count) revert BadValidatorSet();
            uint256 dtag = b.loadUint(s, 8);
            if (dtag != 0x53 && dtag != 0x73) revert BadValidatorSet();
            if (b.loadUint(s, 32) != SIG_PUBKEY_TAG) revert BadValidatorSet();
            bytes32 pk = bytes32(b.loadUint(s, 256));
            uint64 w = uint64(b.loadUint(s, 64));
            assembly ("memory-safe") {
                let p := add(add(packed, 0x20), mul(count, 40))
                mstore(p, pk)
                // weight: 8 bytes big-endian right after the key
                let q := add(p, 32)
                mstore(q, or(shl(192, w), and(mload(q), sub(shl(192, 1), 1))))
            }
            return (count + 1, total + w);
        }
        (count, total) = _collect(b, b.ref(cell, 0), prefix << 1, m - 1, main, packed, count, total);
        return _collect(b, b.ref(cell, 1), (prefix << 1) | 1, m - 1, main, packed, count, total);
    }

    /// @notice From a masterchain state, the root hash of the shard block holding `addr` in `workchain`
    ///         (McStateExtra.shard_hashes → BinTree ShardDescr).
    function shardBlockRoot(TonCells.Boc memory b, int32 workchain, bytes32 addr) internal pure returns (bytes32) {
        uint256 root = b.root;
        TonCells.Slice memory s = b.open(root);
        if (b.loadUint(s, 32) != SHARD_STATE_TAG) revert BadTag(9);
        // global_id 32, shard_ident 104, seq_no 32, vert_seq_no 32, gen_utime 32, gen_lt 64,
        // min_ref_mc_seqno 32, before_split 1, then custom:(Maybe ^McStateExtra)
        b.skip(s, 32 + 104 + 32 + 32 + 32 + 64 + 32 + 1);
        if (!b.loadBit(s)) revert BadTag(10);
        uint256 mse = b.ref(root, 3);
        TonCells.Slice memory x = b.open(mse);
        if (b.loadUint(x, 16) != MC_STATE_EXTRA_TAG) revert BadTag(11);
        if (!b.loadBit(x)) revert ShardNotFound();
        uint256 hashesRoot = b.loadRef(x);
        TonCells.Slice memory leaf = b.lookup(hashesRoot, uint32(workchain), 32);
        uint256 node = b.loadRef(leaf);
        for (uint256 depth = 0; depth <= 60; depth++) {
            TonCells.Slice memory t = b.open(node);
            if (!b.loadBit(t)) {
                uint256 tag = b.loadUint(t, 4);
                if (tag != 0xa && tag != 0xb) revert BadTag(12);
                b.skip(t, 32 + 32 + 64 + 64);
                return bytes32(b.loadUint(t, 256));
            }
            if (depth == 60) break;
            node = b.ref(node, uint256(addr) >> (255 - depth) & 1);
        }
        revert ShardNotFound();
    }

    /// @notice From a shard (or masterchain) state, the hash of `addr`'s `Account` cell.
    function accountHash(TonCells.Boc memory b, bytes32 addr) internal pure returns (bytes32) {
        uint256 root = b.root;
        TonCells.Slice memory s = b.open(root);
        if (b.loadUint(s, 32) != SHARD_STATE_TAG) revert BadTag(13);
        uint256 accounts = b.ref(root, 1);
        TonCells.Slice memory a = b.open(accounts);
        if (!b.loadBit(a)) revert TonCells.KeyNotFound();
        uint256 dictRoot = b.loadRef(a);
        TonCells.Slice memory leaf = b.lookup(dictRoot, uint256(addr), 256);
        // ahmn_leaf: extra:DepthBalanceInfo value:ShardAccount
        b.skip(leaf, 5); // split_depth (#<= 30)
        b.skipCurrencyCollection(leaf); // balance
        uint256 accountCell = b.loadRef(leaf); // account_descr: account:^Account
        return b.cells[accountCell].hashes[0];
    }

    /// @notice Parse an `Account` cell (the root of `b`), check its address, and return the index of
    ///         its persistent data cell (`StateInit.data`).
    function accountData(TonCells.Boc memory b, int8 workchain, bytes32 addr) internal pure returns (uint256) {
        TonCells.Slice memory s = b.open(b.root);
        if (!b.loadBit(s)) revert NotAccountActive(); // account_none$0
        if (b.loadUint(s, 2) != 2) revert UnsupportedAddress(); // addr_std$10
        if (b.loadBit(s)) revert UnsupportedAddress(); // anycast
        if (int8(uint8(b.loadUint(s, 8))) != workchain || bytes32(b.loadUint(s, 256)) != addr) {
            revert AccountAddressMismatch();
        }
        // storage_stat: StorageUsed{cells, bits: VarUInteger 7}, StorageExtraInfo, last_paid, due_payment
        b.loadVarUint(s, 3);
        b.loadVarUint(s, 3);
        uint256 extra = b.loadUint(s, 3);
        if (extra == 1) b.skip(s, 256);
        else if (extra != 0) revert BadTag(14);
        b.skip(s, 32);
        if (b.loadBit(s)) b.loadVarUint(s, 4);
        // storage: last_trans_lt, balance, state
        b.skip(s, 64);
        b.skipCurrencyCollection(s);
        if (!b.loadBit(s)) revert NotAccountActive(); // account_active$1
        if (b.loadBit(s)) b.skip(s, 5); // fixed_prefix_length
        if (b.loadBit(s)) b.skip(s, 2); // special
        if (b.loadBit(s)) b.loadRef(s); // code
        if (!b.loadBit(s)) revert NotAccountActive(); // data
        return b.loadRef(s);
    }
}
