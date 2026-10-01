// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {XrplUnlKeys} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplUnlKeys.sol";
import {XrplLib} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title XrplLightClient
/// @notice Stateless XRP Ledger light client: UNL validations, validator manifests, ledger headers,
///         and SHAMap proofs of transactions (with metadata) and ledger objects. Split from
///         {XrplVerifier} to keep both under EIP-170; it holds no CLPR logic.
///
///         A ledger is validated when at least ceil(0.8 × n) validators of a UNL of n sign full
///         validations of its hash (rippled `ValidatorList::calculateQuorum`; the negative UNL, which
///         can lower the quorum to 60%, is not applied, which is stricter).
///
/// @dev Ledger proof prefix shared by every entry point, RLP:
///        [0] UNL: [[masterKey(33), signingAddress(20), manifestSeq], ...]  (must hash to `unlHash`)
///        [1] manifests: [manifest, ...]  signing-key rotations, applied before validations
///        [2] validated ledger header (118 bytes, no prefix)
///        [3] validations: [[unlIndex, STValidation], ...]  strictly increasing indexes
///        [4] ancestors: [header, ...]  ancestors[0] is the parent of [2], and so on
///      Transaction entries are [ledgerRef, tx, meta, [inner(512), ...]]: ledgerRef 0 is [2], k is
///      ancestors[k-1]; each inner is one inner node's 16 child hashes, root first.
contract XrplLightClient {
    XrplUnlKeys public immutable UNL_KEYS;
    /// @dev {ClprSha512Hasher}: sha512Half for every ledger, validation and SHAMap hash.
    address public immutable HASHER;

    error InvalidPayloadShape();
    error UnlMismatch();
    error EmptyUnl();
    error QuorumNotReached(uint256 have, uint256 need);
    error ValidatorIndexOrder(uint256 index);
    error BadValidationSignature(uint256 index);
    error StaleLedger(uint32 seq, uint256 minSeq);
    error AncestorMismatch(uint256 index);
    error BadLedgerRef(uint256 ref);
    error TransactionFailed();
    error ZeroUnlKeys();

    constructor(XrplUnlKeys unlKeys) {
        if (address(unlKeys) == address(0)) revert ZeroUnlKeys();
        UNL_KEYS = unlKeys;
        HASHER = unlKeys.HASHER();
    }

    struct Unl {
        bytes[] masters;
        address[] signers;
        uint32[] seqs;
    }

    /// @dev One proven, successful transaction: its id and serialized bytes (callers parse them).
    struct ProvenTx {
        bytes32 id;
        bytes tx;
    }

    /// @dev The validated-ledger part of a proof.
    struct Ledger {
        uint32 seq;
        bytes32 accountHash;
        bytes32[] txRoots;
        bytes32 newUnlHash; // non-zero iff a manifest rotated a signing key
    }

    // ── entry points ──────────────────────────────────────────────────────────

    /// @notice Validate the ledger part of `proof` (fields 0-4) against a UNL committed as
    ///         (unlHash, unlCount), with header sequence >= minLedgerSeq, and prove the transaction
    ///         entries listed in field `txField`. Only successful (tesSUCCESS) transactions pass.
    function proveTransactions(
        bytes calldata proof,
        bytes32 unlHash,
        uint256 unlCount,
        uint256 minLedgerSeq,
        uint256 txField
    ) external view returns (Ledger memory lg, ProvenTx[] memory txs) {
        Memory.Slice[] memory p = RLP.decodeList(proof);
        if (p.length <= txField || txField < 5) revert InvalidPayloadShape();
        lg = _ledger(p, unlHash, unlCount, minLedgerSeq);
        Memory.Slice[] memory list = RLP.readList(p[txField]);
        txs = new ProvenTx[](list.length);
        for (uint256 k = 0; k < list.length; ++k) {
            txs[k] = _proveTx(list[k], lg.txRoots);
        }
    }

    /// @notice Config: validate a ledger against a UNL given with compressed signing keys (turned
    ///         into addresses here, once) and prove `account`'s AccountRoot in its state tree.
    ///         Proof RLP: [UNL [[master, signingKey(33), seq], ...], header, validations,
    ///         [inner(512), ...], accountRootData, ...].
    /// @return ledgerSeq the validated ledger; unlHash/unlCount the UNL commitment for the anchor
    function proveConfigAccount(bytes calldata proof, bytes20 account)
        external
        view
        returns (uint32 ledgerSeq, bytes32 unlHash, uint256 unlCount, bytes memory accountRoot)
    {
        Memory.Slice[] memory p = RLP.decodeList(proof);
        if (p.length < 5) revert InvalidPayloadShape();
        Unl memory unl;
        (unl.masters, unl.signers, unl.seqs) = UNL_KEYS.configUnl(proof);
        XrplLib.Header memory hd = XrplLib.parseHeader(RLP.readBytes(p[1]), HASHER);
        _requireQuorum(unl, RLP.readList(p[2]), hd);
        bytes32 key = XrplLib.half(HASHER, abi.encodePacked(uint16(0x0061), account)); // keylet::account
        accountRoot = RLP.readBytes(p[4]);
        UNL_KEYS.verifyStateEntry(hd.accountHash, key, _blobs(p[3]), accountRoot);
        ledgerSeq = hd.seq;
        unlHash = _unlHash(unl);
        unlCount = unl.signers.length;
    }

    /// @notice Prove one ledger object in a validated ledger's state tree (AccountRoot, DID, ...).
    /// @param proof RLP [UNL, manifests, header, validations, ancestors, [inner(512), ...], key, leafData]
    function verifyLedgerEntry(bytes calldata proof, bytes32 unlHash, uint256 unlCount, uint256 minLedgerSeq)
        external
        view
        returns (uint32 ledgerSeq, bytes32 key, bytes memory data)
    {
        Memory.Slice[] memory p = RLP.decodeList(proof);
        if (p.length != 8) revert InvalidPayloadShape();
        Ledger memory lg = _ledger(p, unlHash, unlCount, minLedgerSeq);
        key = RLP.readBytes32(p[6]);
        data = RLP.readBytes(p[7]);
        UNL_KEYS.verifyStateEntry(lg.accountHash, key, _blobs(p[5]), data);
        ledgerSeq = lg.seq;
    }

    // ── ledger ────────────────────────────────────────────────────────────────

    function _ledger(Memory.Slice[] memory p, bytes32 unlHash, uint256 unlCount, uint256 minLedgerSeq)
        internal
        view
        returns (Ledger memory lg)
    {
        Unl memory unl = _decodeUnl(p[0], unlHash, unlCount);
        bool rotated;
        Memory.Slice[] memory manifests = RLP.readList(p[1]);
        if (manifests.length > 0) {
            bytes[] memory blobs = new bytes[](manifests.length);
            for (uint256 k = 0; k < manifests.length; ++k) {
                blobs[k] = RLP.readBytes(manifests[k]);
            }
            (unl.signers, unl.seqs) = UNL_KEYS.applyManifests(unl.masters, unl.signers, unl.seqs, blobs);
            rotated = true;
        }
        XrplLib.Header memory hd = XrplLib.parseHeader(RLP.readBytes(p[2]), HASHER);
        if (hd.seq < minLedgerSeq) revert StaleLedger(hd.seq, minLedgerSeq);
        _requireQuorum(unl, RLP.readList(p[3]), hd);
        lg.seq = hd.seq;
        lg.accountHash = hd.accountHash;
        lg.txRoots = _txRoots(hd, RLP.readList(p[4]));
        if (rotated) lg.newUnlHash = _unlHash(unl);
    }

    /// @dev Inclusion of one [ledgerRef, tx, meta, inners] entry in its ledger's transaction tree,
    ///      and tesSUCCESS.
    function _proveTx(Memory.Slice item, bytes32[] memory txRoots) internal view returns (ProvenTx memory out) {
        Memory.Slice[] memory e = RLP.readList(item);
        if (e.length != 4) revert InvalidPayloadShape();
        uint256 ref = RLP.readUint256(e[0]);
        if (ref >= txRoots.length) revert BadLedgerRef(ref);
        out.tx = RLP.readBytes(e[1]);
        bytes32 leaf;
        (out.id, leaf) = _txLeaf(out.tx, RLP.readBytes(e[2]));
        XrplLib.verifyPath(txRoots[ref], out.id, _blobs(e[3]), leaf, HASHER);
    }

    /// @dev Transaction id and tx+meta leaf hash; reverts unless the metadata says tesSUCCESS.
    function _txLeaf(bytes memory txb, bytes memory meta) private view returns (bytes32 id, bytes32 leaf) {
        if (!XrplLib.metaSucceeded(meta)) revert TransactionFailed();
        id = XrplLib.txId(txb, HASHER);
        leaf = XrplLib.txLeafHash(txb, meta, id, HASHER);
    }

    // ── consensus ─────────────────────────────────────────────────────────────

    /// @dev At least ceil(0.8 n) distinct UNL validators signed a full validation of `hd`. The
    ///      negative UNL, which can lower rippled's quorum to 60%, is not applied: stricter.
    function _requireQuorum(Unl memory unl, Memory.Slice[] memory vals, XrplLib.Header memory hd) internal view {
        uint256 n = unl.signers.length;
        uint256 need = (n * 8 + 9) / 10;
        if (vals.length < need) revert QuorumNotReached(vals.length, need);
        uint256 prev;
        for (uint256 k = 0; k < vals.length; ++k) {
            Memory.Slice[] memory e = RLP.readList(vals[k]);
            if (e.length != 2) revert InvalidPayloadShape();
            uint256 idx = RLP.readUint256(e[0]);
            if (idx >= n || (k > 0 && idx <= prev)) revert ValidatorIndexOrder(idx);
            prev = idx;
            (bytes32 digest, bytes32 r, bytes32 s) =
                XrplLib.validationDigest(RLP.readBytes(e[1]), hd.hash, hd.seq, HASHER);
            if (!XrplLib.signedBy(digest, r, s, unl.signers[idx])) revert BadValidationSignature(idx);
        }
    }

    /// @dev Roots of the validated ledger's transaction tree and of each linked ancestor's. An
    ///      ancestor entry is [header] (the parent of the previous header) or
    ///      [header, [inner(512), ...], skipListData] / [header, ""]: a header whose hash is in the
    ///      validated ledger's LedgerHashes skip list (proven once, by the first such entry) (keylet::skip(), the last 256 ledger hashes, maintained by
    ///      `Ledger::updateSkipList`), proven in its state tree. Later [header] entries continue from
    ///      the last linked header.
    function _txRoots(XrplLib.Header memory hd, Memory.Slice[] memory ancestors)
        internal
        view
        returns (bytes32[] memory roots)
    {
        roots = new bytes32[](ancestors.length + 1);
        roots[0] = hd.txHash;
        bytes32 parent = hd.parentHash;
        bytes memory skip;
        for (uint256 k = 0; k < ancestors.length; ++k) {
            Memory.Slice[] memory e = RLP.readList(ancestors[k]);
            if (e.length == 0 || e.length > 3) revert InvalidPayloadShape();
            XrplLib.Header memory h = XrplLib.parseHeader(RLP.readBytes(e[0]), HASHER);
            if (e.length == 1) {
                if (h.hash != parent) revert AncestorMismatch(k);
            } else {
                bytes32 listed;
                if (e.length == 3) {
                    // first skip-linked entry: prove the skip list once, keep it for the next ones
                    skip = RLP.readBytes(e[2]);
                    listed = UNL_KEYS.skipListHash(hd.accountHash, _blobs(e[1]), skip, h.seq);
                } else {
                    if (skip.length == 0) revert AncestorMismatch(k);
                    listed = UNL_KEYS.skipListLookup(skip, h.seq);
                }
                if (listed != h.hash) revert AncestorMismatch(k);
            }
            roots[k + 1] = h.txHash;
            parent = h.parentHash;
        }
    }

    function _decodeUnl(Memory.Slice item, bytes32 unlHash, uint256 unlCount) internal pure returns (Unl memory unl) {
        Memory.Slice[] memory list = RLP.readList(item);
        uint256 n = list.length;
        if (n == 0) revert EmptyUnl();
        if (n != unlCount) revert UnlMismatch();
        unl.masters = new bytes[](n);
        unl.signers = new address[](n);
        unl.seqs = new uint32[](n);
        for (uint256 k = 0; k < n; ++k) {
            Memory.Slice[] memory e = RLP.readList(list[k]);
            if (e.length != 3) revert InvalidPayloadShape();
            unl.masters[k] = RLP.readBytes(e[0]);
            unl.signers[k] = RLP.readAddress(e[1]);
            unl.seqs[k] = uint32(RLP.readUint256(e[2]));
        }
        if (_unlHash(unl) != unlHash) revert UnlMismatch();
    }

    function _unlHash(Unl memory unl) internal pure returns (bytes32) {
        bytes memory acc;
        for (uint256 k = 0; k < unl.signers.length; ++k) {
            acc = abi.encodePacked(acc, unl.masters[k], unl.signers[k], unl.seqs[k]);
        }
        return keccak256(acc);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _blobs(Memory.Slice item) internal pure returns (bytes[] memory out) {
        Memory.Slice[] memory l = RLP.readList(item);
        out = new bytes[](l.length);
        for (uint256 k = 0; k < l.length; ++k) {
            out[k] = RLP.readBytes(l[k]);
        }
    }
}
