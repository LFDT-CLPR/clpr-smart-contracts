// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprBlake2} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprBlake2.sol";
import {ClprMithrilStm} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilStm.sol";
import {ClprMithrilMessage} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilMessage.sol";
import {ClprMithrilMmr} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilMmr.sol";
import {ClprBlake2sHasher} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprBlake2sHasher.sol";
import {CardanoMithrilVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/CardanoMithrilVerifier.sol";
import {MithrilStmVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/MithrilStmVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @notice Synthetic but cryptographically real Mithril/Cardano worlds for CardanoMithrilVerifier:
///         BLS keys and signatures via EIP-2537, the real STM lottery (signers keep exactly the
///         indexes they win), the registration batch path, MKMap/MMR trees over BLAKE2s, and CBOR
///         block headers, transaction bodies and Plutus datums built the way Cardano encodes them.
contract CardanoTestKit {
    using RLP for bytes[];

    bytes32 internal constant CHANNEL_ID = keccak256("cardano-channel");
    bytes28 internal constant SCRIPT = bytes28(keccak256("clpr-plutus-script"));

    // φ_f = 0.65: U8F24 and |ln(0.35)| as the f64 mithril computes
    uint32 internal constant PHI = 10905190;
    uint64 internal constant LN_MANT = 1181994632174387;
    uint16 internal constant LN_EXP = 50;
    uint64 internal constant M = 40;

    address internal blake2s;
    MithrilStmVerifier internal stm;
    CardanoMithrilVerifier internal cv;

    struct Network {
        uint64 epoch;
        uint256[] sks;
        uint64[] stakes;
        bytes[] vks; // uncompressed G2
        bytes32[] leaves;
        bytes32 root;
        uint64 total;
        uint64 k;
        uint64 m;
    }

    struct Queue {
        uint8 status;
        uint64 nextMessageId;
        uint64 receivedMessageId;
        bytes32 sentRunningHash;
        bytes32 receivedRunningHash;
        uint64 peerManifestVersion;
        bytes32 manifestCommitment;
    }

    /// @dev Everything that makes up a bundle; tests mutate fields before encoding.
    struct World {
        Network net;
        bool[] signs;
        uint256[] keyIds;
        bytes[] values;
        bytes[] rotations; // encoded rotation certs
        bytes txBody;
        bytes header;
        bytes32 bodiesHash;
        bytes invalidTxs;
        bytes bodies; // overrides bodiesHash when non-empty
        uint256 txIndex;
        uint256 outputIndex;
        bytes sibLeaf;
        bytes32 otherOuter;
        uint64 blockNumber;
        uint64 slot;
        uint64 rangeStart;
        bytes content;
        bytes manifest;
        bool withManifest;
    }

    function _initKit() internal {
        blake2s = address(new ClprBlake2sHasher());
        stm = new MithrilStmVerifier();
        cv = new CardanoMithrilVerifier(stm, blake2s);
    }

    // ── BLS ─────────────────────────────────────────────────────────────────

    function _g2Gen() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes16(0),
            hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            bytes16(0),
            hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            bytes16(0),
            hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            bytes16(0),
            hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    function _mul(address pre, bytes memory p, uint256 s, uint256 outLen) internal view returns (bytes memory out) {
        bytes memory input = abi.encodePacked(p, s);
        out = new bytes(outLen);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), pre, add(input, 0x20), mload(input), add(out, 0x20), outLen)
        }
        require(ok, "msm");
    }

    // ── Network / registration tree ─────────────────────────────────────────

    function _network(uint64 epoch, uint256 seed, uint256 n, uint64 k) internal view returns (Network memory net) {
        net.epoch = epoch;
        net.k = k;
        net.m = M;
        net.sks = new uint256[](n);
        net.stakes = new uint64[](n);
        net.vks = new bytes[](n);
        net.leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            net.sks[i] = uint256(keccak256(abi.encode(seed, i))) % (2 ** 250) + 1;
            net.stakes[i] = uint64(1_000_000 * (i + 2));
            net.total += net.stakes[i];
            net.vks[i] = _mul(address(0x0e), _g2Gen(), net.sks[i], 256);
            bytes memory vkc = encG2(net.vks[i]);
            net.leaves[i] = ClprBlake2.b2b256(abi.encodePacked(vkc, net.stakes[i]));
        }
        net.root = _treeRoot(net.leaves);
    }

    function _heap(bytes32[] memory leaves) internal view returns (bytes32[] memory nodes, uint256 pow2) {
        uint256 n = leaves.length;
        pow2 = 1;
        while (pow2 < n) pow2 <<= 1;
        nodes = new bytes32[](2 * pow2 - 1);
        bytes32 pad = ClprBlake2.b2b256(hex"00");
        for (uint256 i = 0; i < pow2; i++) {
            nodes[pow2 - 1 + i] = i < n ? leaves[i] : pad;
        }
        for (uint256 i = pow2 - 1; i > 0; i--) {
            nodes[i - 1] = ClprBlake2.b2b256(abi.encodePacked(nodes[2 * i - 1], nodes[2 * i]));
        }
    }

    function _treeRoot(bytes32[] memory leaves) internal view returns (bytes32) {
        (bytes32[] memory nodes,) = _heap(leaves);
        return nodes[0];
    }

    /// @dev Batch path values in the order mithril's verifier consumes them.
    function _batchValues(Network memory net, uint256[] memory idxs) internal view returns (bytes memory values) {
        (bytes32[] memory nodes, uint256 pow2) = _heap(net.leaves);
        uint256 nrNodes = pow2 + net.leaves.length - 1;
        uint256 len = idxs.length;
        uint256[] memory idx = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            idx[i] = pow2 + idxs[i] - 1;
        }
        uint256 top = idx[0];
        while (top > 0) {
            top = (top - 1) / 2;
            uint256 outLen;
            for (uint256 i = 0; i < len; i++) {
                uint256 node = idx[i];
                if (node % 2 == 0) {
                    values = abi.encodePacked(values, nodes[node - 1]);
                } else if (i + 1 < len && idx[i + 1] == node + 1) {
                    i++;
                } else if (node + 1 < nrNodes) {
                    values = abi.encodePacked(values, nodes[node + 1]);
                }
                idx[outLen++] = (node - 1) / 2;
            }
            len = outLen;
        }
    }

    function _avk(Network memory net) internal pure returns (ClprMithrilStm.Avk memory) {
        return ClprMithrilStm.Avk({root: net.root, nrLeaves: uint64(net.leaves.length), totalStake: net.total});
    }

    function _params(Network memory net) internal pure returns (ClprMithrilStm.Params memory) {
        return ClprMithrilStm.Params({k: net.k, m: net.m, phiFixed: PHI, lnMant: LN_MANT, lnExpNeg: LN_EXP});
    }

    function _anchor(Network memory net) internal view returns (bytes memory) {
        return cv.encodeAnchor(CardanoMithrilVerifier.Anchor({epoch: net.epoch, avk: _avk(net), params: _params(net)}));
    }

    // ── Certificates ───────────────────────────────────────────────────────

    function _parts(uint64 epoch, bytes32 btRoot, Network memory next)
        internal
        pure
        returns (uint256[] memory ids, bytes[] memory vals)
    {
        ids = new uint256[](6);
        vals = new bytes[](6);
        (ids[0], vals[0]) = (2, abi.encodePacked(btRoot));
        (ids[1], vals[1]) = (3, abi.encodePacked(next.root, uint64(next.leaves.length), next.total));
        (ids[2], vals[2]) = (4, abi.encodePacked(next.k, next.m, PHI));
        (ids[3], vals[3]) = (5, abi.encodePacked(epoch));
        (ids[4], vals[4]) = (6, abi.encodePacked(uint64(1000)));
        (ids[5], vals[5]) = (7, abi.encodePacked(uint64(100)));
    }

    /// @dev Sign the rebuilt message with every `signs[i]` party, keeping only lottery wins.
    function _cert(Network memory net, bool[] memory signs, uint256[] memory ids, bytes[] memory vals)
        internal
        view
        returns (bytes memory)
    {
        bytes memory msgp = bytes.concat(ClprMithrilMessage.build(ids, vals).message, net.root);
        (bytes[] memory signers, uint256[] memory idxs) = _signers(net, signs, msgp);
        bytes[] memory items = new bytes[](4);
        items[0] = _uintList(ids);
        items[1] = _bytesList(vals);
        items[2] = _bytesList(signers);
        items[3] = RLP.encode(_batchValues(net, idxs));
        return RLP.encode(items);
    }

    function _signers(Network memory net, bool[] memory signs, bytes memory msgp)
        internal
        view
        returns (bytes[] memory signers, uint256[] memory idxs)
    {
        bytes memory h = ClprMithrilStm.hashToG1(msgp);
        uint256 cnt;
        for (uint256 i = 0; i < signs.length; i++) {
            if (signs[i]) cnt++;
        }
        signers = new bytes[](cnt);
        idxs = new uint256[](cnt);
        uint256 c;
        bool[] memory taken = new bool[](net.m + 1);
        for (uint256 i = 0; i < signs.length; i++) {
            if (!signs[i]) continue;
            signers[c] = _signerEntry(net, i, h, msgp, taken);
            idxs[c++] = i;
        }
    }

    /// @dev Like mithril's aggregator, each lottery index is used by one signature only.
    function _signerEntry(Network memory net, uint256 i, bytes memory h, bytes memory msgp, bool[] memory taken)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sigma = _mul(address(0x0c), h, net.sks[i], 128);
        bytes memory enc = abi.encodePacked(encG1(sigma), encG2(net.vks[i]));
        bytes memory won = _wins(net, msgp, enc, net.stakes[i], taken);
        return abi.encodePacked(sigma, net.vks[i], enc, net.stakes[i], uint32(i), won);
    }

    /// @dev Compressed G1 encoding, from the existing {ClprBls12381.compressG1}.
    function encG1(bytes memory pt) internal pure returns (bytes memory) {
        return ClprBls12381.compressG1(pt);
    }

    /// @dev Compressed G2 encoding `x.c1 ‖ x.c0` with the compression flag. The verifier binds key
    ///      encodings by x-coordinate and flags only, so the third flag bit is left clear.
    function encG2(bytes memory pt) internal pure returns (bytes memory out) {
        out = new bytes(96);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(pt, 0x70), 48)
            mcopy(add(out, 0x50), add(pt, 0x30), 48)
        }
        out[0] = bytes1(uint8(out[0]) | 0x80);
    }

    /// @dev `enc` = σ compressed (48) ‖ vk compressed (96); the lottery hashes the first 48 bytes.
    function _wins(Network memory net, bytes memory msgp, bytes memory enc, uint64 stake, bool[] memory taken)
        internal
        view
        returns (bytes memory won)
    {
        bytes memory sc = new bytes(48);
        assembly ("memory-safe") {
            mcopy(add(sc, 0x20), add(enc, 0x20), 48)
        }
        uint256 t = ClprMithrilStm.lotteryThreshold(stake, net.total, _params(net));
        for (uint256 j = 0; j <= net.m; j++) {
            (, bytes32 hi) = ClprBlake2.b2b(abi.encodePacked("map", msgp, _le64(j), sc), 64);
            uint256 evTop = ClprMithrilStm._bswap(uint256(hi)) >> 136;
            if (evTop + 1 + (1 << 16) <= t && !taken[j]) {
                taken[j] = true;
                won = abi.encodePacked(won, uint32(j));
            }
        }
    }

    function _le64(uint256 x) internal pure returns (bytes8) {
        return bytes8(bytes32(ClprMithrilStm._bswap(x)));
    }

    // ── Ledger encodings (CBOR) ─────────────────────────────────────────────

    function _head(uint8 major, uint256 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8((major << 5) | uint8(n)));
        if (n < 256) return abi.encodePacked(uint8((major << 5) | 24), uint8(n));
        if (n < 65536) return abi.encodePacked(uint8((major << 5) | 25), uint16(n));
        if (n < 2 ** 32) return abi.encodePacked(uint8((major << 5) | 26), uint32(n));
        return abi.encodePacked(uint8((major << 5) | 27), uint64(n));
    }

    function _cu(uint256 n) internal pure returns (bytes memory) {
        return _head(0, n);
    }

    function _cb(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(_head(2, b.length), b);
    }

    function defaultQueue() internal pure returns (Queue memory q) {
        q.status = uint8(ClprTypes.ChannelStatus.ACTIVE);
        q.nextMessageId = 3;
        q.receivedMessageId = 1;
        q.sentRunningHash = keccak256("sent");
        q.receivedRunningHash = keccak256("received");
        q.peerManifestVersion = 4;
    }

    /// @dev Plutus data Constr 0 (tag 121) with an indefinite field list, as cardano-serialization emits.
    function _datum(Queue memory q) internal pure returns (bytes memory) {
        return bytes.concat(
            hex"d8799f",
            _cu(q.status),
            _cu(q.nextMessageId),
            _cu(q.receivedMessageId),
            _cb(abi.encodePacked(q.sentRunningHash)),
            _cb(abi.encodePacked(q.receivedRunningHash)),
            _cu(q.peerManifestVersion),
            q.manifestCommitment == bytes32(0) ? _cb("") : _cb(abi.encodePacked(q.manifestCommitment)),
            hex"ff"
        );
    }

    function _output(bytes28 script, bytes32 channelId, bytes memory datum) internal pure returns (bytes memory) {
        bytes memory addr = abi.encodePacked(uint8(0x70), script); // type 7: script payment, no stake, testnet
        bytes memory value = bytes.concat(
            hex"82",
            _cu(2_000_000),
            hex"a1",
            _cb(abi.encodePacked(script)),
            hex"a1",
            _cb(abi.encodePacked(channelId)),
            _cu(1)
        );
        bytes memory dopt = bytes.concat(hex"8201d818", _cb(datum));
        return bytes.concat(hex"a3", _cu(0), _cb(addr), _cu(1), value, _cu(2), dopt);
    }

    function _txBody(bytes memory output) internal pure returns (bytes memory) {
        // {0: [[txid, 0]], 1: [change, output], 2: fee}
        bytes memory change =
            bytes.concat(hex"82", _cb(abi.encodePacked(uint8(0x60), bytes28(keccak256("change")))), _cu(5));
        return bytes.concat(
            hex"a3",
            _cu(0),
            hex"8182",
            _cb(abi.encodePacked(keccak256("in"))),
            _cu(0),
            _cu(1),
            hex"82",
            change,
            output,
            _cu(2),
            _cu(170_000)
        );
    }

    function _header(uint64 blockNumber, uint64 slot, bytes32 bodyHash) internal pure returns (bytes memory) {
        bytes memory hb = bytes.concat(
            hex"8a",
            _cu(blockNumber),
            _cu(slot),
            _cb(abi.encodePacked(keccak256("prev"))),
            _cb(abi.encodePacked(keccak256("issuer"))),
            _cb(abi.encodePacked(keccak256("vrf"))),
            bytes.concat(hex"82", _cb(abi.encodePacked(keccak256("out"), keccak256("out2"))), _cb(new bytes(80))),
            _cu(4096),
            _cb(abi.encodePacked(bodyHash)),
            bytes.concat(hex"84", _cb(abi.encodePacked(keccak256("hot"))), _cu(7), _cu(400), _cb(new bytes(64))),
            hex"820a00"
        );
        return bytes.concat(hex"82", hb, _cb(new bytes(448)));
    }

    function _txLeaf(bytes32 txId, bytes32 blockHash, uint64 blockNumber, uint64 slot)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            "Tx/",
            ClprMithrilMessage.toHex(abi.encodePacked(txId)),
            "/",
            ClprMithrilMessage.toHex(abi.encodePacked(blockHash)),
            "/",
            cv.dec(blockNumber),
            "/",
            cv.dec(slot)
        );
    }

    // ── World / proofs ─────────────────────────────────────────────────────

    function _world(Network memory net, Network memory next, Queue memory q) internal pure returns (World memory w) {
        w.net = net;
        w.signs = new bool[](net.sks.length);
        for (uint256 i = 0; i < w.signs.length; i++) {
            w.signs[i] = i != 1; // party 1 abstains
        }
        w.txBody = _txBody(_output(SCRIPT, CHANNEL_ID, _datum(q)));
        w.bodiesHash = keccak256("bodies");
        w.invalidTxs = hex"80";
        w.outputIndex = 1;
        w.blockNumber = 1007;
        w.slot = 5_000_123;
        w.rangeStart = 1005;
        w.sibLeaf = abi.encodePacked(
            "Tx/",
            ClprMithrilMessage.toHex(abi.encodePacked(keccak256("sib"))),
            "/",
            ClprMithrilMessage.toHex(abi.encodePacked(keccak256("blk"))),
            "/1006/5000100"
        );
        w.otherOuter = keccak256("other-range");
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = "hello cardano";
        w.content = bytes.concat(hex"12", abi.encodePacked(uint8(payloads[0].length)), payloads[0]);
        (w.keyIds, w.values) = _parts(net.epoch, bytes32(0), next); // root filled in at encode time
    }

    function _bodyHash(World memory w) internal view returns (bytes32) {
        bytes32 bh = w.bodies.length > 0 ? ClprBlake2.b2b256(w.bodies) : w.bodiesHash;
        return
            ClprBlake2.b2b256(
                abi.encodePacked(bh, keccak256("wits"), keccak256("aux"), ClprBlake2.b2b256(w.invalidTxs))
            );
    }

    /// @dev Build header, MMR trees, the certified root, the certificate and the RLP bundle.
    function _encode(World memory w) internal view returns (bytes memory) {
        if (w.header.length == 0) w.header = _header(w.blockNumber, w.slot, _bodyHash(w));
        bytes32 txId = ClprBlake2.b2b256(w.txBody);
        bytes32 blockHash = ClprBlake2.b2b256(w.header);
        bytes memory leaf = _txLeaf(txId, blockHash, w.blockNumber, w.slot);
        bytes32 inner = ClprMithrilMmr.b2s256(blake2s, bytes.concat(leaf, w.sibLeaf));
        bytes32 outerLeaf = ClprMithrilMmr.b2s256(
            blake2s, abi.encodePacked(cv.dec(w.rangeStart), "-", cv.dec(w.rangeStart + 15), inner)
        );
        bytes32 root = ClprMithrilMmr.b2s256(blake2s, abi.encodePacked(outerLeaf, w.otherOuter));
        // fill the certified root (key id 2) unless the test replaced it
        for (uint256 i = 0; i < w.keyIds.length; i++) {
            if (w.keyIds[i] == 2 && w.values[i].length == 32 && bytes32(w.values[i]) == bytes32(0)) {
                w.values[i] = abi.encodePacked(root);
            }
        }
        bytes[] memory inclusion = new bytes[](10);
        inclusion[0] = RLP.encode(uint256(w.blockNumber));
        inclusion[1] = RLP.encode(uint256(w.slot));
        inclusion[2] = RLP.encode(uint256(0));
        inclusion[3] = RLP.encode(uint256(3));
        inclusion[4] = _bytesList(_one(w.sibLeaf));
        inclusion[5] = RLP.encode(uint256(w.rangeStart));
        inclusion[6] = RLP.encode(uint256(w.rangeStart + 15));
        inclusion[7] = RLP.encode(uint256(0));
        inclusion[8] = RLP.encode(uint256(3));
        inclusion[9] = _bytesList(_one(abi.encodePacked(w.otherOuter)));

        bytes[] memory body = new bytes[](5);
        body[0] = RLP.encode(w.bodies.length > 0 ? w.bodies : abi.encodePacked(w.bodiesHash));
        body[1] = RLP.encode(keccak256("wits"));
        body[2] = RLP.encode(keccak256("aux"));
        body[3] = RLP.encode(w.invalidTxs);
        body[4] = RLP.encode(w.txIndex);

        bytes[] memory p = new bytes[](w.withManifest ? 9 : 8);
        p[0] = _rawList(w.rotations);
        p[1] = _cert(w.net, w.signs, w.keyIds, w.values);
        p[2] = RLP.encode(inclusion);
        p[3] = RLP.encode(w.header);
        p[4] = RLP.encode(body);
        p[5] = RLP.encode(w.txBody);
        p[6] = RLP.encode(w.outputIndex);
        p[7] = RLP.encode(w.content);
        if (w.withManifest) p[8] = RLP.encode(w.manifest);
        return RLP.encode(p);
    }

    /// @dev A rotation certificate of `net`'s epoch that hands over to `next` (no block data needed).
    function _rotation(Network memory net, Network memory next) internal view returns (bytes memory) {
        (uint256[] memory ids, bytes[] memory vals) = _parts(net.epoch, keccak256("any-root"), next);
        bool[] memory signs = new bool[](net.sks.length);
        for (uint256 i = 0; i < signs.length; i++) {
            signs[i] = true;
        }
        return _cert(net, signs, ids, vals);
    }

    // ── CLPR fixtures ─────────────────────────────────────────────────────

    function manifest(bytes memory serviceAddress, uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](0);
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SCRIPT);
        lc.nanosSinceEpoch = 1_760_000_000 * 1e9;
        lc.throttles.maxMessagesPerBundle = 100;
        lc.throttles.maxMessagePayloadBytes = 10_000;
        lc.throttles.maxSyncBytes = 1_000_000;
        lc.throttles.maxQueueDepth = 1000;
        lc.throttles.maxGasPerMessage = 1_000_000;
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(Network memory net, string memory chainId) internal view returns (bytes memory) {
        (uint256[] memory ids, bytes[] memory vals) = _parts(net.epoch, keccak256("cfg-root"), net);
        bool[] memory signs = new bool[](net.sks.length);
        for (uint256 i = 0; i < signs.length; i++) {
            signs[i] = true;
        }
        bytes[] memory c = new bytes[](11);
        c[0] = RLP.encode(uint256(net.epoch));
        c[1] = RLP.encode(net.root);
        c[2] = RLP.encode(net.leaves.length);
        c[3] = RLP.encode(uint256(net.total));
        c[4] = RLP.encode(uint256(net.k));
        c[5] = RLP.encode(uint256(net.m));
        c[6] = RLP.encode(uint256(PHI));
        c[7] = RLP.encode(uint256(LN_MANT));
        c[8] = RLP.encode(uint256(LN_EXP));
        c[9] = _cert(net, signs, ids, vals);
        c[10] = RLP.encode(ledgerConfig(chainId));
        return RLP.encode(c);
    }

    function ctx() internal pure returns (bytes memory) {
        return abi.encodePacked(CHANNEL_ID, SCRIPT);
    }

    // ── RLP helpers ───────────────────────────────────────────────────────

    function _one(bytes memory a) internal pure returns (bytes[] memory l) {
        l = new bytes[](1);
        l[0] = a;
    }

    function _bytesList(bytes[] memory xs) internal pure returns (bytes memory) {
        bytes[] memory e = new bytes[](xs.length);
        for (uint256 i = 0; i < xs.length; i++) {
            e[i] = RLP.encode(xs[i]);
        }
        return RLP.encode(e);
    }

    function _uintList(uint256[] memory xs) internal pure returns (bytes memory) {
        bytes[] memory e = new bytes[](xs.length);
        for (uint256 i = 0; i < xs.length; i++) {
            e[i] = RLP.encode(xs[i]);
        }
        return RLP.encode(e);
    }

    function _rawList(bytes[] memory encoded) internal pure returns (bytes memory) {
        return RLP.encode(encoded);
    }
}
