// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprTempoCertificate} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoCertificate.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Builders for Tempo verifier tests: a BLS test signer made with the EIP-2537 MSM precompiles,
///      Tempo header and proof encoders, and a loader for the mainnet fixtures.
abstract contract TempoSyntheticProofs is QbftSyntheticProofs {
    /// @dev BLS12-381 subgroup order r.
    uint256 internal constant BLS_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @dev G2 generator, EIP-2537 encoding.
    bytes internal constant G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    string internal constant TEMPO_FIXTURE_DIR = "test/verifiers/tempo/fixtures/";

    struct TempoFixture {
        uint64 blockNumber;
        uint64 epoch;
        bytes32 digest;
        bytes headerRlp;
        bytes proposal;
        bytes sigCompressed;
        bytes sigUncompressed;
        bytes keyCompressed;
        bytes keyUncompressed;
    }

    struct CertificateBytes {
        bytes proposal;
        bytes sigCompressed;
        bytes sigUncompressed;
    }

    // ── BLS test signer ─────────────────────────────────────────────────────

    function _testKey(string memory seed) internal pure returns (uint256 sk) {
        sk = uint256(keccak256(bytes(seed))) % BLS_R;
        if (sk == 0) sk = 1;
    }

    /// @dev pk = sk * G2.
    function _blsPublicKey(uint256 sk) internal view returns (bytes memory pk) {
        (bool ok, bytes memory out) = ClprBls12381.BLS12_G2MSM.staticcall(abi.encodePacked(G2_GENERATOR, bytes32(sk)));
        require(ok && out.length == 256, "G2MSM failed");
        return out;
    }

    /// @dev sig = sk * H(m).
    function _blsSign(uint256 sk, bytes memory message) internal view returns (bytes memory sig) {
        bytes memory h = ClprBls12381.hashToG1(message, ClprTempoBls.DST);
        (bool ok, bytes memory out) = ClprBls12381.BLS12_G1MSM.staticcall(abi.encodePacked(h, bytes32(sk)));
        require(ok && out.length == 128, "G1MSM failed");
        return out;
    }

    // ── Encoders ────────────────────────────────────────────────────────────

    function _varint(uint64 v) internal pure returns (bytes memory out) {
        while (v >= 0x80) {
            // masked to 7 bits
            // forge-lint: disable-next-line(unsafe-typecast)
            out = abi.encodePacked(out, bytes1(uint8(v & 0x7f) | 0x80));
            v >>= 7;
        }
        // v is below 0x80
        // forge-lint: disable-next-line(unsafe-typecast)
        out = abi.encodePacked(out, bytes1(uint8(v)));
    }

    function _proposalBytes(uint64 epoch, uint64 viewNumber, uint64 parentView, bytes32 payload)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory out = _varint(epoch);
        out = abi.encodePacked(out, _varint(viewNumber));
        out = abi.encodePacked(out, _varint(parentView));
        return abi.encodePacked(out, payload);
    }

    /// @dev A Tempo header with a 15-field inner Ethereum header.
    function _tempoHeader(uint256 number, bytes32 stateRoot, bytes memory extraData, bool withContext)
        internal
        pure
        returns (bytes memory)
    {
        return _tempoHeaderWithInner(_innerHeader(number, stateRoot, extraData), withContext);
    }

    function _tempoHeaderWithInner(bytes[] memory inner, bool withContext) internal pure returns (bytes memory) {
        bytes[] memory outer = new bytes[](withContext ? 5 : 4);
        outer[0] = RLP.encode(uint256(30_000_000)); // generalGasLimit
        outer[1] = RLP.encode(uint256(10_000_000)); // sharedGasLimit
        outer[2] = RLP.encode(uint256(250)); // timestampMillisPart
        outer[3] = RLP.encode(inner);
        if (withContext) {
            bytes[] memory ctx = new bytes[](4);
            ctx[0] = RLP.encode(uint256(1)); // epoch
            ctx[1] = RLP.encode(uint256(2)); // view
            ctx[2] = RLP.encode(uint256(1)); // parentView
            ctx[3] = RLP.encode(abi.encodePacked(bytes32(uint256(0xA11CE)))); // proposer
            outer[4] = RLP.encode(ctx);
        }
        return RLP.encode(outer);
    }

    function _innerHeader(uint256 number, bytes32 stateRoot, bytes memory extraData)
        internal
        pure
        returns (bytes[] memory inner)
    {
        inner = new bytes[](15);
        inner[0] = RLP.encode(bytes32(0)); // parentHash
        inner[1] = RLP.encode(bytes32(0)); // ommersHash
        inner[2] = RLP.encode(address(0)); // beneficiary
        inner[3] = RLP.encode(stateRoot);
        inner[4] = RLP.encode(bytes32(0)); // transactionsRoot
        inner[5] = RLP.encode(bytes32(0)); // receiptsRoot
        inner[6] = RLP.encode(new bytes(256)); // logsBloom
        inner[7] = RLP.encode(uint256(0)); // difficulty
        inner[8] = RLP.encode(number);
        inner[9] = RLP.encode(uint256(30_000_000)); // gasLimit
        inner[10] = RLP.encode(uint256(21_000)); // gasUsed
        inner[11] = RLP.encode(uint256(1_700_000_000)); // timestamp
        inner[12] = RLP.encode(extraData);
        inner[13] = RLP.encode(bytes32(0)); // mixHash
        inner[14] = RLP.encode(new bytes(8)); // nonce
    }

    /// @dev Certify `header` at `number` under `sk`.
    function _certify(uint256 sk, uint64 epochLength, bytes memory header, uint64 number, uint64 viewNumber)
        internal
        view
        returns (CertificateBytes memory c)
    {
        bytes32 payload = keccak256(header);
        uint64 epoch = number / epochLength;
        uint64 parentView = viewNumber - 1;
        c.proposal = _proposalBytes(epoch, viewNumber, parentView, payload);
        bytes memory message = ClprTempoCertificate.finalizeMessage(c.proposal);
        c.sigUncompressed = _blsSign(sk, message);
        c.sigCompressed = ClprBls12381.compressG1(c.sigUncompressed);
    }

    /// @dev Bundle field 1: RLP([proposal, sigCompressed, sigUncompressed, rotations[]]).
    function _sourceField(CertificateBytes memory c, bytes[] memory rotations) internal pure returns (bytes memory) {
        bytes[] memory source = new bytes[](4);
        source[0] = RLP.encode(c.proposal);
        source[1] = RLP.encode(c.sigCompressed);
        source[2] = RLP.encode(c.sigUncompressed);
        source[3] = RLP.encode(rotations);
        return RLP.encode(source);
    }

    /// @dev A rotation: RLP([boundaryHeader, proposal, sigCompressed, sigUncompressed, newKeyUncompressed]).
    function _encodeRotation(bytes memory header, CertificateBytes memory c, bytes memory newKey)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory rotation = new bytes[](5);
        rotation[0] = header;
        rotation[1] = RLP.encode(c.proposal);
        rotation[2] = RLP.encode(c.sigCompressed);
        rotation[3] = RLP.encode(c.sigUncompressed);
        rotation[4] = RLP.encode(newKey);
        return RLP.encode(rotation);
    }

    /// @dev Parts of a bundle proof. The manifest fields are used only when `manifestProof` is set.
    struct BundleParts {
        bytes header;
        CertificateBytes cert;
        bytes[] rotations;
        bytes accountProof;
        bytes storageProof;
        bytes content;
        bytes manifestProof;
        bytes manifestPreimage;
    }

    function _encodeBundle(BundleParts memory b) internal pure returns (bytes memory) {
        bool withManifest = b.manifestProof.length > 0;
        bytes[] memory top = new bytes[](withManifest ? 7 : 5);
        top[0] = b.header;
        top[1] = _sourceField(b.cert, b.rotations);
        top[2] = b.accountProof;
        top[3] = b.storageProof;
        top[4] = RLP.encode(b.content);
        if (withManifest) {
            top[5] = b.manifestProof;
            top[6] = RLP.encode(b.manifestPreimage);
        }
        return RLP.encode(top);
    }

    /// @dev Config-time manifest proof, 7 items.
    function _configManifestProofItem(
        bytes memory header,
        CertificateBytes memory c,
        bytes memory accountProof,
        bytes memory manifestStorageProof,
        bytes memory carried
    ) internal pure returns (bytes memory) {
        bytes[] memory p = new bytes[](7);
        p[0] = header;
        p[1] = RLP.encode(c.proposal);
        p[2] = RLP.encode(c.sigCompressed);
        p[3] = RLP.encode(c.sigUncompressed);
        p[4] = accountProof;
        p[5] = manifestStorageProof;
        p[6] = RLP.encode(carried);
        return RLP.encode(p);
    }

    /// @dev RLP([proposal, sigCompressed, sigUncompressed]).
    function _certificateItem(CertificateBytes memory c) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(c.proposal);
        items[1] = RLP.encode(c.sigCompressed);
        items[2] = RLP.encode(c.sigUncompressed);
        return RLP.encode(items);
    }

    /// @dev A minimal DKG outcome with one coefficient: the compressed key.
    function _dkgOutcome(uint64 epoch, bytes memory keyCompressed) internal pure returns (bytes memory) {
        bytes memory out = _varint(epoch);
        out = abi.encodePacked(out, bytes32(0), bytes1(0), bytes4(uint32(3)));
        out = abi.encodePacked(out, _varint(1));
        return abi.encodePacked(out, keyCompressed);
    }

    function _tempoAnchor(bytes32 codeHash, uint64 epochLength, uint64 anchorBlock, bytes memory key)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(codeHash, epochLength, anchorBlock, key);
    }

    function _tempoChannelContext(bytes32 channelId, address service) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(service)})
        );
    }

    /// @dev Parts of a config proof.
    struct ConfigParts {
        address service;
        string chainId;
        bytes32 codeHash;
        uint64 epochLength;
        bytes keyCompressed;
        bytes keyUncompressed;
        bytes header;
        CertificateBytes cert;
        bytes[] throttles;
    }

    /// @dev Five zero throttles.
    function _defaultThrottles() internal pure returns (bytes[] memory throttles) {
        throttles = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttles[i] = RLP.encode(uint256(0));
        }
    }

    function _encodeConfigProof(ConfigParts memory c) internal pure returns (bytes memory) {
        bytes[] memory d = new bytes[](4);
        d[0] = RLP.encode(c.codeHash);
        d[1] = RLP.encode(uint256(c.epochLength));
        d[2] = RLP.encode(c.keyCompressed);
        d[3] = RLP.encode(c.keyUncompressed);

        bytes[] memory proof = new bytes[](7);
        proof[0] = RLP.encode(abi.encodePacked(c.service));
        proof[1] = RLP.encode(bytes(c.chainId));
        proof[2] = RLP.encode(uint256(0));
        proof[3] = RLP.encode(c.throttles);
        proof[4] = RLP.encode(RLP.encode(d));
        proof[5] = _certificateItem(c.cert);
        proof[6] = c.header;
        return RLP.encode(proof);
    }

    /// @dev Inner header field `index` of a Tempo header.
    function _innerField(bytes memory tempoHeader, uint256 index) internal pure returns (bytes memory) {
        Memory.Slice[] memory outer = RLP.decodeList(tempoHeader);
        Memory.Slice[] memory inner = RLP.readList(outer[3]);
        return RLP.readBytes(inner[index]);
    }

    // ── Fixtures ────────────────────────────────────────────────────────────

    function _loadTempoFixture(string memory name) internal view returns (TempoFixture memory f) {
        string memory json = vm.readFile(string.concat(TEMPO_FIXTURE_DIR, name, ".json"));
        f.blockNumber = uint64(vm.parseJsonUint(json, ".blockNumber"));
        f.epoch = uint64(vm.parseJsonUint(json, ".epoch"));
        f.digest = vm.parseJsonBytes32(json, ".digest");
        f.headerRlp = vm.parseJsonBytes(json, ".headerRlp");
        f.proposal = vm.parseJsonBytes(json, ".proposal");
        f.sigCompressed = vm.parseJsonBytes(json, ".sigCompressed");
        f.sigUncompressed = vm.parseJsonBytes(json, ".sigUncompressed");
        f.keyCompressed = vm.parseJsonBytes(json, ".keyCompressed");
        f.keyUncompressed = vm.parseJsonBytes(json, ".keyUncompressed");
    }

    /// @dev The key that a boundary fixture announces for the next epoch, compressed.
    function _loadTempoNextKey(string memory name) internal view returns (bytes memory) {
        string memory json = vm.readFile(string.concat(TEMPO_FIXTURE_DIR, name, ".json"));
        return vm.parseJsonBytes(json, ".nextKeyCompressed");
    }
}
