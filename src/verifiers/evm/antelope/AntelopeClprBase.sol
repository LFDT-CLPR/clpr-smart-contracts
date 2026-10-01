// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";

/// @title AntelopeClprBase
/// @notice The CLPR half shared by the Antelope verifiers: what a proven action receipt means.
/// @dev Antelope blocks commit to action receipts, not to contract tables, so CLPR state is proven
///      as the RETURN VALUE of an action of the CLPR Service contract. Since ACTION_RETURN_VALUE
///      (active on Vaulta, Telos, XPR), `act_digest` commits to the action's return value, and every
///      validating node re-executes the action, so a receipt in a final block proves that the
///      contract code returned exactly those bytes at that point of the chain.
///
///      The CLPR Service on Antelope is an account `S`; its service address is the 8-byte packed
///      name (uint64 little-endian, Antelope's own encoding). It exposes three read actions that
///      anyone may push (each in a normal transaction, so its receipt lands in a block):
///
///        queuestate(checksum256 channel_id) -> clpr_queue_state (153 bytes, packed):
///            channel_id checksum256 | status uint8 | next_message_id uint64 |
///            sent_running_hash checksum256 | received_message_id uint64 |
///            received_running_hash checksum256 | endpoint_manifest_version uint64 |
///            manifest_commitment checksum256  (= keccak256 of the protobuf manifest, as ManifestLib)
///        ledgerconfig() -> ClprControlMessage protobuf (the LedgerConfiguration)
///        manifest()     -> ClprEndpointManifest protobuf
///
///      A receipt counts only if receiver == act.account == S (not a notification copy) and the
///      action name matches. Failed actions produce no receipts.
abstract contract AntelopeClprBase is ClprEvmBundleVerifier {
    /// @notice keccak256 of the CAIP-2 id this verifier serves ("antelope:" + first 32 hex chars of
    ///         the chain id). Finality proofs carry no chain id, so verifyConfig pins it.
    bytes32 public immutable CHAIN_ID_HASH;

    uint64 internal immutable QUEUE_ACTION = AntelopeLib.nameValue("queuestate");
    uint64 internal immutable CONFIG_ACTION = AntelopeLib.nameValue("ledgerconfig");
    uint64 internal immutable MANIFEST_ACTION = AntelopeLib.nameValue("manifest");

    uint256 internal constant QUEUE_STATE_LENGTH = 153;

    /// @dev A proven action: the fields the CLPR rules look at.
    struct ProvenAction {
        uint64 receiver;
        uint64 account;
        uint64 name;
        bytes data;
        bytes returnValue;
    }

    error WrongChain(string chainId);
    error NotServiceAction(uint64 receiver, uint64 account);
    error WrongAction(uint64 name);
    error WrongActionData();
    error QueueStateMalformed();
    error QueueChannelMismatch();
    error InvalidChannelStatus(uint8 status);
    error ActionBaseMalformed();
    error InvalidPayloadShape();

    constructor(string memory chainId) {
        if (bytes(chainId).length == 0) revert WrongChain(chainId);
        CHAIN_ID_HASH = keccak256(bytes(chainId));
    }

    /// @dev Service account from an 8-byte service address (packed eosio::name, little-endian).
    function _serviceAccount(bytes memory serviceAddress) internal pure returns (uint64) {
        if (serviceAddress.length != 8) revert InvalidServiceAddressLength();
        return AntelopeLib.readU64(serviceAddress, 0);
    }

    /// @dev Build a ProvenAction from the packed action_base (account, name, authorization), the
    ///      action data and the return value. Returns it with the act_digest.
    function _action(uint64 receiver, bytes memory actionBase, bytes memory data, bytes memory returnValue)
        internal
        pure
        returns (ProvenAction memory a, bytes32 actDigest)
    {
        if (actionBase.length < 17) revert ActionBaseMalformed();
        a.receiver = receiver;
        a.account = AntelopeLib.readU64(actionBase, 0);
        a.name = AntelopeLib.readU64(actionBase, 8);
        a.data = data;
        a.returnValue = returnValue;
        actDigest = AntelopeLib.actionDigest(actionBase, data, returnValue);
    }

    function _requireServiceAction(ProvenAction memory a, uint64 service, uint64 actionName) internal pure {
        if (a.receiver != service || a.account != service) revert NotServiceAction(a.receiver, a.account);
        if (a.name != actionName) revert WrongAction(a.name);
    }

    /// @dev Decode `queuestate` for `ctx`. Returns the queue metadata and the manifest commitment.
    function _queueState(ProvenAction memory a, ClprTypes.ChannelContext memory ctx)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes32 manifestCommitment)
    {
        _requireServiceAction(a, _serviceAccount(ctx.remoteServiceAddress), QUEUE_ACTION);
        if (a.data.length != 32 || bytes32(a.data) != ctx.channelId) revert WrongActionData();
        bytes memory r = a.returnValue;
        if (r.length != QUEUE_STATE_LENGTH) revert QueueStateMalformed();
        if (AntelopeLib.readBytes32(r, 0) != ctx.channelId) revert QueueChannelMismatch();
        uint8 status = AntelopeLib.readU8(r, 32);
        if (status > uint8(type(ClprTypes.ChannelStatus).max)) revert InvalidChannelStatus(status);
        m.state = ClprTypes.ChannelStatus(status);
        m.nextMessageId = AntelopeLib.readU64(r, 33);
        m.sentRunningHash = AntelopeLib.readBytes32(r, 41);
        m.receivedMessageId = AntelopeLib.readU64(r, 73);
        m.receivedRunningHash = AntelopeLib.readBytes32(r, 81);
        m.endpointManifestVersion = AntelopeLib.readU64(r, 113);
        manifestCommitment = AntelopeLib.readBytes32(r, 121);
    }

    /// @dev Decode `ledgerconfig` (receipt of the configured service) and pin the chain id.
    function _ledgerConfig(ProvenAction memory a) internal view returns (ClprTypes.LedgerConfiguration memory lc) {
        lc = ClprProtobuf.decodeControlMessage(a.returnValue).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChain(lc.chainId);
        _requireServiceAction(a, _serviceAccount(lc.serviceAddress), CONFIG_ACTION);
        if (a.data.length != 0) revert WrongActionData();
    }

    /// @dev Decode a config-time `manifest` receipt of `serviceAddress`.
    function _manifestAction(ProvenAction memory a, bytes memory serviceAddress)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        _requireServiceAction(a, _serviceAccount(serviceAddress), MANIFEST_ACTION);
        if (a.data.length != 0) revert WrongActionData();
        m = _checkManifest(a.returnValue, serviceAddress);
    }

    /// @dev Bind a bundle's manifest preimage to the commitment the queue state returned.
    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        return _checkManifest(preimage, serviceAddress);
    }

    function _checkManifest(bytes memory preimage, bytes memory serviceAddress)
        private
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m = ClprProtobuf.decodeEndpointManifest(preimage);
        if (m.version == 0) revert ManifestVersionZero();
        if (keccak256(m.serviceAddress) != keccak256(serviceAddress)) revert ManifestServiceAddressMismatch();
    }

    // ── RLP helpers ───────────────────────────────────────────────────────────

    function _u32(Memory.Slice s) internal pure returns (uint32) {
        uint256 v = RLP.readUint256(s);
        if (v > type(uint32).max) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(v);
    }

    function _u64(Memory.Slice s) internal pure returns (uint64) {
        uint256 v = RLP.readUint256(s);
        if (v > type(uint64).max) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v);
    }

    function _b32(Memory.Slice s) internal pure returns (bytes32) {
        bytes memory b = RLP.readBytes(s);
        if (b.length != 32) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes32(b);
    }

    function _b32s(Memory.Slice s) internal pure returns (bytes32[] memory out) {
        Memory.Slice[] memory l = RLP.readList(s);
        out = new bytes32[](l.length);
        for (uint256 i = 0; i < l.length; ++i) {
            out[i] = _b32(l[i]);
        }
    }
}
