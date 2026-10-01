// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title OpStackOutputRootProof
/// @notice Proves, from an authenticated Ethereum L1 `state_root`, that an OP Stack L2 output root is
///         accepted by the chain's L1 fault-proof contracts — `AnchorStateRegistry` (ASR) and
///         `DisputeGameFactory` (DGF) — using only MPT account/storage proofs of L1 state:
///
///         ANCHOR mode   the output root is the ASR anchor root (`anchorGame`'s root claim, or the
///                       starting anchor root while no anchor game is set).
///         GAME mode     the output root is the root claim of a DGF-registered dispute game of the
///                       respected game type that is not blacklisted, not retired, was respected when
///                       created and delegates to the pinned game implementation; FINALIZED additionally
///                       requires `DEFENDER_WINS` and `l1Time − resolvedAt > disputeGameFinalityDelay`
///                       (exactly `AnchorStateRegistry.isGameClaimValid`), PROPOSED only requires the
///                       game not to have been lost by its proposer (`status != CHALLENGER_WINS`).
///
///         The output root preimage (version 0 ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash) is
///         checked by {outputRoot}, which the caller hashes and then uses the stateRoot of. On chains
///         whose games claim interop SUPER roots (`RootFormat.SUPER_ROOT_V1`, e.g. OP Mainnet's
///         SuperFaultDisputeGame), the dispute proof also carries the super-root preimage, and the
///         output root must be its entry for the profile's `l2ChainId`.
///
/// @dev Every storage slot and packed-field offset comes from a {Layout} value (data), so that a
///      contracts upgrade that moves a field is a new profile, not new code (clpr-spec ADR 2026-10-01
///      "Fork-Aware Verifiers", Class B). Slots are always derived here, never read from the proof.
/// @dev Facts that live in immutables are bound by code hash: the ASR implementation's code hash pins
///      `DISPUTE_GAME_FINALITY_DELAY_SECONDS` (and the ASR semantics), and the game clone's code must
///      delegate to the pinned game implementation (which pins the game's own ASR/DGF immutables).
library OpStackOutputRootProof {
    // ── Dispute proof RLP layout ─────────────────────────────────────────────
    uint256 internal constant DISPUTE_FIELDS = 12;
    uint256 internal constant DP_IDX_MODE = 0;
    uint256 internal constant DP_IDX_GAME_TYPE = 1;
    uint256 internal constant DP_IDX_EXTRA_DATA = 2;
    uint256 internal constant DP_IDX_ASR_ACCOUNT = 3;
    uint256 internal constant DP_IDX_ASR_STORAGE = 4;
    uint256 internal constant DP_IDX_ASR_IMPL_ACCOUNT = 5;
    uint256 internal constant DP_IDX_DGF_ACCOUNT = 6;
    uint256 internal constant DP_IDX_DGF_STORAGE = 7;
    uint256 internal constant DP_IDX_GAME_ACCOUNT = 8;
    uint256 internal constant DP_IDX_GAME_CODE = 9;
    uint256 internal constant DP_IDX_GAME_STORAGE = 10;
    uint256 internal constant DP_IDX_SUPER_ROOT_PREIMAGE = 11;

    uint256 internal constant MODE_ANCHOR = 0;
    uint256 internal constant MODE_GAME = 1;

    /// @dev `GameStatus` enum of the OP Stack dispute games.
    uint8 internal constant STATUS_IN_PROGRESS = 0;
    uint8 internal constant STATUS_CHALLENGER_WINS = 1;
    uint8 internal constant STATUS_DEFENDER_WINS = 2;

    /// @dev EIP-1967 implementation slot (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`).
    bytes32 internal constant EIP1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Output root preimage: `version(32) ‖ stateRoot(32) ‖ messagePasserStorageRoot(32) ‖ blockHash(32)`.
    uint256 internal constant OUTPUT_ROOT_PREIMAGE_LENGTH = 128;

    /// @dev Super root (interop) preimage, version 1: `0x01 ‖ timestamp(8) ‖ (chainId(32) ‖ outputRoot(32))*`.
    uint8 internal constant SUPER_ROOT_VERSION = 1;
    uint256 internal constant SUPER_ROOT_HEADER_LENGTH = 9;
    uint256 internal constant SUPER_ROOT_ENTRY_LENGTH = 64;

    // ── DisputeGameFactory clone format (Solady LibClone CWIA, DGF ≥ 1.0) ────
    // runtime = PREFIX(54) ‖ uint16(argsLength) ‖ MID(9) ‖ implementation(20) ‖ SUFFIX(13) ‖ args
    // where args = CWIA immutable args + a trailing 2-byte length, and argsLength = code.length − 98.
    bytes internal constant CLONE_PREFIX =
        hex"36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b363d3d373d3d3d3d61";
    bytes internal constant CLONE_MID = hex"806062363936013d73";
    bytes internal constant CLONE_SUFFIX = hex"5af43d3d93803e606057fd5bf3";
    uint256 internal constant CLONE_HEADER_LENGTH = 98;

    /// @notice Where the facts live in L1 storage. Values for the OP Stack contracts in use on the
    ///         Superchain today (ASR 3.x, DGF 1.x, FaultDisputeGame / Base AggregateVerifier) are
    ///         listed in the verifier README.
    struct Layout {
        uint256 asrDisputeGameFactorySlot; // ASR.disputeGameFactory
        uint256 asrAnchorGameSlot; // ASR.anchorGame
        uint256 asrStartingAnchorRootSlot; // ASR.startingAnchorRoot.root (l2SequenceNumber at +1)
        uint256 asrBlacklistSlot; // ASR.disputeGameBlacklist (mapping base)
        uint256 asrRespectedGameTypeSlot; // ASR.respectedGameType | retirementTimestamp
        uint256 asrRespectedGameTypeOffset; // byte offset of respectedGameType (uint32)
        uint256 asrRetirementTimestampOffset; // byte offset of retirementTimestamp (uint64)
        uint256 dgfGamesSlot; // DGF._disputeGames (mapping base)
        uint256 gameStateSlot; // game slot holding createdAt | resolvedAt | status | … | wasRespected…
        uint256 gameCreatedAtOffset; // uint64
        uint256 gameResolvedAtOffset; // uint64
        uint256 gameStatusOffset; // uint8
        uint256 gameWasRespectedSlot; // game slot holding wasRespectedGameTypeWhenCreated
        uint256 gameWasRespectedOffset; // bool
    }

    /// @notice What a dispute game's root claim commits to.
    enum RootFormat {
        /// The chain's own L2 output root (FaultDisputeGame, Base AggregateVerifier, …).
        OUTPUT_ROOT,
        /// An interop super root over the dependency set's output roots (SuperFaultDisputeGame, …);
        /// the chain's output root is the entry for `l2ChainId`.
        SUPER_ROOT_V1
    }

    /// @notice The chain being verified: its L1 contracts, the pinned code, and the storage layout.
    struct Profile {
        RootFormat rootFormat;
        uint256 l2ChainId;
        address anchorStateRegistry;
        bytes32 anchorStateRegistryImplCodeHash;
        uint256 disputeGameFinalityDelaySeconds;
        address gameImplementation;
        Layout layout;
    }

    /// @dev What the ASR storage says (read once, shared by both modes).
    struct Registry {
        bytes32 storageRoot;
        address disputeGameFactory;
        uint32 respectedGameType;
        uint64 retirementTimestamp;
    }

    error InvalidDisputeProof();
    error InvalidOutputRootPreimage();
    error InvalidSuperRootPreimage();
    error OutputRootNotInSuperRoot(uint256 l2ChainId, bytes32 outputRoot);
    error UnsupportedOutputRootVersion(bytes32 version);
    error UnknownProofMode(uint256 mode);
    error AnchorStateRegistryImplMismatch(address implementation, bytes32 codeHash);
    error OutputRootNotAnchor(bytes32 outputRoot);
    error GameNotRegistered(bytes32 uuid);
    error GameTypeNotRespected(uint32 gameType, uint32 respectedGameType);
    error GameBlacklisted(address game);
    error GameRetired(address game, uint64 createdAt, uint64 retirementTimestamp);
    error GameNotRespectedWhenCreated(address game);
    error GameCodeMismatch(address game);
    error GameImplementationMismatch(address game);
    error GameChallengerWins(address game);
    error GameNotResolved(address game, uint8 status);
    error GameNotFinalized(address game, uint64 resolvedAt, uint64 l1Time, uint256 finalityDelaySeconds);

    // ─────────────────────────────────────────────────────────────────────────
    //   Output root
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice `keccak256(version ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash)` for a version-0
    ///         output root, returning the L2 state root the later account proof is walked against.
    function outputRoot(bytes memory preimage) internal pure returns (bytes32 root, bytes32 l2StateRoot) {
        if (preimage.length != OUTPUT_ROOT_PREIMAGE_LENGTH) revert InvalidOutputRootPreimage();
        bytes32 version;
        assembly ("memory-safe") {
            version := mload(add(preimage, 0x20))
            l2StateRoot := mload(add(preimage, 0x40))
        }
        if (version != bytes32(0)) revert UnsupportedOutputRootVersion(version);
        root = keccak256(preimage);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Dispute proof
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Prove that the chain's output root `outputRoot_` is accepted by its L1 fault-proof
    ///         contracts in the L1 state `l1StateRoot` (whose wall-clock time is `l1Time`).
    /// @param disputeProofItem RLP `[mode, gameType, extraData, asrAccountProof, asrStorageProof,
    ///        asrImplAccountProof, dgfAccountProof, dgfStorageProof, gameAccountProof, gameCode,
    ///        gameStorageProof, superRootPreimage]` — items unused by a mode/format are empty.
    /// @param acceptProposed PROPOSED tier: accept a registered game that has not (yet) been lost by its
    ///        proposer, without waiting for resolution or the finality delay. Trusts the proposer.
    function verify(
        Profile memory p,
        Memory.Slice disputeProofItem,
        bytes32 l1StateRoot,
        uint64 l1Time,
        bytes32 outputRoot_,
        bool acceptProposed
    ) internal pure {
        Memory.Slice[] memory dp = RLP.readList(disputeProofItem);
        if (dp.length != DISPUTE_FIELDS) revert InvalidDisputeProof();
        bytes32 root = _claimedRoot(p, RLP.readBytes(dp[DP_IDX_SUPER_ROOT_PREIMAGE]), outputRoot_);

        Registry memory reg = _readRegistry(p, dp, l1StateRoot);
        uint256 mode = RLP.readUint256(dp[DP_IDX_MODE]);
        if (mode == MODE_ANCHOR) {
            _verifyAnchor(p, dp, reg, l1StateRoot, root);
        } else if (mode == MODE_GAME) {
            _verifyGame(p, dp, reg, l1StateRoot, l1Time, root, acceptProposed);
        } else {
            revert UnknownProofMode(mode);
        }
    }

    /// @dev ASR account → {disputeGameFactory, respectedGameType, retirementTimestamp, implementation},
    ///      then the implementation's code hash must be the pinned one.
    function _readRegistry(Profile memory p, Memory.Slice[] memory dp, bytes32 l1StateRoot)
        private
        pure
        returns (Registry memory reg)
    {
        (reg.storageRoot,) = _account(dp[DP_IDX_ASR_ACCOUNT], l1StateRoot, p.anchorStateRegistry);
        bytes32[] memory slots = new bytes32[](3);
        slots[0] = bytes32(p.layout.asrDisputeGameFactorySlot);
        slots[1] = bytes32(p.layout.asrRespectedGameTypeSlot);
        slots[2] = EIP1967_IMPLEMENTATION_SLOT;
        bytes32[] memory v = _slots(dp[DP_IDX_ASR_STORAGE], reg.storageRoot, slots);
        reg.disputeGameFactory = address(uint160(uint256(v[0])));
        // forge-lint: disable-next-line(unsafe-typecast)
        reg.respectedGameType = uint32(_field(v[1], p.layout.asrRespectedGameTypeOffset));
        // forge-lint: disable-next-line(unsafe-typecast)
        reg.retirementTimestamp = uint64(_field(v[1], p.layout.asrRetirementTimestampOffset));

        address impl = address(uint160(uint256(v[2])));
        (, bytes32 implCodeHash) = _account(dp[DP_IDX_ASR_IMPL_ACCOUNT], l1StateRoot, impl);
        if (implCodeHash != p.anchorStateRegistryImplCodeHash) {
            revert AnchorStateRegistryImplMismatch(impl, implCodeHash);
        }
    }

    /// @dev ANCHOR mode: `root` is `ASR.getAnchorRoot()`. With an anchor game set, the root must be that
    ///      game's root claim — shown by the DGF registration `(respectedGameType, root, extraData) →
    ///      anchorGame` — and the game must not be blacklisted (stricter than the ASR, which does not
    ///      re-check its anchor). Without one, it must be the stored starting anchor root.
    function _verifyAnchor(
        Profile memory p,
        Memory.Slice[] memory dp,
        Registry memory reg,
        bytes32 l1StateRoot,
        bytes32 root
    ) private pure {
        address anchorGame = address(
            uint160(uint256(_slot(dp[DP_IDX_ASR_STORAGE], reg.storageRoot, p.layout.asrAnchorGameSlot)))
        );
        if (anchorGame == address(0)) {
            if (_slot(dp[DP_IDX_ASR_STORAGE], reg.storageRoot, p.layout.asrStartingAnchorRootSlot) != root) {
                revert OutputRootNotAnchor(root);
            }
            return;
        }
        (address game,) = _registeredGame(dp, reg, l1StateRoot, p.layout.dgfGamesSlot, root);
        if (game != anchorGame) revert OutputRootNotAnchor(root);
        _requireNotBlacklisted(p, dp, reg, game);
    }

    /// @dev GAME mode: `AnchorStateRegistry.isGameClaimValid` (FINALIZED) or its proposer-trusting
    ///      relaxation (PROPOSED), evaluated at the proven L1 state and time.
    function _verifyGame(
        Profile memory p,
        Memory.Slice[] memory dp,
        Registry memory reg,
        bytes32 l1StateRoot,
        uint64 l1Time,
        bytes32 root,
        bool acceptProposed
    ) private pure {
        (address game,) = _registeredGame(dp, reg, l1StateRoot, p.layout.dgfGamesSlot, root);
        _requireNotBlacklisted(p, dp, reg, game);

        // The clone must delegate to the pinned implementation: that fixes the game's semantics, its
        // storage layout and its ASR/DGF immutables (ASR.isGameRegistered's `anchorStateRegistry()` check).
        (bytes32 gameStorageRoot, bytes32 gameCodeHash) = _account(dp[DP_IDX_GAME_ACCOUNT], l1StateRoot, game);
        bytes memory code = RLP.readBytes(dp[DP_IDX_GAME_CODE]);
        if (keccak256(code) != gameCodeHash) revert GameCodeMismatch(game);
        _requireCloneOf(code, p.gameImplementation, game);

        bytes32 state = _slot(dp[DP_IDX_GAME_STORAGE], gameStorageRoot, p.layout.gameStateSlot);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 createdAt = uint64(_field(state, p.layout.gameCreatedAtOffset));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 resolvedAt = uint64(_field(state, p.layout.gameResolvedAtOffset));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 status = uint8(_field(state, p.layout.gameStatusOffset));
        bytes32 respectedWord = p.layout.gameWasRespectedSlot == p.layout.gameStateSlot
            ? state
            : _slot(dp[DP_IDX_GAME_STORAGE], gameStorageRoot, p.layout.gameWasRespectedSlot);
        bool wasRespected = uint8(_field(respectedWord, p.layout.gameWasRespectedOffset)) != 0;

        // ASR.isGameProper (registered ✓, not blacklisted ✓, not retired) + isGameRespected.
        if (createdAt <= reg.retirementTimestamp) revert GameRetired(game, createdAt, reg.retirementTimestamp);
        if (!wasRespected) revert GameNotRespectedWhenCreated(game);
        if (status == STATUS_CHALLENGER_WINS) revert GameChallengerWins(game);
        if (acceptProposed) return;

        // ASR.isGameFinalized + DEFENDER_WINS.
        if (status != STATUS_DEFENDER_WINS || resolvedAt == 0) revert GameNotResolved(game, status);
        if (l1Time <= resolvedAt || l1Time - resolvedAt <= p.disputeGameFinalityDelaySeconds) {
            revert GameNotFinalized(game, resolvedAt, l1Time, p.disputeGameFinalityDelaySeconds);
        }
    }

    /// @dev DGF account → `_disputeGames[keccak256(abi.encode(gameType, root, extraData))]`, a packed
    ///      `GameId` (`gameType(32) ‖ timestamp(64) ‖ proxy(160)`). The game type is the respected one.
    function _registeredGame(
        Memory.Slice[] memory dp,
        Registry memory reg,
        bytes32 l1StateRoot,
        uint256 dgfGamesSlot,
        bytes32 root
    ) private pure returns (address game, uint32 gameType) {
        uint256 rawGameType = RLP.readUint256(dp[DP_IDX_GAME_TYPE]);
        if (rawGameType > type(uint32).max) revert InvalidDisputeProof();
        // forge-lint: disable-next-line(unsafe-typecast)
        gameType = uint32(rawGameType);
        if (gameType != reg.respectedGameType) revert GameTypeNotRespected(gameType, reg.respectedGameType);

        bytes32 uuid = keccak256(abi.encode(gameType, root, RLP.readBytes(dp[DP_IDX_EXTRA_DATA])));
        (bytes32 dgfStorageRoot,) = _account(dp[DP_IDX_DGF_ACCOUNT], l1StateRoot, reg.disputeGameFactory);
        uint256 gameId =
            uint256(_slot(dp[DP_IDX_DGF_STORAGE], dgfStorageRoot, uint256(keccak256(abi.encode(uuid, dgfGamesSlot)))));
        if (gameId == 0) revert GameNotRegistered(uuid);
        // GameId packs the proxy address in its low 160 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        game = address(uint160(gameId));
    }

    function _requireNotBlacklisted(Profile memory p, Memory.Slice[] memory dp, Registry memory reg, address game)
        private
        pure
    {
        uint256 slot = uint256(keccak256(abi.encode(game, p.layout.asrBlacklistSlot)));
        if (_slot(dp[DP_IDX_ASR_STORAGE], reg.storageRoot, slot) != bytes32(0)) revert GameBlacklisted(game);
    }

    /// @dev `code[0:98]` must be the DGF clone header delegating to `implementation`, with the encoded
    ///      argument length equal to the actual trailing length.
    function _requireCloneOf(bytes memory code, address implementation, address game) private pure {
        if (code.length < CLONE_HEADER_LENGTH || code.length - CLONE_HEADER_LENGTH > type(uint16).max) {
            revert GameImplementationMismatch(game);
        }
        bytes32 expected = keccak256(
            abi.encodePacked(
                CLONE_PREFIX,
                // forge-lint: disable-next-line(unsafe-typecast)
                uint16(code.length - CLONE_HEADER_LENGTH),
                CLONE_MID,
                implementation,
                CLONE_SUFFIX
            )
        );
        bytes32 actual;
        assembly ("memory-safe") {
            actual := keccak256(add(code, 0x20), CLONE_HEADER_LENGTH)
        }
        if (actual != expected) revert GameImplementationMismatch(game);
    }

    /// @dev The root the dispute games claim: the output root itself, or the super root whose entry for
    ///      `l2ChainId` is the output root.
    function _claimedRoot(Profile memory p, bytes memory superPreimage, bytes32 outputRoot_)
        private
        pure
        returns (bytes32)
    {
        if (p.rootFormat == RootFormat.OUTPUT_ROOT) {
            if (superPreimage.length != 0) revert InvalidSuperRootPreimage();
            return outputRoot_;
        }
        uint256 len = superPreimage.length;
        if (
            len < SUPER_ROOT_HEADER_LENGTH + SUPER_ROOT_ENTRY_LENGTH
                || (len - SUPER_ROOT_HEADER_LENGTH) % SUPER_ROOT_ENTRY_LENGTH != 0
                || uint8(superPreimage[0]) != SUPER_ROOT_VERSION
        ) revert InvalidSuperRootPreimage();
        bool found;
        for (uint256 off = SUPER_ROOT_HEADER_LENGTH; off < len; off += SUPER_ROOT_ENTRY_LENGTH) {
            uint256 chainId;
            bytes32 entryRoot;
            assembly ("memory-safe") {
                let at := add(add(superPreimage, 0x20), off)
                chainId := mload(at)
                entryRoot := mload(add(at, 0x20))
            }
            if (chainId == p.l2ChainId) {
                if (entryRoot != outputRoot_) break;
                found = true;
                break;
            }
        }
        if (!found) revert OutputRootNotInSuperRoot(p.l2ChainId, outputRoot_);
        return keccak256(superPreimage);
    }

    // ── MPT helpers ──────────────────────────────────────────────────────────

    function _account(Memory.Slice accountProofItem, bytes32 stateRoot, address account)
        private
        pure
        returns (bytes32 storageRoot, bytes32 codeHash)
    {
        return ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(accountProofItem, stateRoot, account));
    }

    function _slots(Memory.Slice storageProofItem, bytes32 storageRoot, bytes32[] memory slots)
        private
        pure
        returns (bytes32[] memory)
    {
        return ClprEvmStateProof.verifyProvenSlots(RLP.readList(storageProofItem), storageRoot, slots);
    }

    function _slot(Memory.Slice storageProofItem, bytes32 storageRoot, uint256 slot) private pure returns (bytes32) {
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(slot);
        return _slots(storageProofItem, storageRoot, slots)[0];
    }

    /// @dev Right-aligned packed field at `byteOffset` (Solidity packs from the low-order end); the
    ///      caller truncates to the field's width.
    function _field(bytes32 word, uint256 byteOffset) private pure returns (uint256) {
        return uint256(word) >> (byteOffset * 8);
    }
}
