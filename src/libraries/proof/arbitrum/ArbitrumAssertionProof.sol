// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ArbitrumAssertionProof
/// @notice Proves, from an authenticated Ethereum L1 `state_root`, that an Arbitrum Nitro (BoLD)
///         assertion is CONFIRMED by the chain's rollup contract, and walks from that assertion to the
///         L2 block's `stateRoot`, using only MPT account/storage proofs and hash preimages:
///
///         1. L1 `state_root` → rollup proxy account → storage root
///         2. the proxy's two logic slots (EIP-1967 primary = RollupAdminLogic, secondary =
///            RollupUserLogic) equal the pinned implementations — so the storage below is read
///            through the layout and semantics those implementations define
///         3. assertion preimage `parentAssertionHash ‖ abi.encode(AssertionState) ‖ inboxAcc`
///            → `assertionHash = keccak256(parent ‖ keccak256(afterState) ‖ inboxAcc)`
///            (`RollupLib.assertionHash`), and `afterState.machineStatus == FINISHED`
///         4. `_assertions[assertionHash]` slot 0 → `status == Confirmed`
///         5. `afterState.globalState.bytes32Vals[0]` is the L2 block hash; the supplied header RLP
///            must hash to it, and its item 3 is the L2 `stateRoot`.
///
///         `Confirmed` is terminal in RollupCore (only `confirmAssertionInternal`, from `Pending`, and
///         the genesis assertion ever set it), so any confirmed assertion is a final statement about
///         the L2 chain. A relayer may pick any confirmed assertion — the newest one or an older one
///         whose L2 block its L2 RPC still serves `eth_getProof` for; CLPR's queue-metadata checks
///         (BundleLib replay / ack monotonicity) reject state older than what a channel has seen.
///
/// @dev Source: OffchainLabs/nitro-contracts v3.x (BoLD) — RollupCore.sol, Assertion.sol,
///      AssertionState.sol, RollupLib.sol, GlobalState.sol, AdminFallbackProxy.sol. Storage slots and
///      packed offsets come from a {Layout} value (data), so a rollup upgrade that moves a field is a
///      new profile, not new code (clpr-spec ADR 2026-10-01 "Fork-Aware Verifiers").
library ArbitrumAssertionProof {
    // ── Assertion proof RLP layout ───────────────────────────────────────────
    uint256 internal constant ASSERTION_PROOF_FIELDS = 2;
    uint256 internal constant AP_IDX_ROLLUP_ACCOUNT = 0;
    uint256 internal constant AP_IDX_ROLLUP_STORAGE = 1;

    /// @dev `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)` — RollupAdminLogic.
    bytes32 internal constant EIP1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    /// @dev `bytes32(uint256(keccak256("eip1967.proxy.implementation.secondary")) - 1)` — RollupUserLogic
    ///      (DoubleLogicERC1967Upgrade._IMPLEMENTATION_SECONDARY_SLOT).
    bytes32 internal constant IMPLEMENTATION_SECONDARY_SLOT =
        0x2b1dbce74324248c222f0ec2d5ed7bd323cfc425b336f0253c5ccfda7265546d;

    /// @dev Assertion preimage: `parentAssertionHash(32) ‖ abi.encode(AssertionState)(192) ‖ inboxAcc(32)`.
    ///      `abi.encode(AssertionState)` = `blockHash ‖ sendRoot ‖ inboxPosition ‖ positionInMessage ‖
    ///      machineStatus ‖ endHistoryRoot`, one 32-byte word each (all members are static).
    uint256 internal constant ASSERTION_PREIMAGE_LENGTH = 256;
    uint256 internal constant AFTER_STATE_OFFSET = 32;
    uint256 internal constant AFTER_STATE_LENGTH = 192;
    uint256 internal constant INBOX_ACC_OFFSET = 224;

    /// @dev `MachineStatus` (state/Machine.sol): RUNNING, FINISHED, ERRORED.
    uint256 internal constant MACHINE_STATUS_FINISHED = 1;
    /// @dev `AssertionStatus` (rollup/Assertion.sol): NoAssertion, Pending, Confirmed.
    uint8 internal constant ASSERTION_STATUS_CONFIRMED = 2;

    /// @dev Ethereum-style header: item 3 is `stateRoot`, item 8 is `number`.
    uint256 internal constant HEADER_IDX_STATE_ROOT = 3;
    uint256 internal constant HEADER_IDX_NUMBER = 8;
    uint256 internal constant HEADER_MIN_FIELDS = 15;

    /// @notice Where the facts live in the rollup proxy's storage.
    struct Layout {
        uint256 assertionsSlot; // RollupCore._assertions (mapping base)
        uint256 assertionStatusOffset; // byte offset of AssertionNode.status in the node's slot 0
    }

    /// @notice The chain being verified: its rollup proxy, the pinned logic contracts and the layout.
    struct Profile {
        address rollup;
        address rollupAdminLogic;
        address rollupUserLogic;
        Layout layout;
    }

    /// @notice What a verified assertion says about the L2 chain.
    struct ConfirmedState {
        bytes32 assertionHash;
        bytes32 l2BlockHash;
        bytes32 l2StateRoot;
        uint256 l2BlockNumber;
        bytes32 sendRoot;
    }

    error InvalidAssertionProof();
    error InvalidAssertionPreimage();
    error MachineNotFinished(uint256 machineStatus);
    error AssertionNotConfirmed(bytes32 assertionHash, uint8 status);
    error RollupLogicMismatch(address adminLogic, address userLogic);
    error L2HeaderHashMismatch(bytes32 expected, bytes32 actual);
    error InvalidL2Header();

    /// @notice Prove that the assertion in `assertionPreimage` is confirmed by `p.rollup` in the L1
    ///         state `l1StateRoot`, and that `l2Header` is its L2 block.
    /// @param assertionProofItem RLP `[rollupAccountProof, rollupStorageProof]`, the storage proof
    ///        carrying `[slot, proofNodes]` entries for the two logic slots and `_assertions[h]` slot 0.
    /// @param assertionPreimage 256 bytes, see {ASSERTION_PREIMAGE_LENGTH}.
    /// @param l2Header the RLP-encoded L2 block header.
    function verify(
        Profile memory p,
        Memory.Slice assertionProofItem,
        bytes32 l1StateRoot,
        bytes memory assertionPreimage,
        bytes memory l2Header
    ) internal pure returns (ConfirmedState memory s) {
        bytes32 machineStatus;
        (s.assertionHash, s.l2BlockHash, s.sendRoot, machineStatus) = decodeAssertion(assertionPreimage);
        if (uint256(machineStatus) != MACHINE_STATUS_FINISHED) revert MachineNotFinished(uint256(machineStatus));

        Memory.Slice[] memory ap = RLP.readList(assertionProofItem);
        if (ap.length != ASSERTION_PROOF_FIELDS) revert InvalidAssertionProof();
        (bytes32 storageRoot,) = ClprEvmStateProof.decodeAccount(
            ClprEvmStateProof.verifyAccount(ap[AP_IDX_ROLLUP_ACCOUNT], l1StateRoot, p.rollup)
        );

        bytes32[] memory slots = new bytes32[](3);
        slots[0] = EIP1967_IMPLEMENTATION_SLOT;
        slots[1] = IMPLEMENTATION_SECONDARY_SLOT;
        slots[2] = assertionSlot(s.assertionHash, p.layout);
        bytes32[] memory v =
            ClprEvmStateProof.verifyProvenSlots(RLP.readList(ap[AP_IDX_ROLLUP_STORAGE]), storageRoot, slots);

        address adminLogic = address(uint160(uint256(v[0])));
        address userLogic = address(uint160(uint256(v[1])));
        if (adminLogic != p.rollupAdminLogic || userLogic != p.rollupUserLogic) {
            revert RollupLogicMismatch(adminLogic, userLogic);
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 status = uint8(uint256(v[2]) >> (p.layout.assertionStatusOffset * 8));
        if (status != ASSERTION_STATUS_CONFIRMED) revert AssertionNotConfirmed(s.assertionHash, status);

        (s.l2StateRoot, s.l2BlockNumber) = verifyL2Header(l2Header, s.l2BlockHash);
    }

    /// @notice `RollupLib.assertionHash` over the preimage, plus the after-state fields the verifier uses.
    function decodeAssertion(bytes memory preimage)
        internal
        pure
        returns (bytes32 assertionHash, bytes32 l2BlockHash, bytes32 sendRoot, bytes32 machineStatus)
    {
        if (preimage.length != ASSERTION_PREIMAGE_LENGTH) revert InvalidAssertionPreimage();
        bytes32 parent;
        bytes32 inboxAcc;
        bytes32 afterStateHash;
        assembly ("memory-safe") {
            let base := add(preimage, 0x20)
            parent := mload(base)
            let st := add(base, AFTER_STATE_OFFSET)
            l2BlockHash := mload(st)
            sendRoot := mload(add(st, 0x20))
            machineStatus := mload(add(st, 0x80))
            afterStateHash := keccak256(st, AFTER_STATE_LENGTH)
            inboxAcc := mload(add(base, INBOX_ACC_OFFSET))
        }
        assertionHash = keccak256(abi.encodePacked(parent, afterStateHash, inboxAcc));
    }

    /// @notice `keccak256(l2Header) == blockHash`, then the header's `stateRoot` and `number`.
    /// @dev Only items 3 and 8 are read, so the check is independent of which optional trailing fields
    ///      (baseFee, withdrawalsRoot, …) the chain's header carries. Nitro headers are geth headers:
    ///      `extraData` = send root, `mixHash` = sendCount ‖ L1 block number ‖ ArbOS version.
    function verifyL2Header(bytes memory l2Header, bytes32 blockHash)
        internal
        pure
        returns (bytes32 stateRoot, uint256 number)
    {
        bytes32 actual = keccak256(l2Header);
        if (actual != blockHash) revert L2HeaderHashMismatch(blockHash, actual);
        Memory.Slice[] memory h = RLP.decodeList(l2Header);
        if (h.length < HEADER_MIN_FIELDS) revert InvalidL2Header();
        stateRoot = RLP.readBytes32(h[HEADER_IDX_STATE_ROOT]);
        number = RLP.readUint256(h[HEADER_IDX_NUMBER]);
    }

    /// @notice Slot 0 of `_assertions[assertionHash]` (packed firstChildBlock | secondChildBlock |
    ///         createdAtBlock | isFirstChild | status).
    function assertionSlot(bytes32 assertionHash, Layout memory layout) internal pure returns (bytes32) {
        return keccak256(abi.encode(assertionHash, layout.assertionsSlot));
    }
}
