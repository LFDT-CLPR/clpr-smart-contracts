// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";
import {RoninProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/profiles/RoninProfile.sol";

/// @title BobProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for BOB (chain 60808), which
///         settles on Ethereum mainnet through permissioned dispute games (game type 1).
/// @dev L1 contracts (read on 2026-10-01 from live mainnet storage; Superchain registry `bob.toml`):
///        L1CrossDomainMessenger 0xE3d981643b806FB8030CDB677D6E60892E547EdA → OptimismPortal
///        0x8AdeE124447435fE03e3CD24dF3f4cAE32E65a3E (5.6.1)
///        → AnchorStateRegistry 0xC9AC21AcD8696B64270716528bF83630Ea7a293c (proxy; implementation
///          0x5020964201c4d65555f33fd9bc281443d65f4c09, version 3.9.0: Ronin's bytecode except the
///          finality-delay immutable, 43,200 s)
///        → DisputeGameFactory 0x96123dbFC3253185B594c6a7472EE5A21E9B1079 (1.6.1, the shared implementation
///          0x72B971717E088B59F26d4236BE222ADB6ACD393b)
///        → gameImpls[1] = PermissionedDisputeGame 2.4.0 0x642d1cc835a81c738313EBe85ED61979a44897bF (not on
///          Sourcify: same length as Ronin's verified 2.4.0 and differs only in immutables; slots 0 and 10
///          checked against the getters of a live game), configured by gameArgs[1] = prestate 0x03682932…94b6,
///          VM 0xb6b6…cc13, ASR, WETH 0x048d…3d95, L2 chain id 60808, proposer 0x7cB1…8C69, challenger 0xC914…764E.
///
///      Trust (README §7): the Ethereum sync committee; one proposer (an EOA) and one challenger, a 4-of-6
///      Safe 0xC914…764E that also owns the ProxyAdmin and the DGF and is the guardian, with no timelock.
///      The game clock is 12 h and the finality delay 12 h, so FINALIZED delivers about a day after a game.
library BobProfile {
    uint256 internal constant L2_CHAIN_ID = 60808;
    address internal constant ANCHOR_STATE_REGISTRY = 0xC9AC21AcD8696B64270716528bF83630Ea7a293c;
    /// @dev keccak256 of BOB's ASR 3.9.0 implementation's runtime code; binds the 12-hour delay.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0x95cd0287fff0b9dbac513c35e8d5a5b6f3f17ff95f54dc9a0f2666855b981c18;
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 43_200;
    address internal constant GAME_IMPLEMENTATION = 0x642d1cc835a81c738313EBe85ED61979a44897bF;
    /// @dev keccak256(DisputeGameFactory.gameArgs(1)), 164 bytes.
    bytes32 internal constant GAME_ARGS_HASH = 0x6168acf76bd054257f945dbc8f45fbedd29be6ac0f023379377445378ba17da9;
    uint32 internal constant GAME_TYPE = 1;

    function profile() internal pure returns (OP.Profile memory) {
        return OP.Profile({
            rootFormat: OP.RootFormat.OUTPUT_ROOT,
            l2ChainId: L2_CHAIN_ID,
            anchorStateRegistry: ANCHOR_STATE_REGISTRY,
            anchorStateRegistryImplCodeHash: ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH,
            disputeGameFinalityDelaySeconds: DISPUTE_GAME_FINALITY_DELAY_SECONDS,
            gameImplementation: GAME_IMPLEMENTATION,
            gameArgsHash: GAME_ARGS_HASH,
            layout: RoninProfile.layout() // ASR 3.9.0 / DGF 1.6.1 / PermissionedDisputeGame 2.4.0 (slot 10)
        });
    }
}
