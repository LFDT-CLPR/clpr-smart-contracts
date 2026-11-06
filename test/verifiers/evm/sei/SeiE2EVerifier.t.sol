// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SeiE2EVerifier} from "@test/SeiE2EVerifier.sol";
import {QbftE2EVerifier} from "@test/QbftE2EVerifier.sol";
import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";

/// Validates the E2E wrapper's verifyConfig: returns the configured peer identity + seed endpoints
/// and a genuine genesis trust anchor (decoding back to the peer chain id / service / validators).
contract SeiE2EVerifierTest is Test {
    SeiE2EVerifier verifier;
    address constant PEER_SERVICE = 0x0165878A594ca255338adfa4d48449f69242Eb8F;
    bytes32 constant VAL_PUBKEY = bytes32(uint256(0xABCD));

    function setUp() public {
        Ed25519Verifier ed = new Ed25519Verifier();
        CometBftLib.SeiValidator[] memory gv = new CometBftLib.SeiValidator[](1);
        gv[0] = CometBftLib.SeiValidator({ed25519PubKey: VAL_PUBKEY, votingPower: int64(1000)});
        SeiCometBftVerifier crypto = new SeiCometBftVerifier(address(ed));
        verifier = new SeiE2EVerifier("sei-local-b", gv, address(crypto));
    }

    function test_verifyConfig_returnsConfiguredIdentityAndSeeds() public {
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] = ClprTypes.Endpoint({ipAddress: "10.96.0.2", port: 9545, tlsCertificate: "", accountId: ""});
        verifier.configure("sei-local-b", abi.encodePacked(PEER_SERVICE), seeds);

        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory outSeeds
        ) = verifier.verifyConfig("", bytes32(0), "");

        assertEq(chainId, "sei-local-b", "peer chainId");
        assertEq(serviceAddress, abi.encodePacked(PEER_SERVICE), "peer service");
        assertEq(outSeeds.endpoints.length, 1, "one seed endpoint");
        assertEq(outSeeds.endpoints[0].port, uint32(9545), "seed port");

        // Trust anchor must be abi.encode(chainId, SeiValidator[]) — the format _decodeTrustAnchor expects.
        CometBftLib.SeiValidator[] memory gv = new CometBftLib.SeiValidator[](1);
        gv[0] = CometBftLib.SeiValidator({ed25519PubKey: VAL_PUBKEY, votingPower: int64(1000)});
        bytes memory expectedAnchor = abi.encode("sei-local-b", gv);
        assertEq(anchor, expectedAnchor, "anchor is abi.encode(chainId, validators)");
        assertEq(anchorId, "", "anchorId is empty (set via genesisLedgerTrustAnchor at initialize time)");

        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        assertEq(ctx.channelId, bytes32(0));
        assertEq(ctx.remoteServiceAddress, abi.encodePacked(PEER_SERVICE), "context service");
    }

    /// @dev The Sei E2E wrapper's configure() now validates seed endpoints exactly as production
    ///      admission does — a DNS hostname is rejected (spec §1.2), so the E2E peer roster can't be
    ///      seeded with data that would never pass on-chain.
    function test_configure_rejectsDnsSeedEndpoint() public {
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] =
            ClprTypes.Endpoint({ipAddress: "clpr-relay-sei2-grpc", port: 9545, tlsCertificate: "", accountId: ""});
        vm.expectRevert(ClprTypes.ClprInvalidEndpointAddress.selector);
        verifier.configure("sei-local-b", abi.encodePacked(PEER_SERVICE), seeds);
    }

    /// @dev Same guarantee for the QBFT E2E wrapper's setSeedEndpoints().
    function test_qbftWrapper_setSeedEndpoints_rejectsDnsName() public {
        QbftE2EVerifier qbft = new QbftE2EVerifier(new QbftHeaderModeVerifier());
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] =
            ClprTypes.Endpoint({ipAddress: "clpr-relay-besu-grpc", port: 50211, tlsCertificate: "", accountId: ""});
        vm.expectRevert(ClprTypes.ClprInvalidEndpointAddress.selector);
        qbft.setSeedEndpoints(seeds);
    }
}
