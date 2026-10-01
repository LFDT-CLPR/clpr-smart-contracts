package keeper_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/keeper"
	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

func setup(t *testing.T) (keeper.Keeper, sdk.Context, *storetypes.KVStoreKey) {
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tctx := testutil.DefaultContextWithDB(t, key, storetypes.NewTransientStoreKey("t"))
	cdc := codec.NewProtoCodec(codectypes.NewInterfaceRegistry())
	k := keeper.NewKeeper(cdc, runtime.NewKVStoreService(key), "gov")
	if err := k.SetParams(tctx.Ctx, types.DefaultGenesis().Params); err != nil {
		t.Fatal(err)
	}
	if err := k.InitServiceItem(tctx.Ctx); err != nil {
		t.Fatal(err)
	}
	return k, tctx.Ctx, key
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Golden vector shared with test/verifiers/evm/dydx/CosmosModuleVerifier.t.sol: the stored
// message value equals the bytes recorded from the localnet, and its payload equals Solidity's
// ClprProtobuf.encodeDataMessage.
func TestEnqueueGoldenVector(t *testing.T) {
	k, ctx, key := setup(t)
	ch := sha256.Sum256([]byte("clpr-dydx-hiero-demo"))
	conn := sha256.Sum256([]byte("connector"))
	sender := sdk.AccAddress(mustHex("e8721a574e9db5232daded88c68f9ebeef69efb3"))
	if err := k.OpenChannel(ctx, sender.String(), ch[:]); err != nil {
		t.Fatal(err)
	}
	id, h, err := k.Enqueue(ctx, sender, ch[:], conn[:], mustHex("000000000000000000000000000000000000abcd"), []byte("hello hiero"))
	if err != nil || id != 1 {
		t.Fatalf("enqueue: %v %d", err, id)
	}
	want := mustHex("0a5d0a5b0a20c08c6acfff81cafe379f88061e6b71bfbf2e9b5c5fcba037f0ac69a6b896d41b1214000000000000000000000000000000000000abcd1a14e8721a574e9db5232daded88c68f9ebeef69efb3220b68656c6c6f20686965726f1220bc785cf7f4ee9d04f222e56a84d56ef462ef8ef5c2d39b45851a42a8159d93a4")
	got := ctx.KVStore(key).Get(types.MessageKey(ch[:], 1))
	if !bytes.Equal(got, want) {
		t.Fatalf("message value\n got %x\nwant %x", got, want)
	}
	if hex.EncodeToString(h[:]) != "bc785cf7f4ee9d04f222e56a84d56ef462ef8ef5c2d39b45851a42a8159d93a4" {
		t.Fatalf("running hash %x", h)
	}
}

func TestQueueRecordAndChain(t *testing.T) {
	k, ctx, key := setup(t)
	ch := bytes.Repeat([]byte{7}, 32)
	sender := sdk.AccAddress(bytes.Repeat([]byte{1}, 20))
	conn := bytes.Repeat([]byte{2}, 32)
	if _, _, err := k.Enqueue(ctx, sender, ch, conn, nil, []byte("x")); err != types.ErrChannelNotFound {
		t.Fatalf("want ErrChannelNotFound, got %v", err)
	}
	if err := k.OpenChannel(ctx, sender.String(), ch); err != nil {
		t.Fatal(err)
	}
	if err := k.OpenChannel(ctx, sender.String(), ch); err != types.ErrChannelExists {
		t.Fatalf("want ErrChannelExists, got %v", err)
	}
	var prev [32]byte
	for i := uint64(1); i <= 3; i++ {
		id, h, err := k.Enqueue(ctx, sender, ch, conn, []byte{0xab}, []byte{byte(i)})
		if err != nil || id != i {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		v, ok := k.GetMessage(ctx, ch, i)
		if !ok {
			t.Fatal("message missing")
		}
		ph := sha256.Sum256(v.Payload)
		if exp := sha256.Sum256(append(prev[:], ph[:]...)); exp != h || !bytes.Equal(v.RunningHashAfterProcessing, h[:]) {
			t.Fatalf("running hash %d", i)
		}
		prev = h
	}
	raw := ctx.KVStore(key).Get(types.QueueRecordKey(ch))
	if len(raw) != types.QueueRecordLength {
		t.Fatalf("record length %d", len(raw))
	}
	r, _, _ := k.GetQueueRecord(ctx, ch)
	if r.Status != types.ACTIVE || r.NextMessageID != 4 || r.SentRunningHash != prev || r.ReceivedMessageID != 0 {
		t.Fatalf("record %+v", r)
	}
	big := make([]byte, types.DefaultGenesis().Params.MaxMessagePayloadBytes+1)
	if _, _, err := k.Enqueue(ctx, sender, ch, conn, nil, big); err != types.ErrPayloadTooLarge {
		t.Fatalf("want ErrPayloadTooLarge, got %v", err)
	}
}

func TestUpdateManifest(t *testing.T) {
	k, ctx, key := setup(t)
	ch := bytes.Repeat([]byte{9}, 32)
	if err := k.OpenChannel(ctx, "owner", ch); err != nil {
		t.Fatal(err)
	}
	man := append([]byte{0x08, 0x02, 0x12, 0x14}, types.ModuleAddress...)
	if err := k.UpdateManifest(ctx, "stranger", man); err == nil {
		t.Fatal("stranger updated the manifest")
	}
	if err := k.UpdateManifest(ctx, "gov", man); err != nil {
		t.Fatal(err)
	}
	item := ctx.KVStore(key).Get(types.ServiceItemKey)
	if len(item) != 52 || !bytes.Equal(item[:20], types.ModuleAddress) {
		t.Fatalf("service item %x", item)
	}
	if r, _, _ := k.GetQueueRecord(ctx, ch); r.EndpointManifestVersion != 2 {
		t.Fatalf("manifest version %d", r.EndpointManifestVersion)
	}
	if hex.EncodeToString(types.ModuleAddress) != "a88f550db4433c59b3322bca3a2c233cfdd69adc" {
		t.Fatalf("module address %x", types.ModuleAddress.Bytes())
	}
}
