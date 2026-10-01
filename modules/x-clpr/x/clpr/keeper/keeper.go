package keeper

import (
	"context"
	"encoding/hex"
	"fmt"

	"cosmossdk.io/core/store"
	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

// Keeper owns the "clpr" KV store. All state the peer chain's verifier reads is written
// here, under the keys in types/keys.go.
type Keeper struct {
	cdc          codec.BinaryCodec
	storeService store.KVStoreService
	// authority may always update the manifest: the x/gov module account on a production chain.
	authority string
}

func NewKeeper(cdc codec.BinaryCodec, storeService store.KVStoreService, authority string) Keeper {
	return Keeper{cdc: cdc, storeService: storeService, authority: authority}
}

func (k Keeper) Authority() string { return k.authority }

// ── Params ────────────────────────────────────────────────────────────────

func (k Keeper) GetParams(ctx context.Context) (p types.Params) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.ParamsKey)
	if err != nil {
		panic(err)
	}
	if bz != nil {
		k.cdc.MustUnmarshal(bz, &p)
	}
	return p
}

func (k Keeper) SetParams(ctx context.Context, p types.Params) error {
	return k.storeService.OpenKVStore(ctx).Set(types.ParamsKey, k.cdc.MustMarshal(&p))
}

// ── Channels and queue records ────────────────────────────────────────────

func (k Keeper) GetChannel(ctx context.Context, channelID []byte) (types.Channel, bool) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.ChannelKey(channelID))
	if err != nil {
		panic(err)
	}
	if bz == nil {
		return types.Channel{}, false
	}
	var c types.Channel
	k.cdc.MustUnmarshal(bz, &c)
	return c, true
}

func (k Keeper) GetQueueRecord(ctx context.Context, channelID []byte) (types.QueueRecord, bool, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.QueueRecordKey(channelID))
	if err != nil || bz == nil {
		return types.QueueRecord{}, false, err
	}
	r, err := types.ParseQueueRecord(bz)
	return r, err == nil, err
}

func (k Keeper) setQueueRecord(ctx context.Context, channelID []byte, r types.QueueRecord) error {
	return k.storeService.OpenKVStore(ctx).Set(types.QueueRecordKey(channelID), r.Bytes())
}

// OpenChannel creates an ACTIVE channel with the spec's initial values (§2.1).
func (k Keeper) OpenChannel(ctx context.Context, owner string, channelID []byte) error {
	if len(channelID) != types.ChannelIDLength {
		return types.ErrInvalidChannelID
	}
	if _, found := k.GetChannel(ctx, channelID); found {
		return types.ErrChannelExists
	}
	kv := k.storeService.OpenKVStore(ctx)
	c := types.Channel{ChannelId: channelID, Owner: owner}
	if err := kv.Set(types.ChannelKey(channelID), k.cdc.MustMarshal(&c)); err != nil {
		return err
	}
	r := types.NewQueueRecord(types.ACTIVE)
	r.EndpointManifestVersion = k.manifestVersion(ctx)
	if err := k.setQueueRecord(ctx, channelID, r); err != nil {
		return err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent("clpr_channel_opened",
		sdk.NewAttribute("channel_id", hex.EncodeToString(channelID)),
		sdk.NewAttribute("owner", owner)))
	return nil
}

// Enqueue implements spec §4.3 steps 1 and 6–9 for a Data Message. Connector lookup and
// authorization (steps 2–3), lazy config propagation (1a) and queue-depth checks (5) are
// out of scope for this prototype.
func (k Keeper) Enqueue(ctx context.Context, sender sdk.AccAddress, channelID, connectorID, target, data []byte) (uint64, [32]byte, error) {
	r, found, err := k.GetQueueRecord(ctx, channelID)
	if err != nil {
		return 0, [32]byte{}, err
	}
	if !found {
		return 0, [32]byte{}, types.ErrChannelNotFound
	}
	if r.Status != types.ACTIVE {
		return 0, [32]byte{}, types.ErrChannelNotActive
	}
	if max := k.GetParams(ctx).MaxMessagePayloadBytes; max != 0 && uint32(len(data)) > max {
		return 0, [32]byte{}, types.ErrPayloadTooLarge
	}

	payload := types.ClprMessagePayload{Payload: &types.ClprMessagePayload_Message{Message: &types.ClprMessage{
		ConnectorId:       connectorID,
		TargetApplication: target,
		Sender:            sender.Bytes(), // stamped from the tx signer (§4.3 step 6)
		MessageData:       data,
	}}}
	payloadBytes, err := payload.Marshal()
	if err != nil {
		return 0, [32]byte{}, err
	}
	id := r.NextMessageID
	h := types.NextRunningHash(r.SentRunningHash, payloadBytes)
	v := types.ClprMessageValue{Payload: payloadBytes, RunningHashAfterProcessing: h[:]}
	if err := k.storeService.OpenKVStore(ctx).Set(types.MessageKey(channelID, id), k.cdc.MustMarshal(&v)); err != nil {
		return 0, [32]byte{}, err
	}
	r.SentRunningHash = h
	r.NextMessageID = id + 1
	if err := k.setQueueRecord(ctx, channelID, r); err != nil {
		return 0, [32]byte{}, err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent("clpr_message_queued",
		sdk.NewAttribute("channel_id", hex.EncodeToString(channelID)),
		sdk.NewAttribute("message_id", fmt.Sprint(id)),
		sdk.NewAttribute("running_hash", hex.EncodeToString(h[:]))))
	return id, h, nil
}

func (k Keeper) GetMessage(ctx context.Context, channelID []byte, id uint64) (types.ClprMessageValue, bool) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.MessageKey(channelID, id))
	if err != nil {
		panic(err)
	}
	if bz == nil {
		return types.ClprMessageValue{}, false
	}
	var v types.ClprMessageValue
	k.cdc.MustUnmarshal(bz, &v)
	return v, true
}

// ── Service item and manifest ─────────────────────────────────────────────

func (k Keeper) InitServiceItem(ctx context.Context) error {
	kv := k.storeService.OpenKVStore(ctx)
	if has, err := kv.Has(types.ServiceItemKey); err != nil || has {
		return err
	}
	return kv.Set(types.ServiceItemKey, types.ServiceItem([32]byte{}))
}

// UpdateManifest stores keccak256(manifest) in the service item and bumps every channel's
// endpoint_manifest_version in its queue record (§2.4), so the peer sees the change.
func (k Keeper) UpdateManifest(ctx context.Context, signer string, manifest []byte) error {
	if signer != k.authority && signer != k.GetParams(ctx).Admin {
		return errorsmod.Wrapf(types.ErrUnauthorized, "%s", signer)
	}
	version, err := manifestVersionOf(manifest)
	if err != nil {
		return err
	}
	var c [32]byte
	hh := sha3.NewLegacyKeccak256()
	hh.Write(manifest)
	copy(c[:], hh.Sum(nil))
	kv := k.storeService.OpenKVStore(ctx)
	if err := kv.Set(types.ServiceItemKey, types.ServiceItem(c)); err != nil {
		return err
	}
	it, err := kv.Iterator(types.QueueRecordPrefix, []byte{types.QueueRecordPrefix[0] + 1})
	if err != nil {
		return err
	}
	type upd struct {
		key []byte
		r   types.QueueRecord
	}
	var updates []upd
	for ; it.Valid(); it.Next() {
		r, err := types.ParseQueueRecord(it.Value())
		if err != nil {
			it.Close()
			return err
		}
		r.EndpointManifestVersion = version
		updates = append(updates, upd{append([]byte{}, it.Key()...), r})
	}
	it.Close()
	for _, u := range updates {
		if err := kv.Set(u.key, u.r.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) manifestVersion(ctx context.Context) uint64 {
	// Channels opened after a manifest update inherit the version of an existing record.
	kv := k.storeService.OpenKVStore(ctx)
	it, err := kv.Iterator(types.QueueRecordPrefix, []byte{types.QueueRecordPrefix[0] + 1})
	if err != nil {
		panic(err)
	}
	defer it.Close()
	if it.Valid() {
		if r, err := types.ParseQueueRecord(it.Value()); err == nil {
			return r.EndpointManifestVersion
		}
	}
	return 0
}

// manifestVersionOf reads ClprEndpointManifest.version (field 1, varint), which must be > 0.
func manifestVersionOf(m []byte) (uint64, error) {
	for len(m) > 0 {
		num, typ, n := protowire.ConsumeTag(m)
		if n < 0 {
			return 0, fmt.Errorf("bad manifest")
		}
		m = m[n:]
		if num == 1 && typ == protowire.VarintType {
			v, n := protowire.ConsumeVarint(m)
			if n < 0 || v == 0 {
				return 0, fmt.Errorf("bad manifest version")
			}
			return v, nil
		}
		n = protowire.ConsumeFieldValue(num, typ, m)
		if n < 0 {
			return 0, fmt.Errorf("bad manifest")
		}
		m = m[n:]
	}
	return 0, fmt.Errorf("manifest version missing")
}
