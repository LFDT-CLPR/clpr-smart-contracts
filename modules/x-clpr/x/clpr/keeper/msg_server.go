package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

type msgServer struct{ Keeper }

func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{k} }

var _ types.MsgServer = msgServer{}

func (s msgServer) OpenChannel(ctx context.Context, m *types.MsgOpenChannel) (*types.MsgOpenChannelResponse, error) {
	if err := m.ValidateBasic(); err != nil {
		return nil, err
	}
	return &types.MsgOpenChannelResponse{}, s.Keeper.OpenChannel(ctx, m.Owner, m.ChannelId)
}

func (s msgServer) SendMessage(ctx context.Context, m *types.MsgSendMessage) (*types.MsgSendMessageResponse, error) {
	if err := m.ValidateBasic(); err != nil {
		return nil, err
	}
	sender, _ := sdk.AccAddressFromBech32(m.Sender)
	id, h, err := s.Keeper.Enqueue(ctx, sender, m.ChannelId, m.ConnectorId, m.TargetApplication, m.MessageData)
	if err != nil {
		return nil, err
	}
	return &types.MsgSendMessageResponse{MessageId: id, RunningHash: h[:]}, nil
}

func (s msgServer) UpdateManifest(ctx context.Context, m *types.MsgUpdateManifest) (*types.MsgUpdateManifestResponse, error) {
	if err := m.ValidateBasic(); err != nil {
		return nil, err
	}
	return &types.MsgUpdateManifestResponse{}, s.Keeper.UpdateManifest(ctx, m.Authority, m.Manifest)
}
