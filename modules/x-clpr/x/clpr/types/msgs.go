package types

import (
	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

var (
	ErrInvalidChannelID = errorsmod.Register(ModuleName, 2, "channel id must be 32 bytes")
	ErrChannelExists    = errorsmod.Register(ModuleName, 3, "channel already exists")
	ErrChannelNotFound  = errorsmod.Register(ModuleName, 4, "channel not found")
	ErrChannelNotActive = errorsmod.Register(ModuleName, 5, "channel is not ACTIVE")
	ErrPayloadTooLarge  = errorsmod.Register(ModuleName, 6, "message_data exceeds max_message_payload_bytes")
	ErrUnauthorized     = errorsmod.Register(ModuleName, 7, "signer may not update the manifest")
	ErrInvalidConnector = errorsmod.Register(ModuleName, 8, "connector id must be 32 bytes")
)

var (
	_ sdk.Msg = &MsgOpenChannel{}
	_ sdk.Msg = &MsgSendMessage{}
	_ sdk.Msg = &MsgUpdateManifest{}
)

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil), &MsgOpenChannel{}, &MsgSendMessage{}, &MsgUpdateManifest{})
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}

func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgOpenChannel{}, "clpr/MsgOpenChannel", nil)
	cdc.RegisterConcrete(&MsgSendMessage{}, "clpr/MsgSendMessage", nil)
	cdc.RegisterConcrete(&MsgUpdateManifest{}, "clpr/MsgUpdateManifest", nil)
}

func (m *MsgOpenChannel) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Owner); err != nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, err.Error())
	}
	if len(m.ChannelId) != ChannelIDLength {
		return ErrInvalidChannelID
	}
	return nil
}

func (m *MsgSendMessage) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Sender); err != nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, err.Error())
	}
	if len(m.ChannelId) != ChannelIDLength {
		return ErrInvalidChannelID
	}
	if len(m.ConnectorId) != 32 {
		return ErrInvalidConnector
	}
	return nil
}

func (m *MsgUpdateManifest) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, err.Error())
	}
	return nil
}

func DefaultGenesis() *GenesisState {
	return &GenesisState{Params: Params{MaxMessagePayloadBytes: 16 * 1024}}
}
