package clpr

import (
	"encoding/json"

	"cosmossdk.io/core/appmodule"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/client/cli"
	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/keeper"
	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

// ConsensusVersion is bumped with every store migration (needed for an upgrade handler).
const ConsensusVersion = 1

var (
	_ module.AppModuleBasic = AppModule{}
	_ module.HasGenesis     = AppModule{}
	_ module.HasServices    = AppModule{}
	_ appmodule.AppModule   = AppModule{}
)

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(c *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(c)
}
func (AppModuleBasic) RegisterInterfaces(r cdctypes.InterfaceRegistry)             { types.RegisterInterfaces(r) }
func (AppModuleBasic) RegisterGRPCGatewayRoutes(client.Context, *runtime.ServeMux) {}
func (AppModuleBasic) GetTxCmd() *cobra.Command                                    { return cli.GetTxCmd() }

func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesis())
}

func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var g types.GenesisState
	return cdc.UnmarshalJSON(bz, &g)
}

type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule { return AppModule{keeper: k} }

func (AppModule) IsOnePerModuleType()      {}
func (AppModule) IsAppModule()             {}
func (AppModule) ConsensusVersion() uint64 { return ConsensusVersion }

func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
}

func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, bz json.RawMessage) {
	var g types.GenesisState
	cdc.MustUnmarshalJSON(bz, &g)
	if err := am.keeper.SetParams(ctx, g.Params); err != nil {
		panic(err)
	}
	if err := am.keeper.InitServiceItem(ctx); err != nil {
		panic(err)
	}
}

// ExportGenesis exports params only. Channel and queue state export is future work (README §6).
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(&types.GenesisState{Params: am.keeper.GetParams(ctx)})
}
