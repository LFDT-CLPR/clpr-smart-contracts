// Package app is a minimal single-purpose Cosmos SDK chain (auth, bank, staking, genutil,
// consensus + x/clpr) built on dYdX v4's own forks of cosmos-sdk, store, IAVL and CometBFT
// (see go.mod). It exists to run x/clpr on a local single-validator chain and record real
// commits and ICS-23 proofs; it is not dYdX.
package app

import (
	"encoding/json"
	"io"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"cosmossdk.io/x/tx/signing"
	abci "github.com/cometbft/cometbft/abci/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server/api"
	"github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	consensuskeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	consensustypes "github.com/cosmos/cosmos-sdk/x/consensus/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr"
	clprkeeper "github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/keeper"
	clprtypes "github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

const (
	Name          = "clprd"
	AccountPrefix = "dydx" // dYdX's bech32 prefix, so addresses look like the real chain's
)

var DefaultNodeHome = ".clprd"

type EncodingConfig struct {
	InterfaceRegistry types.InterfaceRegistry
	Codec             codec.Codec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}

func SetBech32() {
	c := sdk.GetConfig()
	c.SetBech32PrefixForAccount(AccountPrefix, AccountPrefix+"pub")
	c.SetBech32PrefixForValidator(AccountPrefix+"valoper", AccountPrefix+"valoperpub")
	c.SetBech32PrefixForConsensusNode(AccountPrefix+"valcons", AccountPrefix+"valconspub")
}

func MakeEncodingConfig() EncodingConfig {
	SetBech32()
	reg, err := types.NewInterfaceRegistryWithOptions(types.InterfaceRegistryOptions{
		ProtoFiles: proto.HybridResolver,
		SigningOptions: signing.Options{
			AddressCodec:          address.Bech32Codec{Bech32Prefix: AccountPrefix},
			ValidatorAddressCodec: address.Bech32Codec{Bech32Prefix: AccountPrefix + "valoper"},
		},
	})
	if err != nil {
		panic(err)
	}
	cdc := codec.NewProtoCodec(reg)
	amino := codec.NewLegacyAmino()
	std.RegisterLegacyAminoCodec(amino)
	std.RegisterInterfaces(reg)
	BasicManager().RegisterLegacyAminoCodec(amino)
	BasicManager().RegisterInterfaces(reg)
	return EncodingConfig{reg, cdc, authtx.NewTxConfig(cdc, authtx.DefaultSignModes), amino}
}

func BasicManager() module.BasicManager {
	return module.NewBasicManager(
		auth.AppModuleBasic{},
		genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
		bank.AppModuleBasic{},
		staking.AppModuleBasic{},
		consensus.AppModuleBasic{},
		clpr.AppModuleBasic{},
	)
}

type App struct {
	*baseapp.BaseApp
	enc  EncodingConfig
	keys map[string]*storetypes.KVStoreKey

	AccountKeeper   authkeeper.AccountKeeper
	BankKeeper      bankkeeper.BaseKeeper
	StakingKeeper   *stakingkeeper.Keeper
	ConsensusKeeper consensuskeeper.Keeper
	ClprKeeper      clprkeeper.Keeper

	mm *module.Manager
}

var _ servertypes.Application = (*App)(nil)

func NewApp(logger log.Logger, db dbm.DB, traceStore io.Writer, loadLatest bool, _ servertypes.AppOptions, opts ...func(*baseapp.BaseApp)) *App {
	enc := MakeEncodingConfig()
	bApp := baseapp.NewBaseApp(Name, logger, db, enc.TxConfig.TxDecoder(), opts...)
	bApp.SetCommitMultiStoreTracer(traceStore)
	bApp.SetInterfaceRegistry(enc.InterfaceRegistry)
	bApp.SetTxEncoder(enc.TxConfig.TxEncoder())

	keys := storetypes.NewKVStoreKeys(authtypes.StoreKey, banktypes.StoreKey, stakingtypes.StoreKey,
		consensustypes.StoreKey, clprtypes.StoreKey)
	a := &App{BaseApp: bApp, enc: enc, keys: keys}
	authority := authtypes.NewModuleAddress("gov").String()

	a.ConsensusKeeper = consensuskeeper.NewKeeper(enc.Codec, runtime.NewKVStoreService(keys[consensustypes.StoreKey]), authority, runtime.EventService{})
	bApp.SetParamStore(a.ConsensusKeeper.ParamsStore)

	maccPerms := map[string][]string{
		authtypes.FeeCollectorName:     nil,
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
		clprtypes.ModuleName:           nil,
	}
	a.AccountKeeper = authkeeper.NewAccountKeeper(enc.Codec, runtime.NewKVStoreService(keys[authtypes.StoreKey]),
		authtypes.ProtoBaseAccount, maccPerms, address.NewBech32Codec(AccountPrefix), AccountPrefix, authority)
	a.BankKeeper = bankkeeper.NewBaseKeeper(enc.Codec, runtime.NewKVStoreService(keys[banktypes.StoreKey]),
		a.AccountKeeper, map[string]bool{}, authority, logger)
	a.StakingKeeper = stakingkeeper.NewKeeper(enc.Codec, runtime.NewKVStoreService(keys[stakingtypes.StoreKey]),
		a.AccountKeeper, a.BankKeeper, authority,
		address.NewBech32Codec(AccountPrefix+"valoper"), address.NewBech32Codec(AccountPrefix+"valcons"))
	a.ClprKeeper = clprkeeper.NewKeeper(enc.Codec, runtime.NewKVStoreService(keys[clprtypes.StoreKey]), authority)

	a.mm = module.NewManager(
		genutil.NewAppModule(a.AccountKeeper, a.StakingKeeper, a, enc.TxConfig),
		auth.NewAppModule(enc.Codec, a.AccountKeeper, nil, nil),
		bank.NewAppModule(enc.Codec, a.BankKeeper, a.AccountKeeper, nil),
		staking.NewAppModule(enc.Codec, a.StakingKeeper, a.AccountKeeper, a.BankKeeper, nil),
		consensus.NewAppModule(enc.Codec, a.ConsensusKeeper),
		clpr.NewAppModule(a.ClprKeeper),
	)
	a.mm.SetOrderBeginBlockers(stakingtypes.ModuleName)
	a.mm.SetOrderEndBlockers(stakingtypes.ModuleName)
	order := []string{authtypes.ModuleName, banktypes.ModuleName, stakingtypes.ModuleName,
		genutiltypes.ModuleName, consensustypes.ModuleName, clprtypes.ModuleName}
	a.mm.SetOrderInitGenesis(order...)
	a.mm.SetOrderExportGenesis(order...)
	if err := a.mm.RegisterServices(module.NewConfigurator(enc.Codec, a.MsgServiceRouter(), a.GRPCQueryRouter())); err != nil {
		panic(err)
	}

	a.MountKVStores(keys)
	a.SetInitChainer(a.InitChainer)
	a.SetBeginBlocker(a.mm.BeginBlock)
	a.SetEndBlocker(a.mm.EndBlock)
	anteHandler, err := ante.NewAnteHandler(ante.HandlerOptions{
		AccountKeeper:   a.AccountKeeper,
		BankKeeper:      a.BankKeeper,
		SignModeHandler: enc.TxConfig.SignModeHandler(),
		SigGasConsumer:  ante.DefaultSigVerificationGasConsumer,
	})
	if err != nil {
		panic(err)
	}
	a.SetAnteHandler(anteHandler)
	if loadLatest {
		if err := a.LoadLatestVersion(); err != nil {
			panic(err)
		}
	}
	return a
}

func (a *App) InitChainer(ctx sdk.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	var genesis map[string]json.RawMessage
	if err := json.Unmarshal(req.AppStateBytes, &genesis); err != nil {
		return nil, err
	}
	return a.mm.InitGenesis(ctx, a.enc.Codec, genesis)
}

func (a *App) RegisterAPIRoutes(*api.Server, config.APIConfig) {}

func (a *App) RegisterTxService(cctx client.Context) {
	authtx.RegisterTxService(a.GRPCQueryRouter(), cctx, a.Simulate, a.enc.InterfaceRegistry)
}

func (a *App) RegisterTendermintService(cctx client.Context) {
	cmtservice.RegisterTendermintService(cctx, a.GRPCQueryRouter(), a.enc.InterfaceRegistry, a.Query)
}

func (a *App) RegisterNodeService(cctx client.Context, cfg config.Config) {
	nodeservice.RegisterNodeService(cctx, a.GRPCQueryRouter(), cfg)
}

func (a *App) DefaultGenesis() map[string]json.RawMessage {
	return BasicManager().DefaultGenesis(a.enc.Codec)
}
