package main

import (
	"io"
	"os"
	"path/filepath"

	"cosmossdk.io/log"
	clprcli "github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/client/cli"
	cmtcfg "github.com/cometbft/cometbft/config"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/server"
	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankcli "github.com/cosmos/cosmos-sdk/x/bank/client/cli"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	"github.com/spf13/cobra"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/app"
)

func main() {
	home := filepath.Join(os.Getenv("HOME"), app.DefaultNodeHome)
	if err := svrcmd.Execute(newRootCmd(home), "", home); err != nil {
		os.Exit(1)
	}
}

func newRootCmd(home string) *cobra.Command {
	enc := app.MakeEncodingConfig()
	basics := app.BasicManager()
	initCtx := client.Context{}.
		WithCodec(enc.Codec).WithInterfaceRegistry(enc.InterfaceRegistry).WithTxConfig(enc.TxConfig).
		WithLegacyAmino(enc.Amino).WithInput(os.Stdin).WithAccountRetriever(authtypes.AccountRetriever{}).
		WithHomeDir(home).WithViper("")

	root := &cobra.Command{
		Use:   app.Name,
		Short: "Local chain running x/clpr on dYdX's SDK forks",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SetOut(cmd.OutOrStdout())
			cmd.SetErr(cmd.ErrOrStderr())
			c := initCtx.WithCmdContext(cmd.Context())
			c, err := client.ReadPersistentCommandFlags(c, cmd.Flags())
			if err != nil {
				return err
			}
			if c, err = config.ReadFromClientConfig(c); err != nil {
				return err
			}
			if err := client.SetCmdClientContextHandler(c, cmd); err != nil {
				return err
			}
			return server.InterceptConfigsPreRunHandler(cmd, "", nil, cmtcfg.DefaultConfig())
		},
	}

	txCmd := &cobra.Command{Use: "tx", Short: "Transactions", RunE: client.ValidateCmd}
	txCmd.AddCommand(authcmd.GetSignCommand(), authcmd.GetBroadcastCommand(), authcmd.GetEncodeCommand())
	txCmd.AddCommand(clprcli.GetTxCmd(), bankcli.NewSendTxCmd(addresscodec.NewBech32Codec(app.AccountPrefix)))

	queryCmd := &cobra.Command{Use: "query", Aliases: []string{"q"}, Short: "Queries", RunE: client.ValidateCmd}
	queryCmd.AddCommand(rpc.ValidatorCommand(), authcmd.QueryTxCmd(), server.QueryBlockCmd())

	root.AddCommand(
		genutilcli.InitCmd(basics, home),
		genutilcli.Commands(enc.TxConfig, basics, home),
		keys.Commands(),
		txCmd,
		queryCmd,
	)
	server.AddCommands(root, home, newApp, nil, func(*cobra.Command) {})
	return root
}

func newApp(logger log.Logger, db dbm.DB, trace io.Writer, opts servertypes.AppOptions) servertypes.Application {
	return app.NewApp(logger, db, trace, true, opts, server.DefaultBaseappOptions(opts)...)
}
