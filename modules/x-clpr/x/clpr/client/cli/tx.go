package cli

import (
	"encoding/hex"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	"github.com/LFDT-CLPR/clpr-smart-contracts/modules/x-clpr/x/clpr/types"
)

func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{Use: types.ModuleName, Short: "CLPR Service transactions", RunE: client.ValidateCmd}
	cmd.AddCommand(openChannelCmd(), sendMessageCmd(), updateManifestCmd())
	return cmd
}

func hexArg(s string) ([]byte, error) { return hex.DecodeString(strings.TrimPrefix(s, "0x")) }

func openChannelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "open-channel [channel-id-hex]", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			id, err := hexArg(args[0])
			if err != nil {
				return err
			}
			msg := &types.MsgOpenChannel{Owner: cctx.GetFromAddress().String(), ChannelId: id}
			return tx.GenerateOrBroadcastTxCLI(cctx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func sendMessageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "send-message [channel-id-hex] [connector-id-hex] [target-app-hex] [data-hex]",
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			cctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			var b [4][]byte
			for i := range b {
				if b[i], err = hexArg(args[i]); err != nil {
					return err
				}
			}
			msg := &types.MsgSendMessage{Sender: cctx.GetFromAddress().String(), ChannelId: b[0],
				ConnectorId: b[1], TargetApplication: b[2], MessageData: b[3]}
			return tx.GenerateOrBroadcastTxCLI(cctx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func updateManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "update-manifest [manifest-protobuf-hex]", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cctx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			m, err := hexArg(args[0])
			if err != nil {
				return err
			}
			msg := &types.MsgUpdateManifest{Authority: cctx.GetFromAddress().String(), Manifest: m}
			return tx.GenerateOrBroadcastTxCLI(cctx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
