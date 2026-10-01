package types

import (
	"encoding/binary"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

const (
	ModuleName = "clpr"
	// StoreKey is the IAVL store this module owns. The peer's verifier proves
	// app_hash → StoreKey (ICS-23 Tendermint spec) → key (ICS-23 IAVL spec).
	StoreKey = ModuleName

	ChannelIDLength   = 32
	QueueRecordLength = 90
	QueueRecordFormat = 1
)

// Key layout of the "clpr" store. Every key is fixed-length per prefix, so the IAVL
// ordering is (prefix, channel, message id) and absence of any key is provable with an
// ICS-23 non-existence proof (left and right neighbours).
//
//	0x01 ‖ channel_id(32)                 → queue record, 90 B (QueueRecord.Bytes)
//	0x02 ‖ channel_id(32) ‖ message_id u64 BE → ClprMessageValue (protobuf)
//	0x03                                  → service item: module address(20) ‖ manifest commitment(32)
//	0x04 ‖ channel_id(32)                 → Channel (protobuf, local bookkeeping; not proven)
//	0x05                                  → Params (protobuf)
var (
	QueueRecordPrefix = []byte{0x01}
	MessagePrefix     = []byte{0x02}
	ServiceItemKey    = []byte{0x03}
	ChannelPrefix     = []byte{0x04}
	ParamsKey         = []byte{0x05}
)

// ModuleAddress is the CLPR Service address on this chain: the module account,
// sha256("clpr")[:20]. The peer's ChannelContext.remoteServiceAddress holds these 20 bytes.
var ModuleAddress = authtypes.NewModuleAddress(ModuleName)

func QueueRecordKey(channelID []byte) []byte {
	return append(append([]byte{}, QueueRecordPrefix...), channelID...)
}

func MessageKey(channelID []byte, messageID uint64) []byte {
	k := make([]byte, 0, 1+ChannelIDLength+8)
	k = append(k, MessagePrefix...)
	k = append(k, channelID...)
	return binary.BigEndian.AppendUint64(k, messageID)
}

func ChannelKey(channelID []byte) []byte {
	return append(append([]byte{}, ChannelPrefix...), channelID...)
}
