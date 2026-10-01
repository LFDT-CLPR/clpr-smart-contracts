package types

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// QueueRecord is this side's ChannelSyncData (spec §1.5) plus the two running hashes and
// the endpoint manifest version: everything the peer's verifier returns as
// ClprTypes.QueueMetadata. It is one IAVL entry per channel, rewritten on every change, so a
// bundle needs one ICS-23 proof.
//
// Encoding (90 B, integers big-endian), identical to the CosmWasm CLPR Service record that
// CosmWasmVerifier already decodes:
//
//	format u8 (=1) ‖ status u8 ‖ next_message_id u64 ‖ received_message_id u64 ‖
//	endpoint_manifest_version u64 ‖ sent_running_hash[32] ‖ received_running_hash[32]
type QueueRecord struct {
	Status                  ClprChannelStatus
	NextMessageID           uint64
	ReceivedMessageID       uint64
	EndpointManifestVersion uint64
	SentRunningHash         [32]byte
	ReceivedRunningHash     [32]byte
}

// NewQueueRecord is the record of a freshly opened channel (spec §2.1 initial values).
func NewQueueRecord(status ClprChannelStatus) QueueRecord {
	return QueueRecord{Status: status, NextMessageID: 1}
}

func (r QueueRecord) Bytes() []byte {
	b := make([]byte, 0, QueueRecordLength)
	b = append(b, QueueRecordFormat, byte(r.Status))
	b = binary.BigEndian.AppendUint64(b, r.NextMessageID)
	b = binary.BigEndian.AppendUint64(b, r.ReceivedMessageID)
	b = binary.BigEndian.AppendUint64(b, r.EndpointManifestVersion)
	b = append(b, r.SentRunningHash[:]...)
	return append(b, r.ReceivedRunningHash[:]...)
}

func ParseQueueRecord(b []byte) (QueueRecord, error) {
	var r QueueRecord
	if len(b) != QueueRecordLength || b[0] != QueueRecordFormat || b[1] > byte(CLOSED) {
		return r, fmt.Errorf("invalid queue record (%d bytes)", len(b))
	}
	r.Status = ClprChannelStatus(b[1])
	r.NextMessageID = binary.BigEndian.Uint64(b[2:10])
	r.ReceivedMessageID = binary.BigEndian.Uint64(b[10:18])
	r.EndpointManifestVersion = binary.BigEndian.Uint64(b[18:26])
	copy(r.SentRunningHash[:], b[26:58])
	copy(r.ReceivedRunningHash[:], b[58:90])
	return r, nil
}

// NextRunningHash is the running hash the Solidity reference ClprService uses
// (BundleLib._enqueueMessage and Step 5 of bundle verification):
//
//	h' = SHA-256(h ‖ SHA-256(serialized ClprMessagePayload))
//
// The spec text (§4.1) writes SHA-256(h ‖ payload); the Hiero-side receiver recomputes the
// BundleLib form, so that is the one that interoperates.
func NextRunningHash(prev [32]byte, payload []byte) [32]byte {
	ph := sha256.Sum256(payload)
	return sha256.Sum256(append(prev[:], ph[:]...))
}

// ServiceItem is module address(20) ‖ manifest commitment(32).
func ServiceItem(commitment [32]byte) []byte {
	return append(append([]byte{}, ModuleAddress...), commitment[:]...)
}
