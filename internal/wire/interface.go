package wire

import (
	"github.com/nofish24/quic-go/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Append(b []byte, version protocol.VersionNumber) ([]byte, error)
	Length(version protocol.VersionNumber) protocol.ByteCount
}
