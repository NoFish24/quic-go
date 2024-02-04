//Lifted from Benedikt

package quic

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const DstOptsHdrLen = 2

type DstOptsHdr struct {
	NextHeader            uint8
	HeaderExtensionLength uint8
}

func DstOptsLen(datalen int) int {
	return DstOptsHdrLen + datalen
}

// AppendDestOpts min data size is 6 byte.
// data length must be multiple of 8 minus 2.
// using IPv6 destination options might required root privileges.
func AppendDestOpts(oob []byte, dataLen int) (newOob []byte, destOptsData []byte, err error) {
	const firstBlockSize = 6
	const blockSize = 8
	const minDataLen = firstBlockSize
	if dataLen < minDataLen {
		return oob, nil, fmt.Errorf("data must be at least 6 bytes: %d", dataLen)
	}
	if (dataLen-firstBlockSize)%blockSize != 0 {
		return oob, nil, fmt.Errorf("data length must be multiple of 8 minus 2: %d", dataLen)
	}
	oob, cmsgData := appendCmsg(oob, unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, DstOptsLen(dataLen))
	dstOptsHdrOffset := 0
	dstOptsHdr := (*DstOptsHdr)(unsafe.Pointer(&cmsgData[dstOptsHdrOffset]))
	dstOptsHdr.HeaderExtensionLength = uint8((dataLen - firstBlockSize) / blockSize)
	dstOptsDataOffset := dstOptsHdrOffset + DstOptsHdrLen
	return oob, cmsgData[dstOptsDataOffset:], nil
}

// AppendDestOpt adapted to work if we have preexisting data, does need formatted data in format 6 + (8n - 2) bytes, else AppendDestOpts breaks
func AppendDestOpt(destOptsData []byte, optType byte, optDataLen byte) (newDestOptsData []byte, optData []byte) {
	dstoptbuf := make([]byte, len(destOptsData)+2)
	dstoptbuf[0] = optType
	dstoptbuf[1] = optDataLen
	copy(dstoptbuf[2:], destOptsData)
	return dstoptbuf, dstoptbuf[2:]
}

func AppendPad0DestOpt(destOptsData []byte) (newDestOptsData []byte) {
	startLen := len(destOptsData)
	optTypeLen := 1
	optLen := optTypeLen
	destOptsData = append(destOptsData, make([]byte, optLen)...)
	destOptsData[startLen] = DestOptTypePad0
	return destOptsData
}

const (
	DestOptTypePad0 byte = 0
	DestOptTypePadN byte = 1
)

func AppendPadDestOpt(destOptsData []byte, padding int) (newDestOptsData []byte) {
	if padding == 1 {
		destOptsData = AppendPad0DestOpt(destOptsData)
	} else {
		destOptsData, _ = AppendDestOpt(destOptsData, DestOptTypePadN, byte(padding-2))
	}
	return destOptsData
}
