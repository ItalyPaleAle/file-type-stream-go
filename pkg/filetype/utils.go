package filetype

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// ReadBinaryOpts contains options for methods that return numbers
type ReadBinaryOpts struct {
	*ReadBytesOpts

	// Byte order; defaults to little endian if unset
	ByteOrder binary.ByteOrder
}

type uintSizes interface {
	uint8 | uint16 | uint32 | uint64
}

// GetUint reads from the buffer and returns the value as uint
// Note that only the first element in opts is considered, if present at all
func GetUint[T uintSizes](buf *Buffer, dst *T, opts ...*ReadBinaryOpts) error {
	var o *ReadBinaryOpts
	if len(opts) == 0 || opts[0] == nil {
		o = &ReadBinaryOpts{}
	} else {
		o = opts[0]
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if o.ByteOrder != nil {
		bo = o.ByteOrder
	}

	size := unsafe.Sizeof(dst)

	read, err := buf.ReadBytes(int(size), o.ReadBytesOpts)
	if err != nil {
		return err
	} else if len(read) != int(size) {
		return fmt.Errorf("not enough bytes read from buffer: got %d but required %d", len(read), size)
	}

	var res any
	switch size {
	case 1:
		res = uint8(read[0])
	case 2:
		res = bo.Uint16(read[0:2])
	case 4:
		res = bo.Uint32(read[0:4])
	case 8:
		res = bo.Uint64(read[0:8])
	}

	*dst = res.(T)

	return nil
}

// Parses a sequence of 4 bytes into an ID3 "uint32 sync-safe integer"
// See also https://stackoverflow.com/a/7913100/192024
func parseID3SyncSafeUint32(b [4]byte) uint32 {
	return uint32(b[3]&0x7F) | uint32((b[2])<<7) | uint32((b[1])<<14) | uint32((b[0])<<21)
}
