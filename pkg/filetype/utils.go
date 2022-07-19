package filetype

import (
	"encoding/binary"
	"fmt"
	"reflect"
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

	size := reflect.ValueOf(dst).Elem().Type().Size()

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

// Converts a byte slice (with length 0-8) to an uint64, in big endian
func bytesToUintBE(b []byte, bo binary.ByteOrder) uint64 {
	if len(b) > 8 {
		return 0
	}

	var out uint64
	l := len(b)
	for i := 0; i < l; i++ {
		out |= uint64(b[i]) << ((l - i - 1) * 8)
	}

	return out
}

// Parses a sequence of 4 bytes into an ID3 "uint32 sync-safe integer"
func parseID3SyncSafeUint32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return uint32(b[0])<<21 |
		uint32(b[1])<<14 |
		uint32(b[2])<<7 |
		uint32(b[3])
}
