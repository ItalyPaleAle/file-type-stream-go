package filetype

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// How many bytes to read ahead (at most) when reading from the stream
const readAhead = 12

// NewBuffer returns a new Buffer object that reads from the given stream
func NewBuffer(r io.Reader) *Buffer {
	return &Buffer{
		r:   r,
		buf: &bytes.Buffer{},
		eof: false,
		cur: 0,
	}
}

// Buffer implements tools to read from a readable stream and access bytes as needed
type Buffer struct {
	r   io.Reader
	buf *bytes.Buffer
	eof bool
	cur int
}

// ReadBytesOpts contains options for ReadBytes
type ReadBytesOpts struct {
	// If true, advances the current cursor by the number of bytes read
	Advance bool
	// Start reading from the given number of bytes
	Offset int
}

// Instance of ReadBytesOpts that advances the cursor
var advanceReadBytesOpts = &ReadBytesOpts{
	Advance: true,
}

// ReadBytes reads from the buffer n bytes (or less if the stream reaches EOF before)
// It returns an error in case of read error; reaching EOF does not return an error
// Note that the returned slice is valid only until the next call to read or write into the internal buffer
func (b *Buffer) ReadBytes(n int, opts *ReadBytesOpts) ([]byte, error) {
	start := b.cur
	if opts != nil && opts.Offset > 0 {
		start += opts.Offset
	}
	end := start + n

	// Check if we need to read more bytes
	missing := end - b.buf.Len()
	if missing > 0 && !b.eof {
		read := make([]byte, missing+readAhead)
		nr, err := io.ReadFull(b.r, read)
		if nr > 0 {
			nw, errW := b.buf.Write(read[:nr])
			if errW != nil {
				return nil, errW
			}
			if nw != nr {
				return nil, fmt.Errorf("read %d from the stream, but wrote %d in the internal buffer", nr, nw)
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			b.eof = true
		} else if err != nil {
			return nil, fmt.Errorf("error while reading from the stream: %w", err)
		}
	}

	if end > b.buf.Len() {
		end = b.buf.Len()
	}
	if start > end {
		start = end
	}

	if opts != nil && opts.Advance {
		b.cur = end
	}

	return b.buf.Bytes()[start:end], nil
}

// NextEqual returns true if the next len(check) bytes in the buffer (starting from the current cursor) are equal to check
// Note that while opts is variadic, at most one element will be read
func (b *Buffer) NextEqual(check []byte, opts ...*ReadBytesOpts) (bool, error) {
	if len(check) == 0 {
		return false, errors.New("parameter check is empty")
	}
	var (
		read []byte
		err  error
	)
	if len(opts) > 0 {
		read, err = b.ReadBytes(len(check), opts[0])
	} else {
		read, err = b.ReadBytes(len(check), nil)
	}
	if err != nil {
		return false, err
	}
	return bytes.Equal(read, check), nil
}

// MustNextEqual is like NextEqual but does not return errors
// It returns false in case of any error
func (b *Buffer) MustNextEqual(check []byte, opts ...*ReadBytesOpts) bool {
	res, err := b.NextEqual(check, opts...)
	return res && err == nil
}

// NextEqualString is like NextEqual, but accepts a string as value to check
func (b *Buffer) NextEqualString(check string, opts ...*ReadBytesOpts) (bool, error) {
	return b.NextEqual([]byte(check), opts...)
}

// MustNextEqualString is like NextEqualString but does not return errors
// It returns false in case of any error
func (b *Buffer) MustNextEqualString(check string, opts ...*ReadBytesOpts) bool {
	res, err := b.NextEqual([]byte(check), opts...)
	return res && err == nil
}

// NextEqualWithMask is a variant of NextEqual that applies a mask when checking for equality
// Note that while opts is variadic, at most one element will be read
func (b *Buffer) NextEqualWithMask(check []byte, mask []byte, opts ...*ReadBytesOpts) (bool, error) {
	if len(check) == 0 {
		return false, errors.New("parameter check is empty")
	}
	var (
		read []byte
		err  error
	)
	if len(opts) > 0 {
		read, err = b.ReadBytes(len(check), opts[0])
	} else {
		read, err = b.ReadBytes(len(check), nil)
	}
	if err != nil {
		return false, err
	}

	i := 0
	for i < len(read) && i < len(mask) {
		read[i] = read[i] & mask[i]
		i++
	}

	return bytes.Equal(read, check), nil
}

// MustNextEqualWithMask is like NextEqualWithMask but does not return errors
// It returns false in case of any error
func (b *Buffer) MustNextEqualWithMask(check []byte, mask []byte, opts ...*ReadBytesOpts) bool {
	res, err := b.NextEqualWithMask(check, mask, opts...)
	return res && err == nil
}

// Skip advances the current cursor by n bytes
func (b *Buffer) Skip(n int) {
	b.cur += n
}

// ResetCursor resets the cursor to the beginning of the stream
func (b *Buffer) ResetCursor() {
	b.cur = 0
}
