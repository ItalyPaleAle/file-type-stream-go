package filetype

import (
	"bytes"
	"io"
	"os"
)

// ParseOpts contains options for parsing
type ParseOpts struct {
	// Maximum number of bytes that can be read
	// Setting this to 0 uses the default value, while -1 will read till the end of the stream with no limit
	// Default: 2_097_152 bytes (2MB)
	MaxReadBytes int
}

const defaultMaxReadBytes = 2_097_152

// ParseStream detects the file type of a stream
func ParseStream(r io.Reader, o ...ParseOpts) (ext string, mime string, err error) {
	// Parse options
	opts := ParseOpts{}
	if len(o) > 1 {
		panic("cannot pass more than one ParseOpts object")
	} else if len(o) == 1 {
		opts = o[0]
	}

	// Default options
	if opts.MaxReadBytes == 0 {
		opts.MaxReadBytes = defaultMaxReadBytes
	}

	// Set a limit if needed
	if opts.MaxReadBytes > 0 {
		r = io.LimitReader(r, int64(opts.MaxReadBytes))
	}

	return parse(NewBuffer(r))
}

// ParseFile detects the file type of a file
func ParseFile(name string, o ...ParseOpts) (ext string, mime string, err error) {
	f, err := os.Open(name)
	if err != nil {
		return "", "", err
	}

	return ParseStream(f, o...)
}

// ParseBytes detects the file type of a byte slice
func ParseBytes(data []byte, o ...ParseOpts) (ext string, mime string, err error) {
	return ParseStream(bytes.NewReader(data), o...)
}
