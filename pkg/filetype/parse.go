package filetype

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
)

func parse(buf *Buffer) (ext string, mime string, err error) {
	// Read the first 12 bytes to start populating the buffer
	_, err = buf.ReadBytes(12, nil)
	if err != nil {
		return
	}

	if buf.MustNextEqual([]byte{0x42, 0x4D}) {
		ext = "bmp"
		mime = "image/bmp"
		return
	}

	if buf.MustNextEqual([]byte{0x0B, 0x77}) {
		ext = "ac3"
		mime = "audio/vnd.dolby.dd-raw"
		return
	}

	if buf.MustNextEqual([]byte{0x78, 0x01}) {
		ext = "dmg"
		mime = "application/x-apple-diskimage"
		return
	}

	if buf.MustNextEqual([]byte{0x4D, 0x5A}) {
		ext = "exe"
		mime = "application/x-msdownload"
		return
	}

	if buf.MustNextEqual([]byte{0x25, 0x21}) {
		var equal bool
		if equal, err = buf.NextEqualString(" EPSF-", &ReadBytesOpts{Offset: 14}); err != nil {
			return
		} else if equal &&
			buf.MustNextEqualString("PS-Adobe-", &ReadBytesOpts{Offset: 2}) {
			ext = "eps"
			mime = "application/eps"
			return
		}

		ext = "ps"
		mime = "application/postscript"
		return
	}

	if buf.MustNextEqual([]byte{0x1F, 0xA0}) ||
		buf.MustNextEqual([]byte{0x1F, 0x9D}) {
		ext = "Z"
		mime = "application/x-compress"
		return
	}

	if buf.MustNextEqual([]byte{0x47, 0x49, 0x46}) {
		ext = "gif"
		mime = "image/gif"
		return
	}

	if buf.MustNextEqual([]byte{0xFF, 0xD8, 0xFF}) {
		ext = "jpg"
		mime = "image/jpeg"
		return
	}

	if buf.MustNextEqual([]byte{0x49, 0x49, 0xBC}) {
		ext = "jxr"
		mime = "image/vnd.ms-photo"
		return
	}

	if buf.MustNextEqual([]byte{0x1F, 0x8B, 0x8}) {
		ext = "gz"
		mime = "application/gzip"
		return
	}

	if buf.MustNextEqual([]byte{0x42, 0x5A, 0x68}) {
		ext = "bz2"
		mime = "application/x-bzip2"
		return
	}

	if buf.MustNextEqualString("ID3") {
		// Skip ID3 header until the header size
		var read []byte
		read, err = buf.ReadBytes(4, &ReadBytesOpts{Offset: 6, Advance: true})
		if err != nil {
			return
		} else if len(read) != 4 {
			// Undetermined file type
			return
		}
		headerLen := parseID3SyncSafeUint32(read[0:4])
		if headerLen < 4 || headerLen > math.MaxInt32 {
			// Undetermined file type
			return
		}

		// Read the amount of bytes from the header to check if we can get that much data, and advance
		read, err = buf.ReadBytes(int(headerLen), advanceReadBytesOpts)
		if err != nil {
			return
		} else if len(read) < int(headerLen) || buf.eof {
			// We reached EOF before we could read the entire header
			// Guess file type based on ID3 header for backward compatibility
			ext = "mp3"
			mime = "audio/mpeg"
			return
		}

		// Recursion, after having skipped ID3 header
		return parse(buf)
	}

	if buf.MustNextEqualString("MP+") {
		ext = "mpc"
		mime = "audio/x-musepack"
		return
	}

	if buf.MustNextEqual([]byte{0x43, 0x57, 0x53}) ||
		buf.MustNextEqual([]byte{0x46, 0x57, 0x53}) {
		ext = "swf"
		mime = "application/x-shockwave-flash"
		return
	}

	if buf.MustNextEqualString("FLIF") {
		ext = "flif"
		mime = "image/flif"
		return
	}

	if buf.MustNextEqualString("8BPS") {
		ext = "psd"
		mime = "image/vnd.adobe.photoshop"
		return
	}

	if buf.MustNextEqualString("WEBP", &ReadBytesOpts{Offset: 8}) {
		ext = "webp"
		mime = "image/webp"
		return
	}

	// Musepack, SV8
	if buf.MustNextEqualString("MPCK") {
		ext = "mpc"
		mime = "audio/x-musepack"
		return
	}

	if buf.MustNextEqualString("FORM") {
		ext = "aif"
		mime = "audio/aiff"
		return
	}

	if buf.MustNextEqualString("icns") {
		ext = "icns"
		mime = "image/icns"
		return
	}

	// Zip-based file formats
	// Need to be before the `zip` check
	if buf.MustNextEqual([]byte{0x50, 0x4B, 0x3, 0x4}) { // Local file header signature
		var (
			read             []byte
			compressedSize   uint32
			uncompressedSize uint32
			filenameLength   uint16
			extraFieldLength uint16
			filename         string
		)
		for {
			read, err = buf.ReadBytes(30, &ReadBytesOpts{
				Advance: true,
			})
			if err != nil {
				return
			}
			if len(read) < 30 && buf.eof {
				// We reached EOF
				break
			}

			// https://en.wikipedia.org/wiki/Zip_(file_format)#File_headers
			compressedSize = binary.LittleEndian.Uint32(read[18:22])
			uncompressedSize = binary.LittleEndian.Uint32(read[22:26])
			filenameLength = binary.LittleEndian.Uint16(read[26:28])
			extraFieldLength = binary.LittleEndian.Uint16(read[28:30])

			read, err = buf.ReadBytes(int(filenameLength), advanceReadBytesOpts)
			if err != nil {
				return
			}
			if int(filenameLength) > len(read) {
				break
			}
			filename = string(read)
			buf.Skip(int(extraFieldLength))

			// Assumes signed `.xpi` from addons.mozilla.org
			if filename == "META-INF/mozilla.rsa" {
				ext = "xpi"
				mime = "application/x-xpinstall"
				return
			}

			if strings.HasSuffix(filename, ".rels") || strings.HasSuffix(filename, ".xml") {
				check := filename
				if idx := strings.IndexByte(filename, '/'); idx > -1 {
					check = filename[0:idx]
				}
				switch check {
				case "word":
					ext = "docx"
					mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
					return
				case "ppt":
					ext = "pptx"
					mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
					return
				case "xl":
					ext = "xlsx"
					mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
					return
				}
			}

			if strings.HasPrefix(filename, "xl/") {
				ext = "xlsx"
				mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
				return
			}

			if strings.HasPrefix(filename, "3D/") || strings.HasPrefix(filename, ".model") {
				ext = "3mf"
				mime = "model/3mf"
				return
			}

			// The docx, xlsx and pptx file types extend the Office Open XML file format:
			// https://en.wikipedia.org/wiki/Office_Open_XML_file_formats
			// We look for:
			// - one entry named '[Content_Types].xml' or '_rels/.rels',
			// - one entry indicating specific type of file.
			// MS Office, OpenOffice and LibreOffice may put the parts in different order, so the check should not rely on it.
			if filename == "mimetype" && compressedSize == uncompressedSize {
				read, err = buf.ReadBytes(int(compressedSize), advanceReadBytesOpts)
				if err != nil {
					return
				}

				switch strings.TrimSpace(string(read)) {
				case "application/epub+zip":
					ext = "epub"
					mime = "application/epub+zip"
					return
				case "application/vnd.oasis.opendocument.text":
					ext = "odt"
					mime = "application/vnd.oasis.opendocument.text"
					return
				case "application/vnd.oasis.opendocument.spreadsheet":
					ext = "ods"
					mime = "application/vnd.oasis.opendocument.spreadsheet"
					return
				case "application/vnd.oasis.opendocument.presentation":
					ext = "odp"
					mime = "application/vnd.oasis.opendocument.presentation"
					return
				}
			}

			// Try to find next header manually when current one is corrupted
			if compressedSize == 0 {
				nextHeaderIndex := -1
				for nextHeaderIndex < 0 {
					read, err = buf.ReadBytes(4000, nil)
					if err != nil {
						return
					}
					if len(read) == 0 && buf.eof {
						break
					}
					nextHeaderIndex = bytes.Index(read, []byte{0x50, 0x4B, 0x03, 0x04})
					if nextHeaderIndex > -1 {
						buf.Skip(nextHeaderIndex)
					} else {
						buf.Skip(len(read))
					}
				}
			} else {
				// Check for overflow on 32-bit systems, and return with no result
				if compressedSize > math.MaxInt32 {
					return
				}
				buf.Skip(int(compressedSize))
			}
		}

		ext = "zip"
		mime = "application/zip"
		return
	}

	if buf.MustNextEqualString("OggS") {
		// This is an OGG container
		var read []byte
		read, err = buf.ReadBytes(8, &ReadBytesOpts{Offset: 28})
		if err != nil {
			return
		}

		// Needs to be before `ogg` check
		if bytes.HasPrefix(read, []byte{0x4F, 0x70, 0x75, 0x73, 0x48, 0x65, 0x61, 0x64}) {
			ext = "opus"
			mime = "audio/opus"
			return
		}

		// If ' theora' in header.
		if bytes.HasPrefix(read, []byte{0x80, 0x74, 0x68, 0x65, 0x6F, 0x72, 0x61}) {
			ext = "ogv"
			mime = "video/ogg"
			return
		}

		// If '\x01video' in header.
		if bytes.HasPrefix(read, []byte{0x01, 0x76, 0x69, 0x64, 0x65, 0x6F, 0x00}) {
			ext = "ogm"
			mime = "video/ogg"
			return
		}

		// If ' FLAC' in header  https://xiph.org/flac/faq.html
		if bytes.HasPrefix(read, []byte{0x7F, 0x46, 0x4C, 0x41, 0x43}) {
			ext = "oga"
			mime = "audio/ogg"
			return
		}

		// 'Speex  ' in header https://en.wikipedia.org/wiki/Speex
		if bytes.HasPrefix(read, []byte{0x53, 0x70, 0x65, 0x65, 0x78, 0x20, 0x20}) {
			ext = "spx"
			mime = "audio/ogg"
			return
		}

		// If '\x01vorbis' in header
		if bytes.HasPrefix(read, []byte{0x01, 0x76, 0x6F, 0x72, 0x62, 0x69, 0x73}) {
			ext = "ogg"
			mime = "audio/ogg"
			return
		}

		// Default OGG container https://www.iana.org/assignments/media-types/application/ogg
		ext = "ogx"
		mime = "application/ogg"
		return
	}

	if buf.MustNextEqual([]byte{0x50, 0x4B}) {
		var read []byte
		read, err = buf.ReadBytes(2, nil)
		if err != nil {
			return
		}
		if (read[0] == 0x3 || read[0] == 0x5 || read[0] == 0x7) &&
			(read[1] == 0x4 || read[1] == 0x6 || read[1] == 0x8) {
			ext = "zip"
			mime = "application/zip"
			return
		}
	}

	// File Type Box (https://en.wikipedia.org/wiki/ISO_base_media_file_format)
	// It's not required to be first, but it's recommended to be. Almost all ISO base media files start with `ftyp` box.
	if buf.MustNextEqualString("ftyp", &ReadBytesOpts{Offset: 4}) {
		// `ftyp` box must contain a brand major identifier, which must consist of ISO 8859-1 printable characters.
		// Here we check for 8859-1 printable characters (for simplicity, it's a mask which also catches one non-printable character).
		var read []byte
		read, err = buf.ReadBytes(4, &ReadBytesOpts{
			Advance: true,
			Offset:  8,
		})
		if err != nil {
			return
		}
		if len(read) == 4 && (read[0]&0x60 != 0) {
			for i := 0; i < len(read); i++ {
				if read[i]&0x60 == 0 || read[i] == 0x00 {
					read[i] = 0x20
				}
			}
			brandMajor := string(bytes.TrimSpace(read))
			switch brandMajor {
			case "avif", "avis":
				ext = "avif"
				mime = "image/avif"
				return
			case "mif1":
				ext = "heic"
				mime = "image/heif"
				return
			case "msf1":
				ext = "heic"
				mime = "image/heif-sequence"
				return
			case "heic", "heix":
				ext = "heic"
				mime = "image/heic"
				return
			case "hevc", "hevx":
				ext = "heic"
				mime = "image/heic-sequence"
				return
			case "qt":
				ext = "mov"
				mime = "video/quicktime"
				return
			case "M4V", "M4VH", "M4VP":
				ext = "m4v"
				mime = "video/x-m4v"
				return
			case "M4P":
				ext = "m4p"
				mime = "video/mp4"
				return
			case "M4B":
				ext = "m4b"
				mime = "audio/mp4"
				return
			case "M4A":
				ext = "m4a"
				mime = "audio/x-m4a"
				return
			case "F4V":
				ext = "f4v"
				mime = "video/mp4"
				return
			case "F4P":
				ext = "f4p"
				mime = "video/mp4"
				return
			case "F4A":
				ext = "f4a"
				mime = "audio/mp4"
				return
			case "F4B":
				ext = "f4b"
				mime = "audio/mp4"
				return
			case "crx":
				ext = "cr3"
				mime = "image/x-canon-cr3"
				return
			default:
				if strings.HasPrefix(brandMajor, "3g") {
					if strings.HasPrefix(brandMajor, "3g2") {
						ext = "3g2"
						mime = "video/3gpp2"
						return
					}

					ext = "3gp"
					mime = "video/3gpp"
					return
				}

				ext = "mp4"
				mime = "video/mp4"
				return
			}
		}
	}

	if buf.MustNextEqualString("MThd") {
		ext = "mid"
		mime = "audio/midi"
		return
	}

	if buf.MustNextEqualString("wOFF") &&
		(buf.MustNextEqual([]byte{0x00, 0x01, 0x00, 0x00}, &ReadBytesOpts{Offset: 4}) ||
			buf.MustNextEqualString("OTTO", &ReadBytesOpts{Offset: 4})) {
		ext = "woff"
		mime = "font/woff"
		return
	}

	if buf.MustNextEqualString("wOF2") &&
		(buf.MustNextEqual([]byte{0x00, 0x01, 0x00, 0x00}, &ReadBytesOpts{Offset: 4}) ||
			buf.MustNextEqualString("OTTO", &ReadBytesOpts{Offset: 4})) {
		ext = "woff2"
		mime = "font/woff2"
		return
	}

	if buf.MustNextEqual([]byte{0xD4, 0xC3, 0xB2, 0xA1}) || buf.MustNextEqual([]byte{0xA1, 0xB2, 0xC3, 0xD4}) {
		ext = "pcap"
		mime = "application/vnd.tcpdump.pcap"
		return
	}

	// Sony DSD Stream File (DSF)
	if buf.MustNextEqualString("DSD ") {
		ext = "dsf"
		mime = "audio/x-dsf"
		return
	}

	if buf.MustNextEqualString("LZIP") {
		ext = "lz"
		mime = "application/x-lzip"
		return
	}

	if buf.MustNextEqualString("fLaC") {
		ext = "flac"
		mime = "audio/x-flac"
		return
	}

	if buf.MustNextEqual([]byte{0x42, 0x50, 0x47, 0xFB}) {
		ext = "bpg"
		mime = "image/bpg"
		return
	}

	if buf.MustNextEqualString("wvpk") {
		ext = "wv"
		mime = "audio/wavpack"
		return
	}

	if buf.MustNextEqualString("%PDF") {
		var read []byte
		read, err = buf.ReadBytes(10*1024*1024, &ReadBytesOpts{
			Advance: true,
			Offset:  1350,
		})
		if err != nil {
			return
		}

		// Check if this is an Adobe Illustrator file
		if bytes.Contains(read, []byte("AIPrivateData")) {
			ext = "ai"
			mime = "application/postscript"
			return
		}

		// Assume this is just a normal PDF
		ext = "pdf"
		mime = "application/pdf"
		return
	}

	if buf.MustNextEqual([]byte{0x00, 0x61, 0x73, 0x6D}) {
		ext = "wasm"
		mime = "application/wasm"
		return
	}

	// TIFF, little-endian type
	if buf.MustNextEqual([]byte{0x49, 0x49}) {
		ext, mime, err = readTiffHeader(buf, binary.LittleEndian)
		if err != nil || (ext != "" && mime != "") {
			return
		}
		buf.ResetCursor()
	}

	// TIFF, big-endian type
	if buf.MustNextEqual([]byte{0x4D, 0x4D}) {
		ext, mime, err = readTiffHeader(buf, binary.BigEndian)
		if err != nil || (ext != "" && mime != "") {
			return
		}
		buf.ResetCursor()
	}

	if buf.MustNextEqualString("MAC ") {
		ext = "ape"
		mime = "audio/ape"
		return
	}

	// https://github.com/threatstack/libmagic/blob/master/magic/Magdir/matroska
	if buf.MustNextEqual([]byte{0x1A, 0x45, 0xDF, 0xA3}) { // Root element: EBML
		var l uint64
		_, l, err = readMkvElement(buf)
		if err != nil {
			return
		}
		var docType []byte
		docType, err = readMkvChildren(buf, l)
		if err != nil {
			return
		}

		switch string(docType) {
		case "webm":
			ext = "webm"
			mime = "video/webm"
			return

		case "matroska":
			ext = "mkv"
			mime = "video/x-matroska"
			return

		default:
			return
		}
	}

	// RIFF file format which might be AVI, WAV, QCP, etc
	if buf.MustNextEqual([]byte{0x52, 0x49, 0x46, 0x46}) {
		if buf.MustNextEqual([]byte{0x41, 0x56, 0x49}, &ReadBytesOpts{Offset: 8}) {
			ext = "avi"
			mime = "video/vnd.avi"
			return
		}

		if buf.MustNextEqual([]byte{0x57, 0x41, 0x56, 0x45}, &ReadBytesOpts{Offset: 8}) {
			ext = "wav"
			mime = "audio/vnd.wave"
			return
		}

		// QLCM, QCP file
		if buf.MustNextEqual([]byte{0x51, 0x4C, 0x43, 0x4D}, &ReadBytesOpts{Offset: 8}) {
			ext = "qcp"
			mime = "audio/qcelp"
			return
		}
	}

	if buf.MustNextEqualString("SQLi") {
		ext = "sqlite"
		mime = "application/x-sqlite3"
		return
	}

	if buf.MustNextEqual([]byte{0x4E, 0x45, 0x53, 0x1A}) {
		ext = "nes"
		mime = "application/x-nintendo-nes-rom"
		return
	}

	if buf.MustNextEqualString("Cr24") {
		ext = "crx"
		mime = "application/x-google-chrome-extension"
		return
	}

	if buf.MustNextEqualString("MSCF") || buf.MustNextEqualString("ISc(") {
		ext = "cab"
		mime = "application/vnd.ms-cab-compressed"
		return
	}

	if buf.MustNextEqual([]byte{0xED, 0xAB, 0xEE, 0xDB}) {
		ext = "rpm"
		mime = "application/x-rpm"
		return
	}

	if buf.MustNextEqual([]byte{0xC5, 0xD0, 0xD3, 0xC6}) {
		ext = "eps"
		mime = "application/eps"
		return
	}

	if buf.MustNextEqual([]byte{0x28, 0xB5, 0x2F, 0xFD}) {
		ext = "zst"
		mime = "application/zstd"
		return
	}

	if buf.MustNextEqual([]byte{0x7F, 0x45, 0x4C, 0x46}) {
		ext = "elf"
		mime = "application/x-elf"
		return
	}

	if buf.MustNextEqual([]byte{0x4F, 0x54, 0x54, 0x4F, 0x00}) {
		ext = "otf"
		mime = "font/otf"
		return
	}

	if buf.MustNextEqualString("#!AMR") {
		ext = "amr"
		mime = "audio/amr"
		return
	}

	if buf.MustNextEqualString("{\\rtf") {
		ext = "rtf"
		mime = "application/rtf"
		return
	}

	if buf.MustNextEqual([]byte{0x46, 0x4C, 0x56, 0x01}) {
		ext = "flv"
		mime = "video/x-flv"
		return
	}

	if buf.MustNextEqualString("IMPM") {
		ext = "it"
		mime = "audio/x-it"
		return
	}

	if buf.MustNextEqualString("-lh0-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh1-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh2-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh3-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh4-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh5-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh6-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lh7-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lzs-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lz4-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lz5-", &ReadBytesOpts{Offset: 2}) ||
		buf.MustNextEqualString("-lhd-", &ReadBytesOpts{Offset: 2}) {
		ext = "lzh"
		mime = "application/x-lzh-compressed"
		return
	}

	// MPEG program stream (PS or MPEG-PS)
	if buf.MustNextEqual([]byte{0x00, 0x00, 0x01, 0xBA}) {
		//  MPEG-PS, MPEG-1 Part 1
		if buf.MustNextEqualWithMask([]byte{0x21}, []byte{0xF1}, &ReadBytesOpts{Offset: 4}) {
			ext = "mpg" // May also be .ps, .mpeg
			mime = "video/MP1S"
			return
		}

		// MPEG-PS, MPEG-2 Part 1
		if buf.MustNextEqualWithMask([]byte{0x44}, []byte{0xC4}, &ReadBytesOpts{Offset: 4}) {
			ext = "mpg" // May also be .mpg, .m2p, .vob or .sub
			mime = "video/MP2P"
			return
		}
	}

	if buf.MustNextEqualString("ITSF") {
		ext = "chm"
		mime = "application/vnd.ms-htmlhelp"
		return
	}

	if buf.MustNextEqual([]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) {
		ext = "xz"
		mime = "application/x-xz"
		return
	}

	if buf.MustNextEqualString("<?xml ") {
		ext = "xml"
		mime = "application/xml"
		return
	}

	if buf.MustNextEqual([]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		ext = "7z"
		mime = "application/x-7z-compressed"
		return
	}

	if buf.MustNextEqual([]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) ||
		buf.MustNextEqual([]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01}) {
		ext = "rar"
		mime = "application/x-rar-compressed"
		return
	}

	if buf.MustNextEqualString("solid ") {
		ext = "stl"
		mime = "model/stl"
		return
	}

	if buf.MustNextEqualString("BLENDER") {
		ext = "blend"
		mime = "application/x-blender"
		return
	}

	if buf.MustNextEqualString("!<arch>") {
		var read []byte
		read, err = buf.ReadBytes(13, &ReadBytesOpts{Offset: 8})
		if err != nil {
			return
		}
		if string(read) == "debian-binary" {
			ext = "deb"
			mime = "application/x-deb"
			return
		}
		ext = "ar"
		mime = "application/x-unix-archive"
		return
	}

	if buf.MustNextEqual([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		// APNG format (https://wiki.mozilla.org/APNG_Specification)
		// 1. Find the first IDAT (image data) chunk (49 44 41 54)
		// 2. Check if there is an "acTL" chunk before the IDAT one (61 63 54 4C)

		// Offset calculated as follows:
		// - 8 bytes: PNG signature
		// - 4 (length) + 4 (chunk type) + 13 (chunk data) + 4 (CRC): IHDR chunk

		buf.Skip(8) // ignore PNG signature
		var (
			length uint32
			read   []byte
		)
		for {
			read, err = buf.ReadBytes(8, advanceReadBytesOpts)
			if err != nil {
				return
			}
			if len(read) < 8 || buf.eof {
				break // Reached EOF
			}

			length = binary.BigEndian.Uint32(read[0:4])
			if length < 0 || length > math.MaxInt32 {
				return // Invalid chunk length
			}

			switch string(read[4:8]) {
			case "IDAT":
				ext = "png"
				mime = "image/png"
				return
			case "acTL":
				ext = "apng"
				mime = "image/apng"
				return
			}

			buf.Skip(int(length + 4)) // Ignore chunk-data + CRC
		}

		ext = "png"
		mime = "image/png"
		return
	}

	if buf.MustNextEqual([]byte{0x41, 0x52, 0x52, 0x4F, 0x57, 0x31, 0x00, 0x00}) {
		ext = "arrow"
		mime = "application/x-apache-arrow"
		return
	}

	if buf.MustNextEqual([]byte{0x67, 0x6C, 0x54, 0x46, 0x02, 0x00, 0x00, 0x00}) {
		ext = "glb"
		mime = "model/gltf-binary"
		return
	}

	// `mov` format variants
	if buf.MustNextEqual([]byte{0x66, 0x72, 0x65, 0x65}, &ReadBytesOpts{Offset: 4}) || // `free`
		buf.MustNextEqual([]byte{0x6D, 0x64, 0x61, 0x74}, &ReadBytesOpts{Offset: 4}) || // `mdat` MJPEG
		buf.MustNextEqual([]byte{0x6D, 0x6F, 0x6F, 0x76}, &ReadBytesOpts{Offset: 4}) || // `moov`
		buf.MustNextEqual([]byte{0x77, 0x69, 0x64, 0x65}, &ReadBytesOpts{Offset: 4}) { // `wide`
		ext = "mov"
		mime = "video/quicktime"
		return
	}

	if buf.MustNextEqual([]byte{0xEF, 0xBB, 0xBF}) && // UTF-8BOM
		buf.MustNextEqualString("<?xml", &ReadBytesOpts{Offset: 3}) {
		ext = "xml"
		mime = "application/xml"
		return
	}

	if buf.MustNextEqual([]byte{0x49, 0x49, 0x52, 0x4F, 0x08, 0x00, 0x00, 0x00, 0x18}) {
		ext = "orf"
		mime = "image/x-olympus-orf"
		return
	}

	if buf.MustNextEqualString("gimp xcf ") {
		ext = "xcf"
		mime = "image/x-xcf"
		return
	}

	if buf.MustNextEqual([]byte{0x49, 0x49, 0x55, 0x00, 0x18, 0x00, 0x00, 0x00, 0x88, 0xE7, 0x74, 0xD8}) {
		ext = "rw2"
		mime = "image/x-panasonic-rw2"
		return
	}

	// ASF_Header_Object first 80 bytes
	if buf.MustNextEqual([]byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9}) {
		buf.Skip(30)

		// Search for header should be in first 1KB of file.
		var (
			read []byte
			size uint64
		)
		for !buf.eof && buf.cur < 1024 {
			read, err = buf.ReadBytes(24, advanceReadBytesOpts)
			if err != nil {
				return
			}
			if len(read) < 24 {
				break // EOF
			}

			size = binary.LittleEndian.Uint64(read[16:24])
			if size == 0 || size > math.MaxInt32 {
				break
			}

			if bytes.Equal(read[0:16], []byte{0x91, 0x07, 0xDC, 0xB7, 0xB7, 0xA9, 0xCF, 0x11, 0x8E, 0xE6, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65}) {
				// Sync on Stream-Properties-Object (B7DC0791-A9B7-11CF-8EE6-00C00C205365)
				read, err = buf.ReadBytes(16, advanceReadBytesOpts)
				if err != nil {
					return
				}

				if bytes.Equal(read, []byte{0x40, 0x9E, 0x69, 0xF8, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B}) {
					// Found audio:
					ext = "asf"
					mime = "audio/x-ms-asf"
					return
				}

				if bytes.Equal(read, []byte{0xC0, 0xEF, 0x19, 0xBC, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B}) {
					// Found video:
					ext = "asf"
					mime = "video/x-ms-asf"
					return
				}

				break
			}

			buf.Skip(int(size) - 24)
		}

		// Default to ASF generic extension
		ext = "asf"
		mime = "application/vnd.ms-asf"
		return
	}

	if buf.MustNextEqual([]byte{0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A}) {
		ext = "ktx"
		mime = "image/ktx"
		return
	}

	if ((buf.MustNextEqual([]byte{0x7E, 0x10, 0x04}) || buf.MustNextEqual([]byte{0x7E, 0x18, 0x04})) &&
		buf.MustNextEqual([]byte{0x30, 0x4D, 0x49, 0x45}, &ReadBytesOpts{Offset: 4})) {
		ext = "mie"
		mime = "application/x-mie"
		return
	}

	if buf.MustNextEqual([]byte{0x27, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, &ReadBytesOpts{Offset: 2}) {
		ext = "shp"
		mime = "application/x-esri-shape"
		return
	}

	if buf.MustNextEqual([]byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}) {
		// JPEG-2000 family
		var read []byte
		read, err = buf.ReadBytes(4, &ReadBytesOpts{Offset: 20})
		if err != nil {
			return
		}
		switch string(read) {
		case "jp2 ":
			ext = "jp2"
			mime = "image/jp2"
			return
		case "jpx ":
			ext = "jpx"
			mime = "image/jpx"
			return
		case "jpm ":
			ext = "jpm"
			mime = "image/jpm"
			return
		case "mjp2":
			ext = "mj2"
			mime = "image/mj2"
			return
		default:
			return
		}
	}

	if buf.MustNextEqual([]byte{0xFF, 0x0A}) ||
		buf.MustNextEqual([]byte{0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A}) {
		ext = "jxl"
		mime = "image/jxl"
		return
	}

	if buf.MustNextEqual([]byte{0xFE, 0xFF, 0, 60, 0, 63, 0, 120, 0, 109, 0, 108}) || // UTF-16-BOM-LE
		buf.MustNextEqual([]byte{0xFF, 0xFE, 60, 0, 63, 0, 120, 0, 109, 0, 108, 0}) { // UTF-16-BOM-LE
		ext = "xml"
		mime = "application/xml"
		return
	}

	// -- Unsafe signatures --

	if buf.MustNextEqual([]byte{0x0, 0x0, 0x1, 0xBA}) || buf.MustNextEqual([]byte{0x0, 0x0, 0x1, 0xB3}) {
		ext = "mpg"
		mime = "video/mpeg"
		return
	}

	if buf.MustNextEqual([]byte{0x00, 0x01, 0x00, 0x00, 0x00}) {
		ext = "ttf"
		mime = "font/ttf"
		return
	}

	if buf.MustNextEqual([]byte{0x00, 0x00, 0x01, 0x00}) {
		ext = "ico"
		mime = "image/x-icon"
		return
	}

	if buf.MustNextEqual([]byte{0x00, 0x00, 0x02, 0x00}) {
		ext = "cur"
		mime = "image/x-icon"
		return
	}

	if buf.MustNextEqual([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
		// Detected Microsoft Compound File Binary File (MS-CFB) Format.
		ext = "cfb"
		mime = "application/x-cfb"
		return
	}

	// Increase sample size from 12 to 256
	_, err = buf.ReadBytes(256, nil)
	if err != nil {
		return
	}

	if buf.MustNextEqualString("BEGIN:VCARD") {
		ext = "vcf"
		mime = "text/vcard"
		return
	}

	if buf.MustNextEqualString("BEGIN:VCALENDAR") {
		ext = "ics"
		mime = "text/calendar"
		return
	}

	// `raf` is here just to keep all the raw image detectors together.
	if buf.MustNextEqualString("FUJIFILMCCD-RAW") {
		ext = "raf"
		mime = "image/x-fujifilm-raf"
		return
	}

	if buf.MustNextEqualString("Extended Module:") {
		ext = "xm"
		mime = "audio/x-xm"
		return
	}

	if buf.MustNextEqualString("Creative Voice File") {
		ext = "voc"
		mime = "audio/x-voc"
		return
	}

	if buf.MustNextEqual([]byte{0x04, 0x00, 0x00, 0x00}) && buf.buf.Len() >= 16 { // Rough & quick check Pickle/ASAR
		var jsonSize uint32
		err = GetUint(buf, &jsonSize, &ReadBinaryOpts{
			ByteOrder: binary.LittleEndian,
			ReadBytesOpts: &ReadBytesOpts{
				Advance: true,
				Offset:  12,
			},
		})
		if err != nil {
			return
		}
		if jsonSize > 12 && jsonSize <= math.MaxInt32 && buf.buf.Len() >= int(jsonSize+16) {
			var read []byte
			read, err = buf.ReadBytes(int(jsonSize), &ReadBytesOpts{})
			if err != nil {
				return
			}
			if len(read) == int(jsonSize) {
				var j map[string]any
				err = json.Unmarshal(read, &j)
				// Check if Pickle is ASAR
				if err == nil {
					if _, ok := j["files"]; ok { // Final check, assuring Pickle/ASAR format
						ext = "asar"
						mime = "application/x-asar"
						return
					}
				}
			}
		}
	}

	if buf.MustNextEqual([]byte{0x06, 0x0E, 0x2B, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0D, 0x01, 0x02, 0x01, 0x01, 0x02}) {
		ext = "mxf"
		mime = "application/mxf"
		return
	}

	if buf.MustNextEqualString("SCRM", &ReadBytesOpts{Offset: 44}) {
		ext = "s3m"
		mime = "audio/x-s3m"
		return
	}

	// Raw MPEG-2 transport stream (188-byte packets)
	if buf.MustNextEqual([]byte{0x47}) && buf.MustNextEqual([]byte{0x47}, &ReadBytesOpts{Offset: 188}) {
		ext = "mts"
		mime = "video/mp2t"
		return
	}

	// Blu-ray Disc Audio-Video (BDAV) MPEG-2 transport stream has 4-byte TP_extra_header before each 188-byte packet
	if buf.MustNextEqual([]byte{0x47}, &ReadBytesOpts{Offset: 4}) && buf.MustNextEqual([]byte{0x47}, &ReadBytesOpts{Offset: 196}) {
		ext = "mts"
		mime = "video/mp2t"
		return
	}

	if buf.MustNextEqual([]byte{0x42, 0x4F, 0x4F, 0x4B, 0x4D, 0x4F, 0x42, 0x49}, &ReadBytesOpts{Offset: 60}) {
		ext = "mobi"
		mime = "application/x-mobipocket-ebook"
		return
	}

	if buf.MustNextEqual([]byte{0x44, 0x49, 0x43, 0x4D}, &ReadBytesOpts{Offset: 128}) {
		ext = "dcm"
		mime = "application/dicom"
		return
	}

	if buf.MustNextEqual([]byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}) {
		ext = "lnk"
		mime = "application/x.ms.shortcut" // Invented by us
		return
	}

	if buf.MustNextEqual([]byte{0x62, 0x6F, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x61, 0x72, 0x6B, 0x00, 0x00, 0x00, 0x00}) {
		ext = "alias"
		mime = "application/x.apple.alias" // Invented by us
		return
	}

	if buf.MustNextEqual([]byte{0x4C, 0x50}, &ReadBytesOpts{Offset: 34}) &&
		(buf.MustNextEqual([]byte{0x00, 0x00, 0x01}, &ReadBytesOpts{Offset: 8}) ||
			buf.MustNextEqual([]byte{0x01, 0x00, 0x02}, &ReadBytesOpts{Offset: 8}) ||
			buf.MustNextEqual([]byte{0x02, 0x00, 0x02}, &ReadBytesOpts{Offset: 8})) {
		ext = "eot"
		mime = "application/vnd.ms-fontobject"
		return
	}

	if buf.MustNextEqual([]byte{0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5, 0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D}) {
		ext = "indd"
		mime = "application/x-indesign"
		return
	}

	// Increase sample size from 256 to 512
	_, err = buf.ReadBytes(512, nil)
	if err != nil {
		return
	}

	// Requires a buffer size of 512 bytes
	if tarHeaderChecksumMatches(buf, 0) {
		ext = "tar"
		mime = "application/x-tar"
		return
	}

	if buf.MustNextEqual([]byte{0xFF, 0xFE, 0xFF, 0x0E, 0x53, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x74, 0x00, 0x63, 0x00, 0x68, 0x00, 0x55, 0x00, 0x70, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x65, 0x00, 0x6C, 0x00}) {
		ext = "skp"
		mime = "application/vnd.sketchup.skp"
		return
	}

	if buf.MustNextEqualString("-----BEGIN PGP MESSAGE-----") {
		ext = "pgp"
		mime = "application/pgp-encrypted"
		return
	}

	// Check MPEG 1 or 2 Layer 3 header, or 'layer 0' for ADTS (MPEG sync-word 0xFFE)
	if buf.MustNextEqualWithMask([]byte{0xFF, 0xE0}, []byte{0xFF, 0xE0}) {
		if buf.MustNextEqualWithMask([]byte{0x10}, []byte{0x16}, &ReadBytesOpts{Offset: 1}) {
			// Check for (ADTS) MPEG-2
			if buf.MustNextEqualWithMask([]byte{0x08}, []byte{0x08}, &ReadBytesOpts{Offset: 1}) {
				ext = "aac"
				mime = "audio/aac"
				return
			}

			// Must be (ADTS) MPEG-4
			ext = "aac"
			mime = "audio/aac"
			return
		}

		// MPEG 1 or 2 Layer 3 header
		// Check for MPEG layer 3
		if buf.MustNextEqualWithMask([]byte{0x02}, []byte{0x06}, &ReadBytesOpts{Offset: 1}) {
			ext = "mp3"
			mime = "audio/mpeg"
			return
		}

		// Check for MPEG layer 2
		if buf.MustNextEqualWithMask([]byte{0x04}, []byte{0x06}, &ReadBytesOpts{Offset: 1}) {
			ext = "mp2"
			mime = "audio/mpeg"
			return
		}

		// Check for MPEG layer 1
		if buf.MustNextEqualWithMask([]byte{0x06}, []byte{0x06}, &ReadBytesOpts{Offset: 1}) {
			ext = "mp1"
			mime = "audio/mpeg"
			return
		}
	}

	/*!!!!!!!!

	if buf.MustNextEqual([]byte{}) {
		ext = ""
		mime = ""
		return
	}

	if buf.MustNextEqualString("") {
		ext = ""
		mime = ""
		return
	}

	/*!!!!!!!!*/

	return
}

func tarHeaderChecksumMatches(buf *Buffer, offset int) bool {
	// Requires a 512-byte buffer
	read, err := buf.ReadBytes(512, &ReadBytesOpts{Offset: offset})
	if err != nil || len(read) < 512 {
		return false
	}

	// Read sum in header
	start := 148
	end := 154
	idx := bytes.IndexByte(read[start:end], 0x00)
	if idx > -1 {
		end = start + idx
	}
	readSum, err := strconv.ParseUint(
		strings.TrimSpace(string(read[start:end])),
		8, 64,
	)
	if err != nil {
		return false
	}

	// Initialize signed bit sum
	var sum uint64 = 8 * 0x20

	for i := offset; i < offset+148; i++ {
		sum += uint64(read[i])
	}

	for i := offset + 156; i < offset+512; i++ {
		sum += uint64(read[i])
	}

	return readSum == sum
}

func readTiffHeader(buf *Buffer, bo binary.ByteOrder) (ext string, mime string, err error) {
	var read []byte
	read, err = buf.ReadBytes(10, &ReadBytesOpts{
		Offset: 2,
	})
	if err != nil || len(read) < 10 {
		return
	}

	version := bo.Uint16(read[0:2])
	ifdOffset := bo.Uint32(read[2:6])

	if version == 42 {
		// TIFF file header
		if ifdOffset >= 6 && len(read) >= 8 &&
			string(read[6:8]) == "CR" {
			ext = "cr2"
			mime = "image/x-canon-cr2"
			return
		}
		if ifdOffset >= 8 && len(read) >= 10 &&
			(bytes.Equal(read[6:10], []byte{0x1C, 0x00, 0xFE, 0x00}) ||
				bytes.Equal(read[6:10], []byte{0x1F, 0x00, 0x0B, 0x00})) {
			ext = "nef"
			mime = "image/x-nikon-nef"
			return
		}

		buf.Skip(int(ifdOffset))
		read, err = buf.ReadBytes(2, advanceReadBytesOpts)
		if err != nil || len(read) < 2 {
			return
		}
		numberOfTags := bo.Uint16(read[0:2])
		for n := uint16(0); n < numberOfTags; n++ {
			read, err = buf.ReadBytes(2, advanceReadBytesOpts)
			if err != nil || len(read) < 2 {
				return
			}
			tagID := bo.Uint16(read[0:2])
			switch tagID {
			case 50_341:
				ext = "arw"
				mime = "image/x-sony-arw"
				return
			case 50_706:
				ext = "dng"
				mime = "image/x-adobe-dng"
				return
			}
			buf.Skip(10)
		}

		ext = "tif"
		mime = "image/tiff"
		return
	}

	// Big TIFF file header
	if version == 43 {
		ext = "tif"
		mime = "image/tiff"
		return
	}

	return
}

func readMkvField(buf *Buffer) (id []byte, err error) {
	var msb uint8
	err = GetUint(buf, &msb)
	if err != nil {
		return
	}
	var mask uint8 = 0x80
	var ic uint8 = 0 // 0 = A, 1 = B, 2 = C, 3 = D

	for ((msb & mask) == 0) && mask != 0 {
		ic++
		mask >>= 1
	}

	id, err = buf.ReadBytes(int(ic+1), &ReadBytesOpts{
		Advance: true,
	})
	return
}

func readMkvElement(buf *Buffer) (id uint64, l uint64, err error) {
	var idBytes []byte
	idBytes, err = readMkvField(buf)
	if err != nil {
		return
	}
	if len(idBytes) > 8 {
		err = errors.New("invalid idBytes length: greater than 8")
	}

	var lengthField []byte
	lengthField, err = readMkvField(buf)
	if err != nil {
		return
	}
	if len(lengthField) > 8 {
		err = errors.New("invalid lengthField length: greater than 8")
	}

	lengthField[0] ^= 0x80 >> (len(lengthField) - 1)
	id = bytesToUintBE(idBytes, binary.BigEndian)
	l = bytesToUintBE(lengthField, binary.BigEndian)

	return
}

func readMkvChildren(buf *Buffer, children uint64) (rawValue []byte, err error) {
	var (
		id uint64
		l  uint64
	)
	for children > 0 {
		id, l, err = readMkvElement(buf)
		if err != nil {
			return
		}
		if l > math.MaxInt32 {
			err = errors.New("length is beyond int32 boundary")
			return
		}
		if id == 0x42_82 {
			rawValue, err = buf.ReadBytes(int(l), &ReadBytesOpts{
				Advance: true,
			})
			if err != nil {
				return
			}

			// Return DocType
			idx := bytes.IndexByte(rawValue, 0x00)
			if idx > -1 {
				rawValue = rawValue[0:idx]
			}
			return
		}

		buf.Skip(int(l)) // ignore payload
		children--
	}

	return
}
