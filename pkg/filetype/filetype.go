package filetype

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strings"
)

// GetFileType returns the asset type and MIME type by reading the "magic numbers" at the beginning of the stream
func GetFileType(r io.Reader) (ext string, mime string, err error) {
	return getFileType(NewBuffer(r))
}

func getFileType(buf *Buffer) (ext string, mime string, err error) {
	var equal bool

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
		// Read the header length
		var read []byte
		read, err = buf.ReadBytes(4, &ReadBytesOpts{
			Advance: true,
			// Skip ID3 header until the header size
			Offset: 6,
		})
		if err != nil {
			return
		} else if len(read) != 4 {
			// Undetermined file type
			return
		}
		headerLen := parseID3SyncSafeUint32([4]byte{read[0], read[1], read[2], read[3]})
		if headerLen > math.MaxInt32 {
			// Undetermined file type
			return
		}

		// Read the amount of bytes from the header to check if we can get that much data, and advance
		read, err = buf.ReadBytes(int(headerLen), &ReadBytesOpts{Advance: true})
		if err != nil {
			return
		} else if len(read) < int(headerLen) {
			// We reached EOF before we could read the entire header
			// Undetermined file type
			return
		}

		// Recursion, after having skipped ID3 header
		return getFileType(buf)
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
			if buf.eof {
				break
			}
			read, err = buf.ReadBytes(30, &ReadBytesOpts{
				Advance: true,
				Offset:  4,
			})
			if err != nil {
				return
			}

			// We reached EOF
			if len(read) < 30 {
				break
			}

			// https://en.wikipedia.org/wiki/Zip_(file_format)#File_headers
			compressedSize = binary.LittleEndian.Uint32(read[18:22])
			uncompressedSize = binary.LittleEndian.Uint32(read[22:26])
			filenameLength = binary.LittleEndian.Uint16(read[26:28])
			extraFieldLength = binary.LittleEndian.Uint16(read[28:30])

			read, err = buf.ReadBytes(int(filenameLength+extraFieldLength), &ReadBytesOpts{Advance: true})
			if err != nil {
				return
			}

			if int(filenameLength) > len(read) {
				break
			}

			filename = string(read[:filenameLength])

			// Assumes signed `.xpi` from addons.mozilla.org
			if filename == "META-INF/mozilla.rsa" {
				ext = "xpi"
				mime = "application/x-xpinstall"
				return
			}

			if strings.HasSuffix(filename, ".rels") || strings.HasSuffix(filename, ".xml") {
				switch filename[0:strings.IndexByte(filename, '/')] {
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
				read, err = buf.ReadBytes(int(compressedSize), nil)
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
					read, err = buf.ReadBytes(4000, &ReadBytesOpts{Advance: true})
					if err != nil || (len(read) == 0 && buf.eof) {
						return
					}
					nextHeaderIndex = bytes.Index(read, []byte{0x50, 0x4B, 0x03, 0x04})
					if nextHeaderIndex > 0 {
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
		if len(read) == 4 &&
			(read[0]&0x60 != 0) && (read[1]&0x60 != 0) &&
			(read[2]&0x60 != 0) && (read[3]&0x60 != 0) {
			brandMajor := string(
				bytes.TrimSpace(
					bytes.ReplaceAll(read, []byte{0x00}, []byte{0x20}),
				),
			)
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
		ext, mime, err = readTiffHeader(buf, false)
		if err != nil || (ext != "" && mime != "") {
			return
		}
	}

	// TIFF, big-endian type
	if buf.MustNextEqual([]byte{0x4D, 0x4D}) {
		ext, mime, err = readTiffHeader(buf, true)
		if err != nil || (ext != "" && mime != "") {
			return
		}
	}

	if buf.MustNextEqualString("MAC ") {
		ext = "ape"
		mime = "audio/ape"
		return
	}

	// https://github.com/threatstack/libmagic/blob/master/magic/Magdir/matroska
	if buf.MustNextEqual([]byte{0x1A, 0x45, 0xDF, 0xA3}) { // Root element: EBML
		/*async function readField() {
			const msb = await tokenizer.peekNumber(Token.UINT8);
			let mask = 0x80;
			let ic = 0; // 0 = A, 1 = B, 2 = C, 3
			// = D

			while ((msb & mask) === 0) {
				++ic;
				mask >>= 1;
			}

			const id = Buffer.alloc(ic + 1);
			await tokenizer.readBuffer(id);
			return id;
		}

		async function readElement() {
			const id = await readField();
			const lengthField = await readField();
			lengthField[0] ^= 0x80 >> (lengthField.length - 1);
			const nrLength = Math.min(6, lengthField.length); // JavaScript can max read 6 bytes integer
			return {
				id: id.readUIntBE(0, id.length),
				len: lengthField.readUIntBE(lengthField.length - nrLength, nrLength),
			};
		}

		async function readChildren(level, children) {
			while (children > 0) {
				const element = await readElement();
				if (element.id === 0x42_82) {
					const rawValue = await tokenizer.readToken(new Token.StringType(element.len, 'utf-8'));
					return rawValue.replace(/\00.*$/g, ''); // Return DocType
				}

				await tokenizer.ignore(element.len); // ignore payload
				--children;
			}
		}

		const re = await readElement();
		const docType = await readChildren(1, re.len);

		switch (docType) {
			case 'webm':
				return {
					ext: 'webm',
					mime: 'video/webm',
				};

			case 'matroska':
				return {
					ext: 'mkv',
					mime: 'video/x-matroska',
				};

			default:
				return;
		}*/
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

func readTiffHeader(buf *Buffer, bigEndian bool) (ext string, mime string, err error) {
	var bo binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		bo = binary.BigEndian
	}

	var (
		read []byte
	)

	read, err = buf.ReadBytes(10, &ReadBytesOpts{
		Advance: true,
		Offset:  2,
	})
	if err != nil || len(read) < 10 {
		return
	}

	version := bo.Uint16(read[0:2])
	ifdOffset := bo.Uint32(read[2:6])

	if version == 42 {
		// TIFF file header
		if ifdOffset >= 6 && len(read) >= 8 {
			if string(read[6:8]) == "CR" {
				ext = "cr2"
				mime = "image/x-canon-cr2"
				return
			}

			if ifdOffset >= 8 && len(read) >= 10 &&
				(bytes.Equal(read[6:10], []byte{0x1C, 0x00, 0xFE, 0x00}) || bytes.Equal(read[6:10], []byte{0x1F, 0x00, 0x0B, 0x00})) {
				ext = "nef"
				mime = "image/x-nikon-nef"
				return
			}
		}

		buf.Skip(int(ifdOffset))
		read, err = buf.ReadBytes(2, &ReadBytesOpts{Advance: true})
		if err != nil || len(read) < 2 {
			return
		}
		numberOfTags := bo.Uint16(read[0:2])
		for n := uint16(0); n < numberOfTags; n++ {
			read, err = buf.ReadBytes(2, &ReadBytesOpts{Advance: true})
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
