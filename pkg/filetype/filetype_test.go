package filetype

import (
	"path/filepath"
	"testing"
)

const fixturePath = "../../fixture"

var missingTests = map[string]struct{}{
	"mpc": {},
}

//const types = [...supportedExtensions].filter(ext => !missingTests.has(ext));

// Define an entry here only if the fixture has a different name than `fixture` or if you want multiple fixtures
var names = map[string][]string{
	"aac": {
		"fixture-adts-mpeg2",
		"fixture-adts-mpeg4",
		"fixture-adts-mpeg4-2",
		"fixture-id3v2",
	},
	"asar": {
		"fixture",
		"fixture2",
	},
	"arw": {
		"fixture-sony-zv-e10",
	},
	"cr3": {
		"fixture",
	},
	"dng": {
		"fixture-Leica-M10",
	},
	"epub": {
		"fixture",
		"fixture-crlf",
	},
	"nef": {
		"fixture",
		"fixture2",
		"fixture3",
		"fixture4",
	},
	"3gp": {
		"fixture",
		"fixture2",
	},
	"woff2": {
		"fixture",
		"fixture-otto",
	},
	"woff": {
		"fixture",
		"fixture-otto",
	},
	"eot": {
		"fixture",
		"fixture-0x20001",
	},
	"mov": {
		"fixture",
		"fixture-mjpeg",
		"fixture-moov",
	},
	"mp2": {
		"fixture",
		"fixture-mpa",
	},
	"mp3": {
		"fixture",
		"fixture-mp2l3",
		"fixture-ffe3",
	},
	"mp4": {
		"fixture-imovie",
		"fixture-isom",
		"fixture-isomv2",
		"fixture-mp4v2",
		"fixture-dash",
	},
	"mts": {
		"fixture-raw",
		"fixture-bdav",
	},
	"tif": {
		"fixture-big-endian",
		"fixture-little-endian",
	},
	"gz": {
		"fixture.tar",
	},
	"xz": {
		"fixture.tar",
	},
	"lz": {
		"fixture.tar",
	},
	"Z": {
		"fixture.tar",
	},
	"zst": {
		"fixture.tar",
	},
	"mkv": {
		"fixture",
		"fixture2",
	},
	"mpg": {
		"fixture",
		"fixture2",
		"fixture.ps",
		"fixture.sub",
	},
	"heic": {
		"fixture-mif1",
		"fixture-msf1",
		"fixture-heic",
	},
	"ape": {
		"fixture-monkeysaudio",
	},
	"mpc": {
		"fixture-sv7",
		"fixture-sv8",
	},
	"pcap": {
		"fixture-big-endian",
		"fixture-little-endian",
	},
	"png": {
		"fixture",
		"fixture-itxt",
	},
	"tar": {
		"fixture",
		"fixture-v7",
		"fixture-spaces",
	},
	"mie": {
		"fixture-big-endian",
		"fixture-little-endian",
	},
	"m4a": {
		"fixture-babys-songbook.m4b", // Actually it"s an `.m4b`
	},
	"flac": {
		"fixture",
		"fixture-id3v2", // FLAC prefixed with ID3v2 header
	},
	"docx": {
		"fixture",
		"fixture2",
		"fixture-office365",
	},
	"pptx": {
		"fixture",
		"fixture2",
		"fixture-office365",
	},
	"xlsx": {
		"fixture",
		"fixture2",
		"fixture-office365",
	},
	"ogx": {
		"fixture-unknown-ogg", // Manipulated fixture to unrecognized Ogg based file
	},
	"avif": {
		"fixture-yuv420-8bit", // Multiple bit-depths and/or subsamplings
		"fixture-sequence",
	},
	"eps": {
		"fixture",
		"fixture2",
	},
	"cfb": {
		"fixture.msi",
		"fixture.xls",
		"fixture.doc",
		"fixture.ppt",
		"fixture-2.doc",
	},
	"asf": {
		"fixture",
		"fixture.wma",
		"fixture.wmv",
	},
	"ai": {
		"fixture-normal",                    // Normal AI
		"fixture-without-pdf-compatibility", // AI without the PDF compatibility (cannot be opened by PDF viewers I guess)
	},
	"jxl": {
		"fixture",  // Image data stored within JXL container
		"fixture2", // Bare image data with no container
	},
	"pdf": {
		"fixture",
		"fixture-adobe-illustrator", // PDF saved from Adobe Illustrator, using the default "[Illustrator Default]" preset
		"fixture-smallest",          // PDF saved from Adobe Illustrator, using the preset "smallest PDF"
		"fixture-fast-web",          // PDF saved from Adobe Illustrator, using the default "[Illustrator Default"] preset, but enabling "Optimize for Fast Web View"
		"fixture-printed",           // PDF printed from Adobe Illustrator, but with a PDF printer.
	},
	"webm": {
		"fixture-null", // EBML DocType with trailing null character
	},
	"xml": {
		"fixture",
		"fixture-utf8-bom",     // UTF-8 with BOM
		"fixture-utf16-be-bom", // UTF-16 little endian encoded XML, with BOM
		"fixture-utf16-le-bom", // UTF-16 big endian encoded XML, with BOM
	},
}

// Define an entry here only if the file type has potential for false-positives
var falsePositives = map[string][]string{
	"png": {
		"fixture-corrupt",
	},
}

func TestGetFileType(t *testing.T) {
	for _, ext := range supportedExtensions {
		if _, ok := missingTests[ext]; ok {
			continue
		}

		t.Run(ext, func(t *testing.T) {
			var files []string
			if list, ok := names[ext]; ok {
				files = list
			} else {
				files = []string{"fixture"}
			}

			for _, f := range files {
				filename := f + "." + ext
				t.Run(filename, func(t *testing.T) {
					gotExt, gotMime, err := ParseFile(filepath.Join(fixturePath, filename))
					if err != nil {
						t.Errorf("GetFileType() error='%v'", err)
						return
					}
					if gotExt != ext {
						t.Errorf("GetFileType() got extension='%v', want='%v'", gotExt, ext)
					}
					if gotMime == "" {
						t.Errorf("GetFileType() got mime='', want a value")
					}
				})
			}
		})

		if fp, ok := falsePositives[ext]; ok && len(fp) > 0 {
			for _, f := range fp {
				filename := f + "." + ext
				t.Run(filename, func(t *testing.T) {
					gotExt, _, err := ParseFile(filepath.Join(fixturePath, filename))
					if err != nil {
						t.Errorf("GetFileType() error='%v'", err)
						return
					}
					if gotExt != "" {
						t.Errorf("GetFileType() got extension='%v', want=''", gotExt)
					}
				})
			}
		}
	}

	t.Run("corrupt MKV", func(t *testing.T) {
		_, _, err := ParseFile(filepath.Join(fixturePath, "fixture-corrupt.mkv"))
		if err == nil {
			t.Errorf("GetFileType() did not return an error")
			return
		}
	})
}
