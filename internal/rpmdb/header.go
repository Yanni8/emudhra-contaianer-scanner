package rpmdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// rpm header tags (rpm/rpmtag.h) read by ParseHeader.
const (
	tagName    = 1000
	tagVersion = 1001
	tagRelease = 1002
	tagEpoch   = 1003
	tagArch    = 1022
)

// rpm header data types (rpm/rpmtd.h).
const (
	typeNull        = 0
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

const (
	headerMagicSize  = 8          // magic (3 bytes), version and 4 reserved bytes
	headerIntroSize  = 8          // index length and data length, big endian
	headerEntrySize  = 16         // tag, type, offset, count, big endian
	maxHeaderEntries = 0xffff     // rpm's hdrchkTags limit
	maxHeaderData    = 0x0fffffff // rpm's hdrchkData limit
)

// headerMagic starts a header written to a package file or exported with
// headerWrite; the blobs stored in rpm databases omit it.
var headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01}

// headerEntry is one decoded index entry.
type headerEntry struct {
	tag    int32
	typ    uint32
	offset int32
	count  uint32
}

// ParseHeader decodes an rpm header blob into a Package. The blob is the
// form stored in rpm databases (index length, data length, index entries
// and data section, all big endian); the 8-byte magic that prefixes headers
// in package files is accepted and skipped. Every offset is bounds-checked
// and nothing is allocated from untrusted counts, so truncated or corrupt
// input yields an error rather than a panic.
func ParseHeader(blob []byte) (Package, error) {
	if bytes.HasPrefix(blob, headerMagic) {
		if len(blob) < headerMagicSize {
			return Package{}, errors.New("truncated header magic")
		}
		blob = blob[headerMagicSize:]
	}
	if len(blob) < headerIntroSize {
		return Package{}, fmt.Errorf("header blob too short (%d bytes)", len(blob))
	}
	il := binary.BigEndian.Uint32(blob[0:4])
	dl := binary.BigEndian.Uint32(blob[4:8])
	if il > maxHeaderEntries || dl > maxHeaderData {
		return Package{}, fmt.Errorf("implausible header: %d index entries, %d data bytes", il, dl)
	}
	indexEnd := headerIntroSize + int(il)*headerEntrySize
	dataEnd := indexEnd + int(dl)
	if len(blob) < dataEnd {
		return Package{}, fmt.Errorf("truncated header: need %d bytes, have %d", dataEnd, len(blob))
	}
	index := blob[headerIntroSize:indexEnd]
	data := blob[indexEnd:dataEnd]

	var p Package
	for i := 0; i < int(il); i++ {
		e := decodeHeaderEntry(index[i*headerEntrySize:])
		if e.typ > typeI18NString {
			return Package{}, fmt.Errorf("index entry %d: unknown data type %d", i, e.typ)
		}
		if e.offset < 0 || int(e.offset) > len(data) {
			return Package{}, fmt.Errorf("index entry %d (tag %d): offset %d outside the %d-byte data section", i, e.tag, e.offset, len(data))
		}
		var err error
		switch e.tag {
		case tagName:
			p.Name, err = entryString(e, data)
		case tagVersion:
			p.Version, err = entryString(e, data)
		case tagRelease:
			p.Release, err = entryString(e, data)
		case tagArch:
			p.Arch, err = entryString(e, data)
		case tagEpoch:
			var epoch int32
			epoch, err = entryInt32(e, data)
			p.Epoch = strconv.Itoa(int(epoch))
		}
		if err != nil {
			return Package{}, fmt.Errorf("tag %d: %w", e.tag, err)
		}
	}
	if p.Name == "" {
		return Package{}, errors.New("header has no NAME tag")
	}
	return p, nil
}

// decodeHeaderEntry decodes the 16-byte index entry at the start of b.
func decodeHeaderEntry(b []byte) headerEntry {
	return headerEntry{
		tag:    int32(binary.BigEndian.Uint32(b[0:4])),
		typ:    binary.BigEndian.Uint32(b[4:8]),
		offset: int32(binary.BigEndian.Uint32(b[8:12])),
		count:  binary.BigEndian.Uint32(b[12:16]),
	}
}

// entryString returns the (first) NUL-terminated string of a STRING,
// STRING_ARRAY or I18NSTRING entry.
func entryString(e headerEntry, data []byte) (string, error) {
	switch e.typ {
	case typeString, typeStringArray, typeI18NString:
	default:
		return "", fmt.Errorf("data type %d is not a string type", e.typ)
	}
	if e.count == 0 {
		return "", errors.New("string entry with count 0")
	}
	rest := data[e.offset:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", errors.New("unterminated string")
	}
	return string(rest[:end]), nil
}

// entryInt32 returns the first value of an INT32 entry.
func entryInt32(e headerEntry, data []byte) (int32, error) {
	if e.typ != typeInt32 {
		return 0, fmt.Errorf("data type %d is not INT32", e.typ)
	}
	if e.count == 0 {
		return 0, errors.New("INT32 entry with count 0")
	}
	if len(data)-int(e.offset) < 4 {
		return 0, errors.New("INT32 value truncated")
	}
	return int32(binary.BigEndian.Uint32(data[e.offset:])), nil
}
