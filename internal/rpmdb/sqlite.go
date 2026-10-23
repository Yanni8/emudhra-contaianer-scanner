package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// SQLite 3 file format constants (https://sqlite.org/fileformat2.html).
const (
	sqliteMagic      = "SQLite format 3\x00"
	sqliteHeaderSize = 100
	sqliteMinUsable  = 480

	pageInteriorIndex = 0x02
	pageInteriorTable = 0x05
	pageLeafIndex     = 0x0a
	pageLeafTable     = 0x0d

	encodingUTF8    = 1
	encodingUTF16LE = 2
	encodingUTF16BE = 3

	// rpm keeps the header blobs in this table (hnum INTEGER PRIMARY KEY, blob BLOB).
	packagesTable = "Packages"
)

// sqliteFile is a whole SQLite database held in memory.
type sqliteFile struct {
	data     []byte
	pageSize int
	usable   int // page size minus the reserved bytes at the end of each page
	encoding uint32
	pages    int // number of complete pages in data
}

// column is one value of a decoded record.
type column struct {
	serial uint64
	data   []byte
}

// parseSQLite implements Parse for rpmdb.sqlite.
func parseSQLite(data []byte) ([]Package, error) {
	f, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := f.tableRoot(packagesTable)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	err = f.walkTable(root, func(rowid int64, record []byte) error {
		cols, err := decodeRecord(record)
		if err != nil {
			return fmt.Errorf("row %d: %w", rowid, err)
		}
		blob, ok := firstBlob(cols)
		if !ok {
			return fmt.Errorf("row %d has no BLOB column", rowid)
		}
		p, err := ParseHeader(blob)
		if err != nil {
			return fmt.Errorf("row %d: %w", rowid, err)
		}
		pkgs = append(pkgs, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pkgs, nil
}

// openSQLite validates the 100-byte database header.
func openSQLite(data []byte) (*sqliteFile, error) {
	if len(data) < sqliteHeaderSize || string(data[:len(sqliteMagic)]) != sqliteMagic {
		return nil, errors.New("not a SQLite 3 database")
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("invalid page size %d", pageSize)
	}
	if data[21] != 64 || data[22] != 32 || data[23] != 32 {
		return nil, errors.New("unexpected payload fractions in the database header")
	}
	usable := pageSize - int(data[20])
	if usable < sqliteMinUsable {
		return nil, fmt.Errorf("usable page size %d is too small", usable)
	}
	encoding := binary.BigEndian.Uint32(data[56:60])
	switch encoding {
	case 0: // never written by a database that holds a schema; treat as UTF-8
		encoding = encodingUTF8
	case encodingUTF8, encodingUTF16LE, encodingUTF16BE:
	default:
		return nil, fmt.Errorf("unknown text encoding %d", encoding)
	}
	if len(data) < pageSize {
		return nil, errors.New("file shorter than one page")
	}
	return &sqliteFile{data: data, pageSize: pageSize, usable: usable, encoding: encoding, pages: len(data) / pageSize}, nil
}

// page returns page n (pages are numbered from 1).
func (f *sqliteFile) page(n uint32) ([]byte, error) {
	if n == 0 || uint64(n) > uint64(f.pages) {
		return nil, fmt.Errorf("page %d does not exist (file has %d pages)", n, f.pages)
	}
	start := (int(n) - 1) * f.pageSize
	return f.data[start : start+f.pageSize], nil
}

// tableRoot finds the root page of a table in sqlite_master (page 1).
func (f *sqliteFile) tableRoot(name string) (uint32, error) {
	var root uint32
	err := f.walkTable(1, func(rowid int64, record []byte) error {
		cols, err := decodeRecord(record)
		if err != nil {
			return fmt.Errorf("sqlite_master row %d: %w", rowid, err)
		}
		if len(cols) < 4 || root != 0 {
			return nil
		}
		if f.text(cols[0]) != "table" || !strings.EqualFold(f.text(cols[1]), name) {
			return nil
		}
		page, ok := intValue(cols[3])
		if !ok || page < 1 || page > int64(f.pages) {
			return fmt.Errorf("table %q has invalid root page %d", name, page)
		}
		root = uint32(page)
		return nil
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("table %q not found", name)
	}
	return root, nil
}

// walkTable visits every row of a table b-tree in rowid order. Pages are
// never visited twice, so a corrupt file with a page cycle is reported
// instead of looping.
func (f *sqliteFile) walkTable(root uint32, visit func(rowid int64, record []byte) error) error {
	visited := make(map[uint32]bool)
	stack := []uint32{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n] {
			return fmt.Errorf("page %d is referenced twice in the b-tree", n)
		}
		visited[n] = true
		page, err := f.page(n)
		if err != nil {
			return err
		}
		hdr := 0
		if n == 1 {
			hdr = sqliteHeaderSize
		}
		typ := page[hdr]
		cells := int(binary.BigEndian.Uint16(page[hdr+3:]))
		switch typ {
		case pageInteriorTable:
			ptrs := hdr + 12
			if ptrs+2*cells > f.usable {
				return fmt.Errorf("page %d: %d cells do not fit", n, cells)
			}
			children := make([]uint32, 0, cells+1)
			for i := 0; i < cells; i++ {
				off := int(binary.BigEndian.Uint16(page[ptrs+2*i:]))
				if off < ptrs+2*cells || off+4 > f.usable {
					return fmt.Errorf("page %d: cell %d at invalid offset %d", n, i, off)
				}
				children = append(children, binary.BigEndian.Uint32(page[off:]))
			}
			children = append(children, binary.BigEndian.Uint32(page[hdr+8:]))
			for i := len(children) - 1; i >= 0; i-- { // leftmost child is visited first
				stack = append(stack, children[i])
			}
		case pageLeafTable:
			ptrs := hdr + 8
			if ptrs+2*cells > f.usable {
				return fmt.Errorf("page %d: %d cells do not fit", n, cells)
			}
			for i := 0; i < cells; i++ {
				off := int(binary.BigEndian.Uint16(page[ptrs+2*i:]))
				if off < ptrs+2*cells {
					return fmt.Errorf("page %d: cell %d at invalid offset %d", n, i, off)
				}
				rowid, record, err := f.leafCell(page, off)
				if err != nil {
					return fmt.Errorf("page %d: cell %d: %w", n, i, err)
				}
				if err := visit(rowid, record); err != nil {
					return err
				}
			}
		case pageInteriorIndex, pageLeafIndex:
			return fmt.Errorf("page %d is an index page, not a table page", n)
		default:
			return fmt.Errorf("page %d has unknown page type %#x", n, typ)
		}
	}
	return nil
}

// leafCell decodes a table leaf cell: payload size, rowid and the payload,
// reassembled from overflow pages when it does not fit in the page.
func (f *sqliteFile) leafCell(page []byte, off int) (rowid int64, record []byte, err error) {
	if off >= f.usable {
		return 0, nil, fmt.Errorf("cell offset %d beyond the usable page", off)
	}
	payloadSize, n := varint(page[off:f.usable])
	if n == 0 {
		return 0, nil, errors.New("truncated payload size")
	}
	off += n
	key, n := varint(page[off:f.usable])
	if n == 0 {
		return 0, nil, errors.New("truncated rowid")
	}
	off += n
	rowid = int64(key)
	if payloadSize > uint64(len(f.data)) {
		return 0, nil, fmt.Errorf("payload of %d bytes is larger than the file", payloadSize)
	}
	total := int(payloadSize)
	local := f.localPayload(total)
	if off+local > f.usable {
		return 0, nil, fmt.Errorf("local payload of %d bytes at %d overruns the page", local, off)
	}
	if local == total {
		return rowid, page[off : off+local], nil
	}
	if off+local+4 > f.usable {
		return 0, nil, errors.New("overflow page pointer overruns the page")
	}
	buf := make([]byte, 0, total)
	buf = append(buf, page[off:off+local]...)
	next := binary.BigEndian.Uint32(page[off+local:])
	buf, err = f.readOverflow(buf, next, total-local)
	if err != nil {
		return 0, nil, err
	}
	return rowid, buf, nil
}

// localPayload applies the file format's formula for how much of a table
// leaf cell payload of total bytes is stored in the page itself.
func (f *sqliteFile) localPayload(total int) int {
	u := f.usable
	x := u - 35
	if total <= x {
		return total
	}
	m := (u-12)*32/255 - 23
	k := m + (total-m)%(u-4)
	if k <= x {
		return k
	}
	return m
}

// readOverflow appends remaining payload bytes from a chain of overflow
// pages, each of which starts with the number of the next page (0 at the
// end of the chain).
func (f *sqliteFile) readOverflow(buf []byte, next uint32, remaining int) ([]byte, error) {
	visited := make(map[uint32]bool)
	for remaining > 0 {
		if next == 0 {
			return nil, fmt.Errorf("overflow chain ends with %d payload bytes missing", remaining)
		}
		if visited[next] {
			return nil, fmt.Errorf("overflow page %d is referenced twice", next)
		}
		visited[next] = true
		page, err := f.page(next)
		if err != nil {
			return nil, fmt.Errorf("overflow chain: %w", err)
		}
		chunk := min(f.usable-4, remaining)
		buf = append(buf, page[4:4+chunk]...)
		remaining -= chunk
		next = binary.BigEndian.Uint32(page[0:4])
	}
	return buf, nil
}

// decodeRecord splits a record (header of serial types, then the values)
// into columns.
func decodeRecord(rec []byte) ([]column, error) {
	hdrLen, n := varint(rec)
	if n == 0 || hdrLen < uint64(n) || hdrLen > uint64(len(rec)) {
		return nil, errors.New("invalid record header length")
	}
	pos, body := n, int(hdrLen)
	var cols []column
	for pos < int(hdrLen) {
		serial, n := varint(rec[pos:hdrLen])
		if n == 0 {
			return nil, errors.New("truncated serial type")
		}
		pos += n
		size, err := serialSize(serial)
		if err != nil {
			return nil, fmt.Errorf("column %d: %w", len(cols), err)
		}
		if size > uint64(len(rec)-body) {
			return nil, fmt.Errorf("column %d: %d bytes exceed the record", len(cols), size)
		}
		cols = append(cols, column{serial: serial, data: rec[body : body+int(size)]})
		body += int(size)
	}
	return cols, nil
}

// serialSize returns the number of value bytes a serial type occupies.
func serialSize(serial uint64) (uint64, error) {
	switch serial {
	case 0, 8, 9:
		return 0, nil
	case 1, 2, 3, 4:
		return serial, nil
	case 5:
		return 6, nil
	case 6, 7:
		return 8, nil
	case 10, 11:
		return 0, fmt.Errorf("reserved serial type %d", serial)
	}
	if serial%2 == 0 {
		return (serial - 12) / 2, nil
	}
	return (serial - 13) / 2, nil
}

// firstBlob returns the value of the first BLOB column.
func firstBlob(cols []column) ([]byte, bool) {
	for _, c := range cols {
		if c.serial >= 12 && c.serial%2 == 0 {
			return c.data, true
		}
	}
	return nil, false
}

// intValue returns the value of an integer column.
func intValue(c column) (int64, bool) {
	switch c.serial {
	case 8:
		return 0, true
	case 9:
		return 1, true
	case 1, 2, 3, 4, 5, 6:
		var v int64
		for _, b := range c.data {
			v = v<<8 | int64(b)
		}
		shift := 64 - 8*uint(len(c.data))
		return v << shift >> shift, true // sign-extend
	}
	return 0, false
}

// text returns the value of a TEXT column decoded from the database's
// text encoding, or "" for any other column type.
func (f *sqliteFile) text(c column) string {
	if c.serial < 13 || c.serial%2 == 0 {
		return ""
	}
	if f.encoding == encodingUTF8 {
		return string(c.data)
	}
	units := make([]uint16, len(c.data)/2)
	for i := range units {
		if f.encoding == encodingUTF16LE {
			units[i] = binary.LittleEndian.Uint16(c.data[2*i:])
		} else {
			units[i] = binary.BigEndian.Uint16(c.data[2*i:])
		}
	}
	return string(utf16.Decode(units))
}

// varint decodes a SQLite variable-length integer (up to 9 bytes, big
// endian, 7 bits per byte and all 8 bits of the ninth). It returns the
// number of bytes consumed, which is 0 when b is truncated.
func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 9; i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}
