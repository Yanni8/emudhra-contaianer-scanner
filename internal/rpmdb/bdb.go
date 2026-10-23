package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Berkeley DB on-disk constants (db_page.h). Pages are written in the byte
// order of the host that created the file, which the metadata magic
// reveals. Each page starts with a 26-byte header: LSN (8), page number
// (4), previous and next page (4 each), entry count (2), free-area offset
// (2), level (1) and page type (1).
const (
	bdbHashMagic      = 0x061561
	bdbBtreeMagic     = 0x053162
	bdbMetaSize       = 72
	bdbPageHeaderSize = 26
	bdbMetaChecksum   = 0x01 // DBMETA_CHKSUM in the metaflags byte

	bdbPageHashUnsorted = 2  // P_HASH_UNSORTED (before Berkeley DB 4.6)
	bdbPageBtreeLeaf    = 4  // P_LBTREE
	bdbPageOverflow     = 7  // P_OVERFLOW
	bdbPageHashMeta     = 8  // P_HASHMETA
	bdbPageBtreeMeta    = 9  // P_BTREEMETA
	bdbPageHash         = 13 // P_HASH

	hashKeyData = 1 // H_KEYDATA: type byte followed by the item
	hashDup     = 2 // H_DUPLICATE
	hashOffPage = 3 // H_OFFPAGE: type, 3 unused, page number, total length
	hashOffDup  = 4 // H_OFFDUP

	btreeKeyData  = 1    // B_KEYDATA: length (2), type (1), item
	btreeDup      = 2    // B_DUPLICATE
	btreeOverflow = 3    // B_OVERFLOW: 2 unused, type, 1 unused, page number, total length
	btreeDeleted  = 0x80 // B_DELETE flag on the type byte
)

// bdbFile is a whole Berkeley DB file held in memory.
type bdbFile struct {
	data     []byte
	order    binary.ByteOrder
	pageSize int
	pages    int
}

// bdbItem locates one key or data item within a page.
type bdbItem struct {
	start, end int
}

// isBDBMagic reports whether the 4 bytes hold a hash or btree magic in
// either byte order.
func isBDBMagic(b []byte) bool {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if m := order.Uint32(b); m == bdbHashMagic || m == bdbBtreeMagic {
			return true
		}
	}
	return false
}

// parseBDB implements Parse for Packages. Every hash (and btree leaf) page
// is scanned for key/data pairs; the data items are rpm header blobs.
// rpm's record with key 0 holds the next header number and is skipped.
func parseBDB(data []byte) ([]Package, error) {
	f, err := openBDB(data)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	add := func(page int, key, value []byte) error {
		if isZero(key) {
			return nil
		}
		p, err := ParseHeader(value)
		if err != nil {
			return fmt.Errorf("page %d: %w", page, err)
		}
		pkgs = append(pkgs, p)
		return nil
	}
	for n := 1; n < f.pages; n++ {
		page := f.data[n*f.pageSize : (n+1)*f.pageSize]
		switch page[25] {
		case bdbPageHash, bdbPageHashUnsorted:
			err = f.hashPage(page, n, add)
		case bdbPageBtreeLeaf:
			err = f.btreeLeafPage(page, n, add)
		}
		if err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

// openBDB validates the metadata page and determines the byte order.
func openBDB(data []byte) (*bdbFile, error) {
	if len(data) < bdbMetaSize || !isBDBMagic(data[12:16]) {
		return nil, errors.New("not a Berkeley DB file")
	}
	var order binary.ByteOrder = binary.LittleEndian
	magic := order.Uint32(data[12:16])
	if magic != bdbHashMagic && magic != bdbBtreeMagic {
		order = binary.BigEndian
		magic = order.Uint32(data[12:16])
	}
	if data[24] != 0 {
		return nil, fmt.Errorf("%w: encrypted Berkeley DB file", ErrUnsupported)
	}
	if data[26]&bdbMetaChecksum != 0 {
		return nil, fmt.Errorf("%w: Berkeley DB file with page checksums", ErrUnsupported)
	}
	switch {
	case magic == bdbHashMagic && data[25] != bdbPageHashMeta,
		magic == bdbBtreeMagic && data[25] != bdbPageBtreeMeta:
		return nil, fmt.Errorf("metadata page type %d does not match the magic", data[25])
	}
	pageSize := order.Uint32(data[20:24])
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("invalid page size %d", pageSize)
	}
	if len(data) < int(pageSize) {
		return nil, errors.New("file shorter than one page")
	}
	return &bdbFile{data: data, order: order, pageSize: int(pageSize), pages: len(data) / int(pageSize)}, nil
}

// page returns page n, which must not be the metadata page.
func (f *bdbFile) page(n uint32) ([]byte, error) {
	if n == 0 || uint64(n) >= uint64(f.pages) {
		return nil, fmt.Errorf("page %d does not exist (file has %d pages)", n, f.pages)
	}
	start := int(n) * f.pageSize
	return f.data[start : start+f.pageSize], nil
}

// itemOffsets reads the index of item offsets that follows a page header.
func (f *bdbFile) itemOffsets(page []byte, n int) ([]int, error) {
	entries := int(f.order.Uint16(page[20:22]))
	if entries%2 != 0 {
		return nil, fmt.Errorf("page %d: odd number of entries %d", n, entries)
	}
	if bdbPageHeaderSize+2*entries > f.pageSize {
		return nil, fmt.Errorf("page %d: %d entries do not fit", n, entries)
	}
	offs := make([]int, entries)
	for i := range offs {
		offs[i] = int(f.order.Uint16(page[bdbPageHeaderSize+2*i:]))
	}
	return offs, nil
}

// hashPage visits the key/data pairs of a hash page. Items are laid out
// from the end of the page downwards in index order, so an item extends to
// the start of its predecessor (or the page end for the first item).
func (f *bdbFile) hashPage(page []byte, n int, add func(page int, key, value []byte) error) error {
	offs, err := f.itemOffsets(page, n)
	if err != nil {
		return err
	}
	items := make([]bdbItem, len(offs))
	prev := f.pageSize
	for i, off := range offs {
		if off < bdbPageHeaderSize+2*len(offs) || off >= prev {
			return fmt.Errorf("page %d: item %d at invalid offset %d", n, i, off)
		}
		items[i] = bdbItem{start: off, end: prev}
		prev = off
	}
	for i := 0; i+1 < len(items); i += 2 {
		key, err := f.hashItem(page, items[i])
		if err != nil {
			return fmt.Errorf("page %d: key %d: %w", n, i/2, err)
		}
		value, err := f.hashItem(page, items[i+1])
		if err != nil {
			return fmt.Errorf("page %d: value %d: %w", n, i/2, err)
		}
		if err := add(n, key, value); err != nil {
			return err
		}
	}
	return nil
}

// hashItem returns the bytes of a hash page item, following an off-page
// reference when the item was too large for the page.
func (f *bdbFile) hashItem(page []byte, it bdbItem) ([]byte, error) {
	switch page[it.start] {
	case hashKeyData:
		return page[it.start+1 : it.end], nil
	case hashOffPage:
		if it.end-it.start < 12 {
			return nil, errors.New("truncated off-page reference")
		}
		return f.overflow(f.order.Uint32(page[it.start+4:]), f.order.Uint32(page[it.start+8:]))
	case hashDup, hashOffDup:
		return nil, fmt.Errorf("%w: duplicate hash items", ErrUnsupported)
	}
	return nil, fmt.Errorf("unknown hash item type %d", page[it.start])
}

// btreeLeafPage visits the key/data pairs of a btree leaf page. Deleted
// pairs (B_DELETE flag) are skipped.
func (f *bdbFile) btreeLeafPage(page []byte, n int, add func(page int, key, value []byte) error) error {
	offs, err := f.itemOffsets(page, n)
	if err != nil {
		return err
	}
	for i := 0; i+1 < len(offs); i += 2 {
		key, kdel, err := f.btreeItem(page, offs[i], len(offs))
		if err != nil {
			return fmt.Errorf("page %d: key %d: %w", n, i/2, err)
		}
		value, vdel, err := f.btreeItem(page, offs[i+1], len(offs))
		if err != nil {
			return fmt.Errorf("page %d: value %d: %w", n, i/2, err)
		}
		if kdel || vdel {
			continue
		}
		if err := add(n, key, value); err != nil {
			return err
		}
	}
	return nil
}

// btreeItem returns the bytes of a btree leaf item and whether it is
// flagged as deleted.
func (f *bdbFile) btreeItem(page []byte, off, entries int) (item []byte, deleted bool, err error) {
	if off < bdbPageHeaderSize+2*entries || off+3 > f.pageSize {
		return nil, false, fmt.Errorf("invalid item offset %d", off)
	}
	typ := page[off+2]
	if typ&btreeDeleted != 0 {
		return nil, true, nil
	}
	switch typ {
	case btreeKeyData:
		length := int(f.order.Uint16(page[off:]))
		if off+3+length > f.pageSize {
			return nil, false, fmt.Errorf("item of %d bytes at %d overruns the page", length, off)
		}
		return page[off+3 : off+3+length], false, nil
	case btreeOverflow:
		if off+12 > f.pageSize {
			return nil, false, errors.New("truncated overflow reference")
		}
		item, err := f.overflow(f.order.Uint32(page[off+4:]), f.order.Uint32(page[off+8:]))
		return item, false, err
	case btreeDup:
		return nil, false, fmt.Errorf("%w: duplicate btree items", ErrUnsupported)
	}
	return nil, false, fmt.Errorf("unknown btree item type %d", typ)
}

// overflow reassembles an item of total bytes from a chain of overflow
// pages, each holding its byte count in the free-area offset field and the
// next page number in the next-page field.
func (f *bdbFile) overflow(first, total uint32) ([]byte, error) {
	if uint64(total) > uint64(len(f.data)) {
		return nil, fmt.Errorf("overflow item of %d bytes is larger than the file", total)
	}
	buf := make([]byte, 0, total)
	visited := make(map[uint32]bool)
	for next := first; next != 0 && len(buf) < int(total); {
		if visited[next] {
			return nil, fmt.Errorf("overflow page %d is referenced twice", next)
		}
		visited[next] = true
		page, err := f.page(next)
		if err != nil {
			return nil, fmt.Errorf("overflow chain: %w", err)
		}
		if page[25] != bdbPageOverflow {
			return nil, fmt.Errorf("page %d in an overflow chain has type %d", next, page[25])
		}
		length := int(f.order.Uint16(page[22:24]))
		if bdbPageHeaderSize+length > f.pageSize {
			return nil, fmt.Errorf("overflow page %d claims %d bytes", next, length)
		}
		buf = append(buf, page[bdbPageHeaderSize:bdbPageHeaderSize+length]...)
		next = f.order.Uint32(page[16:20])
	}
	if len(buf) != int(total) {
		return nil, fmt.Errorf("overflow item: got %d of %d bytes", len(buf), total)
	}
	return buf, nil
}

// isZero reports whether b consists only of zero bytes (rpm's key 0).
func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
