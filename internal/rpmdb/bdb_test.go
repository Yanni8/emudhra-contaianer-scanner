package rpmdb

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

// buildBDB returns a file consisting only of a metadata page.
func buildBDB(order binary.ByteOrder, pageSize int, magic uint32, pageType byte) []byte {
	return bdbMetaPage(order, pageSize, magic, pageType, 0)
}

// bdbMetaPage builds page 0: LSN, page number, magic, version, page size,
// encryption algorithm, page type, metaflags, then last page number.
func bdbMetaPage(order binary.ByteOrder, pageSize int, magic uint32, pageType byte, lastPage uint32) []byte {
	page := make([]byte, pageSize)
	order.PutUint32(page[12:], magic)
	order.PutUint32(page[16:], 9) // version
	order.PutUint32(page[20:], uint32(pageSize))
	page[25] = pageType
	order.PutUint32(page[32:], lastPage)
	return page
}

// bdbItemPage builds a hash or btree leaf page from raw items (type byte
// included) laid out from the end of the page downwards, in index order,
// as Berkeley DB keeps them.
func bdbItemPage(order binary.ByteOrder, pageSize int, pageNo uint32, pageType byte, items ...[]byte) []byte {
	page := make([]byte, pageSize)
	order.PutUint32(page[8:], pageNo)
	order.PutUint16(page[20:], uint16(len(items)))
	page[25] = pageType
	end := pageSize
	for i, item := range items {
		end -= len(item)
		copy(page[end:], item)
		order.PutUint16(page[bdbPageHeaderSize+2*i:], uint16(end))
	}
	order.PutUint16(page[22:], uint16(end)) // free-area offset
	return page
}

// bdbOverflowPage builds one overflow page holding data.
func bdbOverflowPage(order binary.ByteOrder, pageSize int, pageNo, next uint32, data []byte) []byte {
	page := make([]byte, pageSize)
	order.PutUint32(page[8:], pageNo)
	order.PutUint32(page[16:], next)
	order.PutUint16(page[22:], uint16(len(data)))
	page[25] = bdbPageOverflow
	copy(page[bdbPageHeaderSize:], data)
	return page
}

// bdbOverflowChain splits data over consecutive overflow pages starting
// at page first.
func bdbOverflowChain(order binary.ByteOrder, pageSize int, first uint32, data []byte) []byte {
	var pages []byte
	chunk := pageSize - bdbPageHeaderSize
	for n := first; len(data) > 0; n++ {
		next := n + 1
		take := chunk
		if len(data) <= chunk {
			take, next = len(data), 0
		}
		pages = append(pages, bdbOverflowPage(order, pageSize, n, next, data[:take])...)
		data = data[take:]
	}
	return pages
}

func hashInline(data []byte) []byte { return append([]byte{hashKeyData}, data...) }

func hashOffPageItem(order binary.ByteOrder, page, length uint32) []byte {
	item := make([]byte, 12)
	item[0] = hashOffPage
	order.PutUint32(item[4:], page)
	order.PutUint32(item[8:], length)
	return item
}

func btreeInline(data []byte) []byte {
	item := make([]byte, 3+len(data))
	binary.LittleEndian.PutUint16(item, uint16(len(data)))
	item[2] = btreeKeyData
	copy(item[3:], data)
	return item
}

func btreeOverflowItem(page, length uint32) []byte {
	item := make([]byte, 12)
	item[2] = btreeOverflow
	binary.LittleEndian.PutUint32(item[4:], page)
	binary.LittleEndian.PutUint32(item[8:], length)
	return item
}

func hdrNum(n uint32) []byte { return binary.LittleEndian.AppendUint32(nil, n) }

func concat(pages ...[]byte) []byte {
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

var (
	bdbPkgA = Package{Name: "a", Version: "1", Release: "1.amzn2", Arch: "x86_64"}
	bdbPkgB = Package{Name: "b", Version: "2", Release: "2", Epoch: "1", Arch: "noarch"}
	bdbPkgC = Package{Name: "c", Version: "3"}
)

// bdbHashFile builds the realistic shape of an rpm Packages file in the
// given byte order: key 0 holding the next header number, a small header
// stored in the page and two large ones on overflow pages.
func bdbHashFile(order binary.ByteOrder, pageType byte) []byte {
	const ps = 512
	blobA := buildHeader(false, strEntry(tagName, "a"), strEntry(tagVersion, "1"), strEntry(tagRelease, "1.amzn2"), strEntry(tagArch, "x86_64"))
	blobB := buildRegionHeader(strEntry(tagName, "b"), strEntry(tagVersion, "2"), strEntry(tagRelease, "2"), int32Entry(tagEpoch, 1), strEntry(tagArch, "noarch"), binEntry(1013, make([]byte, 700)))
	blobC := buildHeader(false, strEntry(tagName, "c"), strEntry(tagVersion, "3"), binEntry(1013, make([]byte, ps-bdbPageHeaderSize-60)))
	chainB := bdbOverflowChain(order, ps, 2, blobB) // pages 2 and 3
	chainC := bdbOverflowChain(order, ps, 4, blobC) // page 4
	hash := bdbItemPage(order, ps, 1, pageType,
		hashInline(hdrNum(0)), hashInline(hdrNum(4)),
		hashInline(hdrNum(1)), hashInline(blobA),
		hashInline(hdrNum(2)), hashOffPageItem(order, 2, uint32(len(blobB))),
		hashInline(hdrNum(3)), hashOffPageItem(order, 4, uint32(len(blobC))),
	)
	return concat(bdbMetaPage(order, ps, bdbHashMagic, bdbPageHashMeta, 4), hash, chainB, chainC)
}

func TestParseBDB(t *testing.T) {
	const ps = 512
	le := binary.LittleEndian
	good := bdbHashFile(le, bdbPageHash)
	blobA := buildHeader(false, strEntry(tagName, "a"), strEntry(tagVersion, "1"), strEntry(tagRelease, "1.amzn2"), strEntry(tagArch, "x86_64"))
	blobC := buildHeader(false, strEntry(tagName, "c"), strEntry(tagVersion, "3"), binEntry(1013, make([]byte, 600)))
	btree := concat(
		bdbMetaPage(le, ps, bdbBtreeMagic, bdbPageBtreeMeta, 3),
		bdbItemPage(le, ps, 1, bdbPageBtreeLeaf,
			btreeInline(hdrNum(1)), btreeInline(blobA),
			btreeInline(hdrNum(2)), btreeOverflowItem(2, uint32(len(blobC))),
		),
		bdbOverflowChain(le, ps, 2, blobC),
	)
	deleted := btreeInline(hdrNum(3))
	deleted[2] |= btreeDeleted
	btreeDeletedPair := concat(
		bdbMetaPage(le, ps, bdbBtreeMagic, bdbPageBtreeMeta, 1),
		bdbItemPage(le, ps, 1, bdbPageBtreeLeaf, deleted, btreeInline([]byte("not a header")), btreeInline(hdrNum(1)), btreeInline(blobA)),
	)
	hashPage := func(items ...[]byte) []byte {
		return concat(bdbMetaPage(le, ps, bdbHashMagic, bdbPageHashMeta, 1), bdbItemPage(le, ps, 1, bdbPageHash, items...))
	}
	// Offsets within the hash page of good (file offset ps + ...).
	const inp = ps + bdbPageHeaderSize

	tests := []struct {
		name    string
		data    []byte
		want    []Package
		wantErr string
		unsupp  bool
	}{
		{name: "hash little endian", data: good, want: []Package{bdbPkgA, bdbPkgB, bdbPkgC}},
		{name: "hash big endian", data: bdbHashFile(binary.BigEndian, bdbPageHash), want: []Package{bdbPkgA, bdbPkgB, bdbPkgC}},
		{name: "unsorted hash page type", data: bdbHashFile(le, bdbPageHashUnsorted), want: []Package{bdbPkgA, bdbPkgB, bdbPkgC}},
		{name: "metadata page only", data: buildBDB(le, ps, bdbHashMagic, bdbPageHashMeta), want: nil},
		{name: "unrelated page types are skipped", data: concat(bdbMetaPage(le, ps, bdbHashMagic, bdbPageHashMeta, 2), make([]byte, ps), bdbOverflowPage(le, ps, 2, 0, []byte("x"))), want: nil},
		{name: "btree leaf", data: btree, want: []Package{bdbPkgA, {Name: "c", Version: "3"}}},
		{name: "btree deleted pair skipped", data: btreeDeletedPair, want: []Package{bdbPkgA}},
		{name: "garbage", data: []byte("this is not a Berkeley DB file, honestly, it really is not one"), wantErr: "not a Berkeley DB file"},
		{name: "empty", data: nil, wantErr: "not a Berkeley DB file"},
		{name: "short", data: good[:40], wantErr: "not a Berkeley DB file"},
		{name: "encrypted", data: patchByte(good, 24, 1), wantErr: "encrypted", unsupp: true},
		{name: "checksummed", data: patchByte(good, 26, bdbMetaChecksum), wantErr: "page checksums", unsupp: true},
		{name: "hash magic with btree metadata type", data: patchByte(good, 25, bdbPageBtreeMeta), wantErr: "metadata page type 9 does not match"},
		{name: "btree magic with hash metadata type", data: patch(good, 12, bdbBtreeMagic), wantErr: "metadata page type 8 does not match"},
		{name: "bad page size", data: patch(good, 20, 0x300), wantErr: "invalid page size 768"},
		{name: "page size too small", data: patch(good, 20, 256), wantErr: "invalid page size 256"},
		{name: "page size larger than file", data: patch(good, 20, 65536), wantErr: "file shorter than one page"},
		{name: "odd entry count", data: patchByte(good, ps+20, 7), wantErr: "page 1: odd number of entries 7"},
		{name: "entries do not fit", data: patchByte(good, ps+20, 250), wantErr: "page 1: 250 entries do not fit"},
		{name: "item offset inside the index", data: patch16(good, inp, 30), wantErr: "page 1: item 0 at invalid offset 30"},
		{name: "item offsets out of order", data: patch16(good, inp+2, 0x1ff), wantErr: "page 1: item 1 at invalid offset 511"},
		{name: "unknown hash item type", data: hashPage([]byte{9, 0, 0, 0, 0}, hashInline(blobA)), wantErr: "page 1: key 0: unknown hash item type 9"},
		{name: "duplicate hash items", data: hashPage(hashInline(hdrNum(1)), []byte{hashDup, 0}), wantErr: "duplicate hash items", unsupp: true},
		{name: "off-page duplicates", data: hashPage(hashInline(hdrNum(1)), []byte{hashOffDup, 0, 0, 0, 2, 0, 0, 0}), wantErr: "duplicate hash items", unsupp: true},
		{name: "truncated off-page reference", data: hashPage(hashInline(hdrNum(1)), []byte{hashOffPage, 0, 0, 0, 2, 0, 0, 0}), wantErr: "page 1: value 0: truncated off-page reference"},
		{name: "overflow page beyond the file", data: hashPage(hashInline(hdrNum(1)), hashOffPageItem(le, 99, 10)), wantErr: "overflow chain: page 99 does not exist"},
		{name: "overflow page zero", data: hashPage(hashInline(hdrNum(1)), hashOffPageItem(le, 0, 10)), wantErr: "overflow item: got 0 of 10 bytes"},
		{name: "overflow pointing at a hash page", data: hashPage(hashInline(hdrNum(1)), hashOffPageItem(le, 1, 10)), wantErr: "page 1 in an overflow chain has type 13"},
		{name: "overflow cycle", data: patch(good, 2*ps+16, 2), wantErr: "overflow page 2 is referenced twice"},
		{name: "overflow chain too short", data: patch(good, 2*ps+16, 0), wantErr: "overflow item: got 486 of"},
		{name: "overflow item larger than file", data: patch(good, itemOffset(good, ps, 1, 5)+8, 0xffffffff), wantErr: "larger than the file"},
		{name: "overflow length mismatch", data: patch(good, itemOffset(good, ps, 1, 5)+8, 10), wantErr: "overflow item: got 486 of 10 bytes"},
		{name: "overflow page claims too much", data: patch16(good, 2*ps+22, 0x7fff), wantErr: "overflow page 2 claims 32767 bytes"},
		{name: "corrupt header blob", data: hashPage(hashInline(hdrNum(1)), hashInline([]byte("not a header"))), wantErr: "page 1: implausible header"},
		{name: "header blob missing name", data: hashPage(hashInline(hdrNum(1)), hashInline(buildHeader(false, strEntry(tagVersion, "1")))), wantErr: "page 1: header has no NAME tag"},
		{name: "btree item offset invalid", data: patch16(btree, inp, 1), wantErr: "page 1: key 0: invalid item offset 1"},
		{name: "btree item overruns page", data: patch16(btree, itemOffset(btree, ps, 1, 1), 0xffff), wantErr: "item of 65535 bytes at"},
		{name: "btree unknown item type", data: concat(bdbMetaPage(le, ps, bdbBtreeMagic, bdbPageBtreeMeta, 1), bdbItemPage(le, ps, 1, bdbPageBtreeLeaf, []byte{0, 0, 7, 0}, btreeInline(blobA))), wantErr: "unknown btree item type 7"},
		{name: "btree duplicates", data: concat(bdbMetaPage(le, ps, bdbBtreeMagic, bdbPageBtreeMeta, 1), bdbItemPage(le, ps, 1, bdbPageBtreeLeaf, btreeInline(hdrNum(1)), []byte{0, 0, btreeDup, 0})), wantErr: "duplicate btree items", unsupp: true},
		{name: "btree truncated overflow reference", data: concat(bdbMetaPage(le, ps, bdbBtreeMagic, bdbPageBtreeMeta, 1), bdbItemPage(le, ps, 1, bdbPageBtreeLeaf, btreeInline(hdrNum(1)), []byte{0, 0, btreeOverflow, 0})), wantErr: "truncated overflow reference"},
		{name: "truncated file", data: good[:3*ps], wantErr: "overflow chain: page 3 does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(FormatBDB, tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				if errors.Is(err, ErrUnsupported) != tt.unsupp {
					t.Errorf("errors.Is(err, ErrUnsupported) = %v, want %v (%v)", !tt.unsupp, tt.unsupp, err)
				}
				if got != nil {
					t.Errorf("packages = %v on error, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Parse = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// patch16 returns a copy of data with a little-endian uint16 written at off.
func patch16(data []byte, off int, v uint16) []byte {
	out := append([]byte{}, data...)
	binary.LittleEndian.PutUint16(out[off:], v)
	return out
}

// itemOffset returns the file offset of item index on page pageNo of a
// little-endian file with pageSize pages.
func itemOffset(data []byte, pageSize, pageNo, index int) int {
	page := data[pageNo*pageSize:]
	return pageNo*pageSize + int(binary.LittleEndian.Uint16(page[bdbPageHeaderSize+2*index:]))
}

// patchByte returns a copy of data with one byte replaced.
func patchByte(data []byte, off int, v byte) []byte {
	out := append([]byte{}, data...)
	out[off] = v
	return out
}

func FuzzParseBDB(f *testing.F) {
	f.Add(bdbHashFile(binary.LittleEndian, bdbPageHash))
	f.Add(bdbHashFile(binary.BigEndian, bdbPageHashUnsorted))
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(FormatBDB, data)
	})
}
