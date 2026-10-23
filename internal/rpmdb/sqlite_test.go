package rpmdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// smallPackages is the content of testdata/packages-small.sqlite (and the
// UTF-16 copy of it) in rowid order; see testdata/gen_fixtures.py.
var smallPackages = []Package{
	{Name: "ca-certificates", Version: "2025.2.80_v9.0.305", Release: "91.el9", Arch: "noarch"},
	{Name: "openssl-libs", Version: "3.5.8", Release: "2.el9_8", Epoch: "1", Arch: "x86_64"},
	{Name: "p11-kit", Version: "0.26.4", Release: "1.el9_8", Epoch: "0", Arch: "x86_64"},
	{Name: "gpg-pubkey", Version: "fd431d51", Release: "4ae0493b"},
	{Name: "big-package", Version: "7.0", Release: "1", Arch: "noarch"},
	{Name: "zlib", Version: "1.2.13", Release: "4.el9", Arch: "x86_64"},
}

// deepPackages is the content of testdata/packages-deep.sqlite: 300 rows
// spread over a three-level b-tree.
func deepPackages() []Package {
	pkgs := make([]Package, 300)
	for i := range pkgs {
		pkgs[i] = Package{Name: fmt.Sprintf("pkg%03d", i), Version: fmt.Sprintf("1.%d", i), Release: fmt.Sprintf("r%d", i%7), Arch: "noarch"}
	}
	return pkgs
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseSQLiteFixtures(t *testing.T) {
	tests := []struct {
		file string
		want []Package
	}{
		{"packages-small.sqlite", smallPackages},
		{"packages-utf16le.sqlite", smallPackages},
		{"packages-deep.sqlite", deepPackages()},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := Parse(FormatSQLite, readFixture(t, tt.file))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Parse = %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// overflowPages lists the overflow pages of a small fixture: every page
// after the first whose first byte is zero, which b-tree pages (type byte
// first) never are and overflow pages (next-page pointer first) always are
// in a file of fewer than 2^24 pages.
func overflowPages(data []byte, pageSize int) []int {
	var pages []int
	for p := 2; p*pageSize <= len(data); p++ {
		if data[(p-1)*pageSize] == 0 {
			pages = append(pages, p)
		}
	}
	return pages
}

func TestParseSQLiteCorrupt(t *testing.T) {
	small := readFixture(t, "packages-small.sqlite")
	const ps = 512
	const root = 3 // root page of Packages, an interior page (see gen_fixtures.py)
	rootOff := (root - 1) * ps
	leaf := int(binary.BigEndian.Uint32(small[rootOff+8:])) // right-most child of the root
	leafOff := (leaf - 1) * ps
	if small[rootOff] != pageInteriorTable || small[leafOff] != pageLeafTable || len(overflowPages(small, ps)) == 0 {
		t.Fatal("fixture layout changed: need an interior root, a leaf child and overflow pages")
	}
	patch32 := func(data []byte, off int, v uint32) []byte {
		out := append([]byte{}, data...)
		binary.BigEndian.PutUint32(out[off:], v)
		return out
	}
	patch16 := func(data []byte, off int, v uint16) []byte {
		out := append([]byte{}, data...)
		binary.BigEndian.PutUint16(out[off:], v)
		return out
	}
	patchOverflow := func(data []byte, next func(page int) uint32) []byte {
		out := append([]byte{}, data...)
		for _, p := range overflowPages(data, ps) {
			binary.BigEndian.PutUint32(out[(p-1)*ps:], next(p))
		}
		return out
	}
	rootPage := bytes.Index(small, []byte("PackagesPackages")) + len("PackagesPackages") // rootpage column of the sqlite_master row
	nameEntry := bytes.Index(small, appendIndexEntry(nil, tagName, typeString, 0, 1))
	if rootPage < len("PackagesPackages") || nameEntry < 0 {
		t.Fatal("fixture layout changed: sqlite_master row or NAME entry not found")
	}

	tests := []struct {
		name    string
		data    []byte
		want    []Package
		wantErr string
	}{
		{name: "garbage", data: []byte("SQLite format 3 is what this pretends to be but it is not, not at all, no way, never"), wantErr: "not a SQLite 3 database"},
		{name: "empty", data: nil, wantErr: "not a SQLite 3 database"},
		{name: "header only", data: small[:sqliteHeaderSize], wantErr: "file shorter than one page"},
		{name: "half the file", data: small[:len(small)/2], wantErr: "larger than the file"},
		{name: "three quarters of the file", data: small[:len(small)*3/4], wantErr: "does not exist"},
		{name: "bad page size", data: patch16(small, 16, 0x300), wantErr: "invalid page size 768"},
		{name: "page size too small", data: patch16(small, 16, 256), wantErr: "invalid page size 256"},
		{name: "page size 1 means 65536", data: patch16(small, 16, 1), wantErr: "file shorter than one page"},
		{name: "bad fractions", data: patchByte(small, 21, 65), wantErr: "unexpected payload fractions"},
		{name: "reserved space too large", data: patchByte(small, 20, 200), wantErr: "usable page size 312 is too small"},
		{name: "unknown encoding", data: patch32(small, 56, 4), wantErr: "unknown text encoding 4"},
		{name: "encoding zero is read as UTF-8", data: patch32(small, 56, 0), want: smallPackages},
		{name: "no Packages table", data: readFixture(t, "no-packages-table.sqlite"), wantErr: `table "Packages" not found`},
		{name: "negative root page", data: patchByte(small, rootPage, 0xff), wantErr: `table "Packages" has invalid root page -1`},
		{name: "root page beyond file", data: patchByte(small, rootPage, 100), wantErr: `table "Packages" has invalid root page 100`},
		{name: "b-tree cycle", data: patch32(small, rootOff+8, root), wantErr: "page 3 is referenced twice"},
		{name: "child page beyond file", data: patch32(small, rootOff+8, 999), wantErr: "page 999 does not exist"},
		{name: "child page without blobs", data: patch32(small, rootOff+8, 1), wantErr: "has no BLOB column"},
		{name: "unknown page type", data: patchByte(small, rootOff, 0x07), wantErr: "page 3 has unknown page type 0x7"},
		{name: "index page in table tree", data: patchByte(small, rootOff, pageInteriorIndex), wantErr: "page 3 is an index page"},
		{name: "interior cell count too large", data: patch16(small, rootOff+3, 0xffff), wantErr: "page 3: 65535 cells do not fit"},
		{name: "interior cell pointer in header", data: patch16(small, rootOff+12, 0), wantErr: "page 3: cell 0 at invalid offset 0"},
		{name: "interior cell pointer beyond page", data: patch16(small, rootOff+12, 510), wantErr: "cell 0 at invalid offset 510"},
		{name: "leaf cell count too large", data: patch16(small, leafOff+3, 0xffff), wantErr: "cells do not fit"},
		{name: "leaf cell pointer in header", data: patch16(small, leafOff+8, 1), wantErr: "cell 0 at invalid offset 1"},
		{name: "leaf cell beyond usable page", data: patch16(small, leafOff+8, 0xffff), wantErr: "cell offset 65535 beyond the usable page"},
		{name: "leaf cell at page end", data: patch16(small, leafOff+8, 511), wantErr: "truncated"},
		{name: "overflow cycle", data: patchOverflow(small, func(p int) uint32 { return uint32(p) }), wantErr: "is referenced twice"},
		{name: "overflow chain ends early", data: patchOverflow(small, func(int) uint32 { return 0 }), wantErr: "overflow chain ends with"},
		{name: "overflow page beyond file", data: patchOverflow(small, func(int) uint32 { return 9999 }), wantErr: "overflow chain: page 9999 does not exist"},
		{name: "corrupt header blob", data: patchByte(small, nameEntry+7, 10), wantErr: "unknown data type 10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(FormatSQLite, tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
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

// TestParseSQLiteMutations corrupts the small fixture at random (fixed
// seed) and requires that the parser neither panics nor hangs.
func TestParseSQLiteMutations(t *testing.T) {
	small := readFixture(t, "packages-small.sqlite")
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 5000; i++ {
		data := append([]byte{}, small...)
		for flips := 1 + rng.Intn(8); flips > 0; flips-- {
			data[rng.Intn(len(data))] = byte(rng.Intn(256))
		}
		if rng.Intn(4) == 0 {
			data = data[:rng.Intn(len(data)+1)]
		}
		Parse(FormatSQLite, data)
	}
}

func TestVarint(t *testing.T) {
	tests := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{nil, 0, 0},
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0x81, 0x7f, 0x05}, 255, 2},
		{[]byte{0xff, 0x7f}, 0x3fff, 2},
		{[]byte{0x80}, 0, 0},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0, 0},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffffffff, 9},
		{[]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 1 << 57, 9},
	}
	for _, tt := range tests {
		got, n := varint(tt.in)
		if got != tt.want || n != tt.n {
			t.Errorf("varint(%x) = %d, %d; want %d, %d", tt.in, got, n, tt.want, tt.n)
		}
	}
}

func TestSerialSize(t *testing.T) {
	tests := []struct {
		serial uint64
		size   uint64
		err    bool
	}{
		{0, 0, false}, {1, 1, false}, {2, 2, false}, {3, 3, false}, {4, 4, false}, {5, 6, false}, {6, 8, false}, {7, 8, false},
		{8, 0, false}, {9, 0, false}, {10, 0, true}, {11, 0, true}, {12, 0, false}, {13, 0, false}, {14, 1, false}, {15, 1, false},
		{10012, 5000, false}, {10013, 5000, false}, {1 << 63, 1<<62 - 6, false},
	}
	for _, tt := range tests {
		size, err := serialSize(tt.serial)
		if (err != nil) != tt.err || size != tt.size {
			t.Errorf("serialSize(%d) = %d, %v; want %d, err=%v", tt.serial, size, err, tt.size, tt.err)
		}
	}
}

func TestDecodeRecord(t *testing.T) {
	record := func(header []byte, body ...[]byte) []byte {
		out := append([]byte{byte(len(header) + 1)}, header...)
		for _, b := range body {
			out = append(out, b...)
		}
		return out
	}
	good := record([]byte{0, 1, 2, 23, 14 + 2, 8, 9, 6}, []byte{0xfe}, []byte{0x12, 0x34}, []byte("table"), []byte{1, 2}, []byte{0, 0, 0, 0, 0, 0, 0, 5})
	cols, err := decodeRecord(good)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	wantSerials := []uint64{0, 1, 2, 23, 16, 8, 9, 6}
	for i, c := range cols {
		if i >= len(wantSerials) || c.serial != wantSerials[i] {
			t.Fatalf("column %d serial %d, want %v", i, c.serial, wantSerials)
		}
	}
	if v, ok := intValue(cols[1]); !ok || v != -2 {
		t.Errorf("int8 column = %d, %v; want -2", v, ok)
	}
	if v, ok := intValue(cols[2]); !ok || v != 0x1234 {
		t.Errorf("int16 column = %d, %v; want 0x1234", v, ok)
	}
	if v, ok := intValue(cols[5]); !ok || v != 0 {
		t.Errorf("serial 8 column = %d, %v; want 0", v, ok)
	}
	if v, ok := intValue(cols[6]); !ok || v != 1 {
		t.Errorf("serial 9 column = %d, %v; want 1", v, ok)
	}
	if v, ok := intValue(cols[7]); !ok || v != 5 {
		t.Errorf("int64 column = %d, %v; want 5", v, ok)
	}
	if _, ok := intValue(cols[3]); ok {
		t.Error("text column reported as integer")
	}
	f := &sqliteFile{encoding: encodingUTF8}
	if s := f.text(cols[3]); s != "table" {
		t.Errorf("text column = %q", s)
	}
	if s := f.text(cols[4]); s != "" {
		t.Errorf("blob column as text = %q, want empty", s)
	}
	if blob, ok := firstBlob(cols); !ok || !bytes.Equal(blob, []byte{1, 2}) {
		t.Errorf("firstBlob = %x, %v", blob, ok)
	}
	if _, ok := firstBlob(cols[:4]); ok {
		t.Error("firstBlob found a blob among non-blob columns")
	}

	bad := []struct {
		name string
		rec  []byte
	}{
		{"empty", nil},
		{"header length zero", []byte{0}},
		{"header length beyond record", []byte{9, 1, 2}},
		{"truncated serial type", []byte{2, 0x80}},
		{"reserved serial type 10", record([]byte{10}, nil)},
		{"reserved serial type 11", record([]byte{11}, nil)},
		{"column exceeds record", record([]byte{4}, []byte{1})},
		{"huge blob column", append([]byte{10}, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe)},
	}
	for _, tt := range bad {
		if _, err := decodeRecord(tt.rec); err == nil {
			t.Errorf("%s: no error", tt.name)
		}
	}
}

func TestTextUTF16(t *testing.T) {
	le := &sqliteFile{encoding: encodingUTF16LE}
	be := &sqliteFile{encoding: encodingUTF16BE}
	col := func(b []byte) column { return column{serial: 13 + 2*uint64(len(b)), data: b} }
	if s := le.text(col([]byte{'P', 0, 'k', 0, 0xac, 0x20})); s != "Pk€" {
		t.Errorf("UTF-16LE text = %q", s)
	}
	if s := be.text(col([]byte{0, 'P', 0, 'k', 0x20, 0xac})); s != "Pk€" {
		t.Errorf("UTF-16BE text = %q", s)
	}
	if s := le.text(col([]byte{'P'})); s != "" {
		t.Errorf("odd-length UTF-16 text = %q, want empty", s)
	}
}

func TestLocalPayload(t *testing.T) {
	tests := []struct {
		usable, total, want int
	}{
		{512, 0, 0},
		{512, 477, 477},   // X = U-35 fits entirely
		{512, 478, 39},    // K = 478 > X, so M = (500*32/255)-23 = 39
		{512, 600, 92},    // K = 39 + (561 % 508) = 92
		{512, 5233, 153},  // K = 39 + (5194 % 508) = 153
		{1024, 989, 989},  // X = 989
		{1024, 1000, 103}, // M = (1012*32/255)-23 = 126-23 = 103; K = 1000 > X
		{1024, 1500, 480},
		{4096, 4061, 4061},
		{4096, 17520, 1152}, // M = 489; K = 489 + (17031 % 4092) = 1152
	}
	for i, tt := range tests {
		f := &sqliteFile{usable: tt.usable}
		if got := f.localPayload(tt.total); got != tt.want {
			t.Errorf("case %d: localPayload(usable=%d, total=%d) = %d, want %d", i, tt.usable, tt.total, got, tt.want)
		}
	}
}

func FuzzParseSQLite(f *testing.F) {
	for _, name := range []string{"packages-small.sqlite", "packages-utf16le.sqlite", "no-packages-table.sqlite"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(FormatSQLite, data)
	})
}
