package rpmdb

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

// ndbBlob is one package for buildNDB.
type ndbBlob struct {
	index uint32
	blob  []byte
}

// buildNDB lays out a Packages.db file the way rpm's rpmpkg.c does: a
// 32-byte header, one 16-byte slot per blob in the given order (the rest
// empty) across slotPages 4 KiB pages, then each blob in 16-byte blocks
// with its 16-byte header and a 16-byte trailer.
func buildNDB(slotPages uint32, blobs []ndbBlob) []byte {
	le := binary.LittleEndian
	file := make([]byte, int(slotPages)*ndbPageSize)
	copy(file, ndbMagic)
	le.PutUint32(file[4:], ndbVersion)
	le.PutUint32(file[8:], 7) // generation
	le.PutUint32(file[12:], slotPages)
	le.PutUint32(file[16:], uint32(len(blobs))+1) // next package index
	for off := ndbHeaderSize; off < len(file); off += ndbSlotSize {
		copy(file[off:], ndbSlotMagic)
	}
	for i, b := range blobs {
		blkOff := uint32(len(file) / ndbBlockSize)
		blkCnt := uint32((ndbBlobHeaderSize + len(b.blob) + 16 + ndbBlockSize - 1) / ndbBlockSize)
		slot := file[ndbHeaderSize+i*ndbSlotSize:]
		le.PutUint32(slot[4:], b.index)
		le.PutUint32(slot[8:], blkOff)
		le.PutUint32(slot[12:], blkCnt)
		block := make([]byte, int(blkCnt)*ndbBlockSize)
		copy(block, ndbBlobMagic)
		le.PutUint32(block[4:], b.index)
		le.PutUint32(block[8:], 7)
		le.PutUint32(block[12:], uint32(len(b.blob)))
		copy(block[ndbBlobHeaderSize:], b.blob)
		copy(block[len(block)-4:], "BlbE")
		file = append(file, block...)
	}
	return file
}

func TestParseNDB(t *testing.T) {
	a := buildHeader(false, strEntry(tagName, "a"), strEntry(tagVersion, "1"), strEntry(tagRelease, "1.suse"), strEntry(tagArch, "x86_64"))
	b := buildRegionHeader(strEntry(tagName, "b"), strEntry(tagVersion, "2"), strEntry(tagRelease, "2"), int32Entry(tagEpoch, 3), strEntry(tagArch, "noarch"), binEntry(1013, make([]byte, 5000)))
	c := buildHeader(false, strEntry(tagName, "c"), strEntry(tagVersion, "3"))
	pa := Package{Name: "a", Version: "1", Release: "1.suse", Arch: "x86_64"}
	pb := Package{Name: "b", Version: "2", Release: "2", Epoch: "3", Arch: "noarch"}
	pc := Package{Name: "c", Version: "3"}
	good := buildNDB(1, []ndbBlob{{5, b}, {2, a}, {9, c}})

	tests := []struct {
		name    string
		data    []byte
		want    []Package
		wantErr string
		unsupp  bool
	}{
		{name: "empty database", data: buildNDB(1, nil), want: []Package{}},
		{name: "two slot pages", data: buildNDB(2, []ndbBlob{{1, a}}), want: []Package{pa}},
		{name: "sorted by package index", data: good, want: []Package{pa, pb, pc}},
		{name: "garbage", data: []byte("nothing like an rpm database at all"), wantErr: "not an rpm ndb database"},
		{name: "empty", data: nil, wantErr: "not an rpm ndb database"},
		{name: "header only", data: good[:ndbHeaderSize], wantErr: "truncated: 1 slot pages need 4096 bytes, file has 32"},
		{name: "version 1", data: patch(good, 4, 1), wantErr: "ndb version 1", unsupp: true},
		{name: "zero slot pages", data: patch(good, 12, 0), wantErr: "implausible slot page count 0"},
		{name: "too many slot pages", data: patch(good, 12, 2049), wantErr: "implausible slot page count 2049"},
		{name: "more slot pages than the file", data: patch(buildNDB(1, nil), 12, 2), wantErr: "truncated: 2 slot pages need 8192 bytes, file has 4096"},
		{name: "slot pages covering the blobs", data: patch(good, 12, 2), wantErr: "bad slot magic at offset 4096"},
		{name: "bad slot magic", data: patchBytes(good, ndbHeaderSize+2*ndbSlotSize, "Slip"), wantErr: "bad slot magic at offset 64"},
		{name: "blob inside the slot area", data: patch(good, ndbHeaderSize+8, 1), wantErr: "package 5: blocks 1+"},
		{name: "blob beyond the file", data: patch(good, ndbHeaderSize+8, 0x7fffffff), wantErr: "package 5: blocks 2147483647+"},
		{name: "block count overflow", data: patch(good, ndbHeaderSize+12, 0xffffffff), wantErr: "lie outside the file"},
		{name: "zero block count", data: patch(good, ndbHeaderSize+12, 0), wantErr: "package 5: blocks 256+0 lie outside the file"},
		{name: "bad blob magic", data: patchBytes(good, ndbPageSize, "BlbX"), wantErr: "package 5: bad blob magic at offset 4096"},
		{name: "blob of another package", data: patch(good, ndbPageSize+4, 6), wantErr: "package 5: blob at offset 4096 belongs to package 6"},
		{name: "blob length beyond its blocks", data: patch(good, ndbPageSize+12, 100000), wantErr: "package 5: blob length 100000 exceeds its"},
		{name: "corrupt header blob", data: patch(good, ndbPageSize+16, 0xffffffff), wantErr: "package 5: implausible header"},
		{name: "truncated in a blob", data: good[:len(good)-40], wantErr: "lie outside the file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(FormatNDB, tt.data)
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

// patch returns a copy of data with a little-endian uint32 written at off.
func patch(data []byte, off int, v uint32) []byte {
	out := append([]byte{}, data...)
	binary.LittleEndian.PutUint32(out[off:], v)
	return out
}

// patchBytes returns a copy of data with s written at off.
func patchBytes(data []byte, off int, s string) []byte {
	out := append([]byte{}, data...)
	copy(out[off:], s)
	return out
}

func FuzzParseNDB(f *testing.F) {
	f.Add(buildNDB(1, []ndbBlob{{1, buildHeader(false, nevraEntries...)}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(FormatNDB, data)
	})
}
