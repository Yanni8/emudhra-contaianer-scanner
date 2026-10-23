package rpmdb

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"
)

// hdrEntry describes one index entry for buildHeader.
type hdrEntry struct {
	tag   int32
	typ   uint32
	data  []byte
	count uint32
}

func strEntry(tag int32, s string) hdrEntry {
	return hdrEntry{tag, typeString, append([]byte(s), 0), 1}
}
func i18nEntry(tag int32, s string) hdrEntry {
	return hdrEntry{tag, typeI18NString, append([]byte(s), 0), 1}
}
func binEntry(tag int32, b []byte) hdrEntry { return hdrEntry{tag, typeBin, b, uint32(len(b))} }

func strArrayEntry(tag int32, ss ...string) hdrEntry {
	var b []byte
	for _, s := range ss {
		b = append(append(b, s...), 0)
	}
	return hdrEntry{tag, typeStringArray, b, uint32(len(ss))}
}

func int32Entry(tag int32, v int32) hdrEntry {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return hdrEntry{tag, typeInt32, b, 1}
}

// typeAlign is the data alignment rpm applies per type.
func typeAlign(typ uint32) int {
	switch typ {
	case typeInt16:
		return 2
	case typeInt32:
		return 4
	case typeInt64:
		return 8
	}
	return 1
}

// buildHeader lays entries out the way rpm does: index entries in the
// given order, data aligned per type, no region tag.
func buildHeader(withMagic bool, entries ...hdrEntry) []byte {
	var index, data []byte
	for _, e := range entries {
		for len(data)%typeAlign(e.typ) != 0 {
			data = append(data, 0)
		}
		index = appendIndexEntry(index, e.tag, e.typ, int32(len(data)), e.count)
		data = append(data, e.data...)
	}
	return assembleHeader(withMagic, index, data)
}

// buildRegionHeader builds a header with the immutable-region tag rpm adds
// to every installed header: entry 0 is tag 63 pointing at a 16-byte
// trailer at the end of the data whose offset field is negative.
func buildRegionHeader(entries ...hdrEntry) []byte {
	plain := buildHeader(false, entries...)
	il := int(binary.BigEndian.Uint32(plain[0:4]))
	dl := int(binary.BigEndian.Uint32(plain[4:8]))
	index := plain[8 : 8+il*16]
	data := plain[8+il*16 : 8+il*16+dl]
	regionIndex := appendIndexEntry(nil, 63, typeBin, int32(len(data)), 16)
	trailer := appendIndexEntry(nil, 63, typeBin, -int32((il+1)*16), 16)
	return assembleHeader(false, append(regionIndex, index...), append(append([]byte{}, data...), trailer...))
}

func appendIndexEntry(b []byte, tag int32, typ uint32, offset int32, count uint32) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(tag))
	b = binary.BigEndian.AppendUint32(b, typ)
	b = binary.BigEndian.AppendUint32(b, uint32(offset))
	return binary.BigEndian.AppendUint32(b, count)
}

// assembleHeader prefixes index and data with their lengths (and the file
// magic when asked).
func assembleHeader(withMagic bool, index, data []byte) []byte {
	var b []byte
	if withMagic {
		b = append(b, 0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(index)/16))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	return append(append(b, index...), data...)
}

// rawHeader builds a blob with arbitrary (possibly lying) lengths.
func rawHeader(il, dl uint32, index, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, il)
	b = binary.BigEndian.AppendUint32(b, dl)
	return append(append(b, index...), data...)
}

var nevraEntries = []hdrEntry{
	strEntry(tagName, "ca-certificates"),
	strEntry(tagVersion, "2025.2.80_v9.0.305"),
	strEntry(tagRelease, "91.el9"),
	strEntry(tagArch, "noarch"),
}

var nevraPackage = Package{Name: "ca-certificates", Version: "2025.2.80_v9.0.305", Release: "91.el9", Arch: "noarch"}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		blob    []byte
		want    Package
		wantErr string
	}{
		{name: "nevra", blob: buildHeader(false, nevraEntries...), want: nevraPackage},
		{name: "with file magic", blob: buildHeader(true, nevraEntries...), want: nevraPackage},
		{name: "with region tag", blob: buildRegionHeader(nevraEntries...), want: nevraPackage},
		{
			name: "epoch",
			blob: buildHeader(false, strEntry(tagName, "openssl-libs"), strEntry(tagVersion, "3.5.8"), strEntry(tagRelease, "2.el9_8"), int32Entry(tagEpoch, 1), strEntry(tagArch, "x86_64")),
			want: Package{Name: "openssl-libs", Version: "3.5.8", Release: "2.el9_8", Epoch: "1", Arch: "x86_64"},
		},
		{
			name: "epoch zero is kept as written",
			blob: buildHeader(false, strEntry(tagName, "a"), strEntry(tagVersion, "1"), int32Entry(tagEpoch, 0)),
			want: Package{Name: "a", Version: "1", Epoch: "0"},
		},
		{
			name: "negative epoch is decoded as int32",
			blob: buildHeader(false, strEntry(tagName, "a"), int32Entry(tagEpoch, -5)),
			want: Package{Name: "a", Epoch: "-5"},
		},
		{
			name: "other tags and types are skipped",
			blob: buildHeader(false, int32Entry(1009, 12345), binEntry(1013, []byte{1, 2, 3}), strEntry(tagName, "a"), strArrayEntry(1047, "x", "y"), i18nEntry(1004, "Summary"), hdrEntry{1028, typeInt16, []byte{0, 7}, 1}, hdrEntry{1033, typeInt64, make([]byte, 8), 1}, hdrEntry{1050, typeChar, []byte{'c'}, 1}, hdrEntry{1051, typeInt8, []byte{1}, 1}, hdrEntry{1052, typeNull, nil, 0}, strEntry(tagVersion, "1")),
			want: Package{Name: "a", Version: "1"},
		},
		{
			name: "i18n and array strings take the first value",
			blob: buildHeader(false, i18nEntry(tagName, "a"), strArrayEntry(tagVersion, "1", "2"), strArrayEntry(tagRelease, "r")),
			want: Package{Name: "a", Version: "1", Release: "r"},
		},
		{
			name: "gpg-pubkey without arch",
			blob: buildHeader(false, strEntry(tagName, "gpg-pubkey"), strEntry(tagVersion, "fd431d51"), strEntry(tagRelease, "4ae0493b")),
			want: Package{Name: "gpg-pubkey", Version: "fd431d51", Release: "4ae0493b"},
		},
		{
			name: "repeated tag: last wins",
			blob: buildHeader(false, strEntry(tagName, "first"), strEntry(tagName, "second")),
			want: Package{Name: "second"},
		},
		{name: "empty", blob: nil, wantErr: "too short"},
		{name: "seven bytes", blob: make([]byte, 7), wantErr: "too short"},
		{name: "magic only", blob: []byte{0x8e, 0xad, 0xe8, 0x01}, wantErr: "truncated header magic"},
		{name: "magic and nothing else", blob: []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}, wantErr: "too short"},
		{name: "no entries", blob: rawHeader(0, 0, nil, nil), wantErr: "no NAME tag"},
		{name: "huge index length", blob: rawHeader(0x10000, 0, nil, nil), wantErr: "implausible"},
		{name: "maximal index length", blob: rawHeader(0xffffffff, 0, nil, nil), wantErr: "implausible"},
		{name: "huge data length", blob: rawHeader(1, 0x10000000, nil, nil), wantErr: "implausible"},
		{name: "index length beyond blob", blob: rawHeader(2, 0, appendIndexEntry(nil, tagName, typeString, 0, 1), nil), wantErr: "truncated header: need 40 bytes, have 24"},
		{name: "data length beyond blob", blob: rawHeader(1, 100, appendIndexEntry(nil, tagName, typeString, 0, 1), []byte("a\x00")), wantErr: "truncated header"},
		{name: "no name", blob: buildHeader(false, strEntry(tagVersion, "1"), strEntry(tagRelease, "2")), wantErr: "no NAME tag"},
		{name: "empty name", blob: buildHeader(false, strEntry(tagName, ""), strEntry(tagVersion, "1")), wantErr: "no NAME tag"},
		{name: "name with int type", blob: buildHeader(false, int32Entry(tagName, 1)), wantErr: "tag 1000: data type 4 is not a string type"},
		{name: "name with bin type", blob: buildHeader(false, binEntry(tagName, []byte("a\x00"))), wantErr: "not a string type"},
		{name: "name count 0", blob: buildHeader(false, hdrEntry{tagName, typeString, []byte("a\x00"), 0}), wantErr: "count 0"},
		{name: "unterminated name", blob: buildHeader(false, hdrEntry{tagName, typeString, []byte("abc"), 1}), wantErr: "unterminated string"},
		{name: "name offset at end of data", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, typeString, 2, 1), []byte("a\x00")), wantErr: "unterminated string"},
		{name: "name offset beyond data", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, typeString, 3, 1), []byte("a\x00")), wantErr: "offset 3 outside the 2-byte data section"},
		{name: "negative offset", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, typeString, -1, 1), []byte("a\x00")), wantErr: "offset -1 outside"},
		{name: "huge offset", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, typeString, 0x7fffffff, 1), []byte("a\x00")), wantErr: "outside"},
		{name: "unknown type on an unrelated tag", blob: rawHeader(2, 2, append(appendIndexEntry(nil, tagName, typeString, 0, 1), appendIndexEntry(nil, 5000, 10, 0, 1)...), []byte("a\x00")), wantErr: "index entry 1: unknown data type 10"},
		{name: "huge type", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, 0xffffffff, 0, 1), []byte("a\x00")), wantErr: "unknown data type"},
		{name: "huge count is harmless", blob: rawHeader(1, 2, appendIndexEntry(nil, tagName, typeStringArray, 0, 0xffffffff), []byte("a\x00")), want: Package{Name: "a"}},
		{name: "epoch with string type", blob: buildHeader(false, strEntry(tagName, "a"), strEntry(tagEpoch, "1")), wantErr: "tag 1003: data type 6 is not INT32"},
		{name: "epoch count 0", blob: buildHeader(false, strEntry(tagName, "a"), hdrEntry{tagEpoch, typeInt32, []byte{0, 0, 0, 1}, 0}), wantErr: "count 0"},
		{name: "epoch truncated", blob: rawHeader(2, 4, append(appendIndexEntry(nil, tagName, typeString, 0, 1), appendIndexEntry(nil, tagEpoch, typeInt32, 2, 1)...), []byte("a\x00\x00\x01")), wantErr: "INT32 value truncated"},
		{name: "epoch at end of data", blob: rawHeader(2, 2, append(appendIndexEntry(nil, tagName, typeString, 0, 1), appendIndexEntry(nil, tagEpoch, typeInt32, 2, 1)...), []byte("a\x00")), wantErr: "INT32 value truncated"},
		{name: "trailing garbage is ignored", blob: append(buildHeader(false, nevraEntries...), "garbage"...), want: nevraPackage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeader(tt.blob)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseHeader() error = %v, want one containing %q", err, tt.wantErr)
				}
				if got != (Package{}) {
					t.Errorf("ParseHeader() = %+v on error, want zero Package", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHeader() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestParseHeaderTruncated feeds every prefix of valid headers to the
// parser: all must fail cleanly, only the whole blob may succeed.
func TestParseHeaderTruncated(t *testing.T) {
	for name, blob := range map[string][]byte{
		"plain":  buildHeader(false, nevraEntries...),
		"magic":  buildHeader(true, nevraEntries...),
		"region": buildRegionHeader(append(nevraEntries, int32Entry(tagEpoch, 3))...),
	} {
		for n := 0; n < len(blob); n++ {
			if _, err := ParseHeader(blob[:n]); err == nil {
				t.Errorf("%s: prefix of %d/%d bytes parsed without error", name, n, len(blob))
			}
		}
		if _, err := ParseHeader(blob); err != nil {
			t.Errorf("%s: whole blob: %v", name, err)
		}
	}
}

// TestParseHeaderMutations corrupts valid headers at random (with a fixed
// seed) and only requires that the parser never panics or hangs.
func TestParseHeaderMutations(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := buildRegionHeader(append(nevraEntries, int32Entry(tagEpoch, 3), i18nEntry(1004, "Summary"), binEntry(1013, make([]byte, 40)))...)
	for i := 0; i < 20000; i++ {
		blob := append([]byte{}, base...)
		for flips := 1 + rng.Intn(4); flips > 0; flips-- {
			blob[rng.Intn(len(blob))] = byte(rng.Intn(256))
		}
		if rng.Intn(4) == 0 {
			blob = blob[:rng.Intn(len(blob)+1)]
		}
		ParseHeader(blob)
	}
}

func FuzzParseHeader(f *testing.F) {
	f.Add(buildHeader(false, nevraEntries...))
	f.Add(buildHeader(true, nevraEntries...))
	f.Add(buildRegionHeader(append(nevraEntries, int32Entry(tagEpoch, 1))...))
	f.Fuzz(func(t *testing.T, blob []byte) {
		p, err := ParseHeader(blob)
		if err != nil && p != (Package{}) {
			t.Errorf("non-zero package %+v returned with error %v", p, err)
		}
		if err == nil && p.Name == "" {
			t.Errorf("empty name without error for %x", blob)
		}
	})
}
