package image

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Yanni8/emudhra-container-scanner/internal/units"
)

// tarRecord is one entry of a tar stream as the tests compare them.
type tarRecord struct {
	name     string
	typeflag byte
	linkname string
	mode     int64
	size     int64
	content  string
	pax      map[string]string
}

// drainTar reads a whole tar stream with archive/tar, the reader the scan
// package uses, and returns its entries in order.
func drainTar(t *testing.T, r io.Reader) []tarRecord {
	t.Helper()
	var recs []tarRecord
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return recs
		}
		if err != nil {
			t.Fatalf("reading tar entry %d: %v", len(recs), err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s: %v", hdr.Name, err)
		}
		recs = append(recs, tarRecord{
			name:     hdr.Name,
			typeflag: hdr.Typeflag,
			linkname: hdr.Linkname,
			mode:     hdr.Mode,
			size:     hdr.Size,
			content:  string(data),
			pax:      hdr.PAXRecords,
		})
	}
}

// flattenToRecords runs flatten over the layers of img.
func flattenToRecords(t *testing.T, img v1.Image, report func(string)) []tarRecord {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("Layers: %v", err)
	}
	var buf bytes.Buffer
	if err := flatten(layers, &buf, reporter(report)); err != nil {
		t.Fatalf("flatten: %v", err)
	}
	return drainTar(t, &buf)
}

func recordNames(recs []tarRecord) []string {
	names := make([]string, 0, len(recs))
	for _, r := range recs {
		names = append(names, r.name)
	}
	return names
}

func findRecord(recs []tarRecord, name string) (tarRecord, bool) {
	for _, r := range recs {
		if r.name == name {
			return r, true
		}
	}
	return tarRecord{}, false
}

func TestFlattenMatchesMutateExtract(t *testing.T) {
	mozilla := "usr/share/ca-certificates/mozilla"
	tests := []struct {
		name   string
		layers []v1.Layer
		// present maps names that must be in the result to their content
		// (ignored for non-regular entries); absent lists names that must
		// not be.
		present map[string]string
		absent  []string
	}{
		{
			name:    "fixture with whiteout and override",
			layers:  []v1.Layer{baseLayer(t, "linux/amd64"), topLayer(t)},
			present: map[string]string{"etc/ssl/certs/ca-certificates.crt": "override bundle", mozilla + "/B.crt": "cert B", "etc/ssl/cert.pem": ""},
			absent:  []string{mozilla + "/A.crt", mozilla + "/.wh.A.crt"},
		},
		{
			name: "opaque directory hides lower contents but not its own layer",
			layers: []v1.Layer{
				baseLayer(t, "linux/amd64"),
				layerFromTar(t, tarArchive(t,
					fileEntry(mozilla+"/.wh..wh..opq", ""),
					fileEntry(mozilla+"/C.crt", "cert C"),
				)),
			},
			present: map[string]string{mozilla + "/C.crt": "cert C", mozilla: "", "etc/os-release": "ID=test\nPLATFORM=linux/amd64\n"},
			absent:  []string{mozilla + "/A.crt", mozilla + "/B.crt", mozilla + "/.wh..wh..opq"},
		},
		{
			name: "whiteout of a directory hides the subtree",
			layers: []v1.Layer{
				baseLayer(t, "linux/amd64"),
				layerFromTar(t, tarArchive(t, fileEntry("usr/share/.wh.ca-certificates", ""))),
			},
			present: map[string]string{"usr/share": "", "etc/os-release": "ID=test\nPLATFORM=linux/amd64\n"},
			absent:  []string{"usr/share/ca-certificates", mozilla, mozilla + "/A.crt", mozilla + "/B.crt"},
		},
		{
			name: "file over a directory hides its children",
			layers: []v1.Layer{
				baseLayer(t, "linux/amd64"),
				layerFromTar(t, tarArchive(t, fileEntry("usr/share/ca-certificates", "now a file"))),
			},
			present: map[string]string{"usr/share/ca-certificates": "now a file"},
			absent:  []string{mozilla, mozilla + "/A.crt"},
		},
		{
			name: "dot-slash names and duplicates within a layer",
			layers: []v1.Layer{layerFromTar(t, tarArchive(t,
				dirEntry("./etc"),
				fileEntry("./etc/os-release", "first"),
				fileEntry("etc/os-release", "second"),
				dirEntry("etc"),
			))},
			present: map[string]string{"etc": "", "etc/os-release": "first"},
			absent:  []string{"./etc", "./etc/os-release"},
		},
		{
			name: "links escaping the root are dropped, others kept",
			layers: []v1.Layer{layerFromTar(t, tarArchive(t,
				dirEntry("etc"),
				fileEntry("etc/os-release", "x"),
				symlinkEntry("etc/evil", "../../../../etc/passwd"),
				symlinkEntry("etc/fine", "../usr/share/x"),
				symlinkEntry("etc/absolute", "/etc/passwd"),
				linkEntry("etc/hard", "etc/os-release"),
				linkEntry("etc/hard-evil", "../../outside"),
			))},
			present: map[string]string{"etc/fine": "", "etc/absolute": "", "etc/hard": "", "etc/os-release": "x"},
			absent:  []string{"etc/evil", "etc/hard-evil"},
		},
		{
			name: "whiteout in a middle layer, file re-added above",
			layers: []v1.Layer{
				layerFromTar(t, tarArchive(t, fileEntry("a.txt", "v1"), fileEntry("b.txt", "v1"))),
				layerFromTar(t, tarArchive(t, fileEntry(".wh.a.txt", ""), fileEntry(".wh.b.txt", ""))),
				layerFromTar(t, tarArchive(t, fileEntry("a.txt", "v3"))),
			},
			present: map[string]string{"a.txt": "v3"},
			absent:  []string{"b.txt", ".wh.a.txt", ".wh.b.txt"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := buildImage(t, linuxAMD64, nil, tc.layers...)
			got := flattenToRecords(t, img, nil)

			rc := mutate.Extract(img)
			defer rc.Close()
			want := drainTar(t, rc)
			strip := func(recs []tarRecord) []tarRecord {
				out := make([]tarRecord, len(recs))
				for i, r := range recs {
					r.pax = nil
					out[i] = r
				}
				return out
			}
			if g, w := strip(got), strip(want); !reflect.DeepEqual(g, w) {
				t.Errorf("flatten differs from mutate.Extract:\n got %q\nwant %q", recordNames(g), recordNames(w))
			}

			for name, content := range tc.present {
				r, ok := findRecord(got, name)
				if !ok {
					t.Errorf("entry %q missing from %q", name, recordNames(got))
					continue
				}
				if r.typeflag == tar.TypeReg && r.content != content {
					t.Errorf("entry %q content = %q, want %q", name, r.content, content)
				}
			}
			for _, name := range tc.absent {
				if _, ok := findRecord(got, name); ok {
					t.Errorf("entry %q should be hidden", name)
				}
			}
			seen := map[string]bool{}
			for _, r := range got {
				if seen[r.name] {
					t.Errorf("entry %q appears twice", r.name)
				}
				seen[r.name] = true
			}
		})
	}
}

// rawHeader is a hand-made 512-byte tar header block. archive/tar's writer
// cannot produce GNU sparse entries, so the tests build them by hand.
type rawHeader [512]byte

// newRawHeader fills the ustar fields shared by every entry type.
func newRawHeader(name string, typeflag byte, size int64) *rawHeader {
	h := &rawHeader{}
	copy(h[0:], name)
	h.octal(100, 8, 0o644)
	h.octal(108, 8, 0)
	h.octal(116, 8, 0)
	h.octal(124, 12, size)
	h.octal(136, 12, 0)
	h[156] = typeflag
	copy(h[257:], "ustar\x0000")
	return h
}

// gnu switches the block to the GNU magic that old-style sparse entries
// require.
func (h *rawHeader) gnu() *rawHeader {
	copy(h[257:], "ustar  \x00")
	return h
}

// octal writes v as a NUL-terminated octal field of the given width.
func (h *rawHeader) octal(off, width int, v int64) {
	copy(h[off:], fmt.Sprintf("%0*o", width-1, v))
}

// entry seals the checksum and returns the header followed by data, padded
// to a whole block.
func (h *rawHeader) entry(data []byte) []byte {
	copy(h[148:], "        ")
	var sum int64
	for _, c := range h {
		sum += int64(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
	return append(append([]byte(nil), h[:]...), padBlock(data)...)
}

// padBlock pads b with NULs to a multiple of 512 bytes.
func padBlock(b []byte) []byte {
	if rem := len(b) % 512; rem != 0 {
		b = append(b, make([]byte, 512-rem)...)
	}
	return b
}

func rawDir(name string) []byte {
	return newRawHeader(name+"/", tar.TypeDir, 0).entry(nil)
}

func rawFile(name, content string) []byte {
	return newRawHeader(name, tar.TypeReg, int64(len(content))).entry([]byte(content))
}

// rawTrailer is the end-of-archive marker.
func rawTrailer() []byte { return make([]byte, 1024) }

// fragment is a run of data inside a sparse file.
type fragment struct {
	offset int64
	data   string
}

// expandFragments is the logical content of a sparse file.
func expandFragments(size int64, frags []fragment) []byte {
	b := make([]byte, size)
	for _, f := range frags {
		copy(b[f.offset:], f.data)
	}
	return b
}

// oldGNUSparseEntry encodes a sparse file the way `tar --sparse` does in its
// default GNU format: type 'S', the data runs in the header's sparse map
// (ended by an empty run at the end of the file, as GNU tar writes it), the
// real size in the realsize field and only the data runs in the data
// section. At most three fragments fit.
func oldGNUSparseEntry(name string, realSize int64, frags []fragment) []byte {
	var data []byte
	for _, f := range frags {
		data = append(data, f.data...)
	}
	h := newRawHeader(name, tar.TypeGNUSparse, int64(len(data))).gnu()
	for i, f := range frags {
		h.octal(386+24*i, 12, f.offset)
		h.octal(386+24*i+12, 12, int64(len(f.data)))
	}
	h.octal(386+24*len(frags), 12, realSize)
	h.octal(386+24*len(frags)+12, 12, 0)
	h.octal(483, 12, realSize)
	return h.entry(data)
}

// paxRecords encodes key/value pairs as PAX extended header records.
func paxRecords(kv ...string) []byte {
	var b []byte
	for i := 0; i+1 < len(kv); i += 2 {
		rec := " " + kv[i] + "=" + kv[i+1] + "\n"
		total := len(rec) + len(strconv.Itoa(len(rec)))
		if len(strconv.Itoa(total)) > len(strconv.Itoa(len(rec))) {
			total++
		}
		b = append(b, strconv.Itoa(total)+rec...)
	}
	return b
}

// paxSparseEntry encodes a sparse file in GNU's PAX sparse format 1.0 (what
// `tar --sparse --format=posix` writes: the map in the data section) or 0.1
// (the map in the extended header), as an extended header followed by a
// regular entry named GNUSparseFile.0/<base>.
func paxSparseEntry(name string, realSize int64, frags []fragment, version string) []byte {
	var data []byte
	for _, f := range frags {
		data = append(data, f.data...)
	}
	var (
		records []string
		body    []byte
	)
	switch version {
	case "1.0":
		records = []string{"GNU.sparse.major", "1", "GNU.sparse.minor", "0", "GNU.sparse.name", name, "GNU.sparse.realsize", strconv.FormatInt(realSize, 10)}
		m := strconv.Itoa(len(frags)) + "\n"
		for _, f := range frags {
			m += strconv.FormatInt(f.offset, 10) + "\n" + strconv.Itoa(len(f.data)) + "\n"
		}
		body = append(padBlock([]byte(m)), data...)
	case "0.1":
		var m []string
		for _, f := range frags {
			m = append(m, strconv.FormatInt(f.offset, 10), strconv.Itoa(len(f.data)))
		}
		records = []string{"GNU.sparse.numblocks", strconv.Itoa(len(frags)), "GNU.sparse.map", strings.Join(m, ","), "GNU.sparse.size", strconv.FormatInt(realSize, 10), "GNU.sparse.name", name}
		body = data
	default:
		panic("unknown PAX sparse version " + version)
	}
	recs := paxRecords(records...)
	x := newRawHeader(path.Dir(name)+"/PaxHeaders/"+path.Base(name), tar.TypeXHeader, int64(len(recs))).entry(recs)
	f := newRawHeader(path.Dir(name)+"/GNUSparseFile.0/"+path.Base(name), tar.TypeReg, int64(len(body))).entry(body)
	return append(x, f...)
}

func TestFlattenSparseEntries(t *testing.T) {
	const realSize = 8196
	frags := []fragment{{offset: 8192, data: "DATA"}}
	want := expandFragments(realSize, frags)

	tests := []struct {
		name   string
		entry  []byte
		oldGNU bool
	}{
		{name: "old GNU format", entry: oldGNUSparseEntry("opt/sp/lastlog", realSize, frags), oldGNU: true},
		{name: "PAX 1.0", entry: paxSparseEntry("opt/sp/lastlog", realSize, frags, "1.0")},
		{name: "PAX 0.1", entry: paxSparseEntry("opt/sp/lastlog", realSize, frags, "0.1")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var layer []byte
			for _, part := range [][]byte{rawDir("opt"), rawDir("opt/sp"), tc.entry, rawFile("opt/sp/ica.pem", "cert"), rawTrailer()} {
				layer = append(layer, part...)
			}

			// The hand-made layer must be what archive/tar reads as a sparse
			// file of the logical size, or the test proves nothing.
			raw := drainTar(t, bytes.NewReader(layer))
			r, ok := findRecord(raw, "opt/sp/lastlog")
			if !ok {
				t.Fatalf("hand-made layer holds %q", recordNames(raw))
			}
			if r.size != realSize || r.content != string(want) {
				t.Fatalf("archive/tar reads the sparse entry as size %d (content ok: %v)", r.size, r.content == string(want))
			}
			if tc.oldGNU && r.typeflag != tar.TypeGNUSparse {
				t.Fatalf("typeflag = %q, want %q", r.typeflag, tar.TypeGNUSparse)
			}
			if !tc.oldGNU && r.pax["GNU.sparse.major"] == "" && r.pax["GNU.sparse.map"] == "" {
				t.Fatalf("PAX records %v carry no sparse map", r.pax)
			}

			// Through the whole Filesystem path: pipe, flattener, archive/tar.
			img := buildImage(t, linuxAMD64, nil, layerFromTar(t, layer))
			im := &Image{Reference: "test", img: img}
			rc, err := im.Filesystem()
			if err != nil {
				t.Fatalf("Filesystem: %v", err)
			}
			defer rc.Close()
			got := drainTar(t, rc)
			assertStrings(t, "entries", recordNames(got), []string{"opt", "opt/sp", "opt/sp/lastlog", "opt/sp/ica.pem"})
			lastlog := got[2]
			if lastlog.typeflag != tar.TypeReg {
				t.Errorf("lastlog typeflag = %q, want %q", lastlog.typeflag, tar.TypeReg)
			}
			if lastlog.size != realSize {
				t.Errorf("lastlog size = %d, want %d", lastlog.size, realSize)
			}
			if lastlog.content != string(want) {
				t.Errorf("lastlog content differs (len %d, want %d)", len(lastlog.content), len(want))
			}
			for k := range lastlog.pax {
				if strings.HasPrefix(k, "GNU.sparse.") {
					t.Errorf("sparse record %s survived flattening", k)
				}
			}
			if ica := got[3]; ica.content != "cert" {
				t.Errorf("entry after the sparse file = %+v, want content \"cert\"", ica)
			}
		})
	}
}

func TestFlattenGNUTarSparseLayers(t *testing.T) {
	// testdata/sparse-{gnu,pax}.tar were made with GNU tar 1.35 from a
	// directory holding a 1 MiB hole followed by "DATA" and a small text
	// file:
	//   truncate -s 1M opt/sp/lastlog && printf DATA >> opt/sp/lastlog
	//   tar --sparse --format=gnu   -b 1 --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -cf sparse-gnu.tar opt
	//   tar --sparse --format=posix -b 1 --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name \
	//       --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime -cf sparse-pax.tar opt
	want := expandFragments(1<<20+4, []fragment{{offset: 1 << 20, data: "DATA"}})
	for _, file := range []string{"sparse-gnu.tar", "sparse-pax.tar"} {
		t.Run(file, func(t *testing.T) {
			layer, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			img := buildImage(t, linuxAMD64, nil, layerFromTar(t, layer))
			got := flattenToRecords(t, img, nil)
			assertStrings(t, "entries", recordNames(got), []string{"opt", "opt/sp", "opt/sp/lastlog", "opt/sp/note.txt"})
			if l := got[2]; l.typeflag != tar.TypeReg || l.size != int64(len(want)) || l.content != string(want) {
				t.Errorf("lastlog = type %q size %d (content ok: %v)", l.typeflag, l.size, l.content == string(want))
			}
			if n := got[3]; n.content != "not a certificate\n" {
				t.Errorf("note.txt = %+v", n)
			}
		})
	}
}

func TestFlattenSkipsGlobalHeader(t *testing.T) {
	recs := paxRecords("comment", "made by git archive")
	var layer []byte
	for _, part := range [][]byte{
		newRawHeader("pax_global_header", tar.TypeXGlobalHeader, int64(len(recs))).entry(recs),
		rawFile("etc/os-release", "x"),
		rawTrailer(),
	} {
		layer = append(layer, part...)
	}
	img := buildImage(t, linuxAMD64, nil, layerFromTar(t, layer))
	got := flattenToRecords(t, img, nil)
	assertStrings(t, "entries", recordNames(got), []string{"etc/os-release"})
}

// brokenLayer cannot be opened.
type brokenLayer struct{ v1.Layer }

func (brokenLayer) Uncompressed() (io.ReadCloser, error) { return nil, errors.New("boom") }

func TestFlattenErrors(t *testing.T) {
	truncated := tarArchive(t, fileEntry("etc/os-release", strings.Repeat("x", 2000)))
	truncated = truncated[:512+100]
	tests := []struct {
		name    string
		layers  []v1.Layer
		wantErr []string
	}{
		{
			name:    "unsafe path",
			layers:  []v1.Layer{layerFromTar(t, tarArchive(t, fileEntry("../etc/passwd", "root")))},
			wantErr: []string{"layer 1/1", `unsafe tar path "../etc/passwd"`},
		},
		{
			name:    "truncated layer",
			layers:  []v1.Layer{layerFromTar(t, tarArchive(t, fileEntry("ok", "fine"))), static.NewLayer(truncated, types.OCIUncompressedLayer)},
			wantErr: []string{"layer 2/2", "etc/os-release"},
		},
		{
			name:    "layer that cannot be opened",
			layers:  []v1.Layer{brokenLayer{static.NewLayer(nil, types.OCIUncompressedLayer)}},
			wantErr: []string{"layer 1/1", "opening layer: boom"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := flatten(tc.layers, io.Discard, func(string) {})
			if err == nil {
				t.Fatal("flatten succeeded")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestFlattenProgress(t *testing.T) {
	base := tarArchive(t, fileEntry("base", "b"))
	top := tarArchive(t, fileEntry("top", "t"))
	layers := []v1.Layer{
		sizelessLayer{static.NewLayer(base, types.OCIUncompressedLayer)},
		static.NewLayer(top, types.OCIUncompressedLayer),
	}
	var progress progressLog
	if err := flatten(layers, io.Discard, progress.add); err != nil {
		t.Fatalf("flatten: %v", err)
	}
	assertStrings(t, "progress", progress.messages(), []string{
		fmt.Sprintf("reading layer 2/2 (%s, top layer first)", units.Bytes(int64(len(top)))),
		"reading layer 1/2 (size unknown)",
	})

	progress = progressLog{}
	if err := flatten(layers[1:], io.Discard, progress.add); err != nil {
		t.Fatalf("flatten: %v", err)
	}
	assertStrings(t, "progress", progress.messages(), []string{
		fmt.Sprintf("reading layer 1/1 (%s)", units.Bytes(int64(len(top)))),
	})
}

func TestUnsafeArchivePathAndLinks(t *testing.T) {
	paths := []struct {
		name   string
		unsafe bool
	}{
		{"etc/passwd", false},
		{"./etc/passwd", false},
		{"etc/../passwd", false},
		{"..", true},
		{"../etc/passwd", true},
		{"etc/../../passwd", true},
		{`\windows`, true},
		{`c:/windows`, true},
		{"..hidden", false},
	}
	for _, tc := range paths {
		if got := unsafeArchivePath(tc.name); got != tc.unsafe {
			t.Errorf("unsafeArchivePath(%q) = %v, want %v", tc.name, got, tc.unsafe)
		}
	}
	links := []struct {
		name, target string
		unsafe       bool
	}{
		{"etc/ssl/cert.pem", "certs/ca-certificates.crt", false},
		{"etc/ssl/cert.pem", "../../usr/share/x", false},
		{"etc/ssl/cert.pem", "../../../x", true},
		{"etc/ssl/cert.pem", "/anything/../../x", false},
		{"link", "..hidden", false},
		{"link", "..", true},
		{"link", `c:\x`, true},
	}
	for _, tc := range links {
		if got := unsafeRelativeLink(tc.name, tc.target); got != tc.unsafe {
			t.Errorf("unsafeRelativeLink(%q, %q) = %v, want %v", tc.name, tc.target, got, tc.unsafe)
		}
	}
}
