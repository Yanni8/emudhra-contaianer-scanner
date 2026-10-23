package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"emudhra-container-scanner/internal/units"
)

const (
	// whiteoutPrefix marks a file that a layer deletes from the layers below
	// it (".wh.name").
	whiteoutPrefix = ".wh."
	// opaqueWhiteout is the marker file of an opaque directory: a layer that
	// holds it hides everything the layers below put into that directory.
	opaqueWhiteout = ".wh..wh..opq"
	// paxGNUSparsePrefix prefixes the PAX records that describe GNU sparse
	// files.
	paxGNUSparsePrefix = "GNU.sparse."
)

// flattener merges the layers of an image into one tar stream. It reads the
// top layer first, so the first entry seen for a path is the one visible in
// the container, and applies the whiteout rules of the OCI image spec the way
// go-containerregistry's mutate.Extract does.
//
// Unlike mutate.Extract it rewrites GNU sparse entries as plain regular
// files: archive/tar's writer copies the sparse type flag into a ustar-style
// header that archive/tar's reader then rejects as invalid, which would abort
// the whole scan at the first sparse file (a lastlog, a database file...).
type flattener struct {
	tw *tar.Writer
	// seen records every path handled so far. A true value is a tombstone (a
	// whiteout or a non-directory entry) that also hides the entries of lower
	// layers underneath the path.
	seen map[string]bool
	// opaque holds the directories that upper layers made opaque; entries of
	// lower layers below them are hidden.
	opaque map[string]bool
}

// flatten writes the flattened root filesystem of layers, ordered base first
// as in the manifest, to w as a tar stream. report receives one message as
// each layer is opened; it must not be nil.
func flatten(layers []v1.Layer, w io.Writer, report func(string)) error {
	f := &flattener{tw: tar.NewWriter(w), seen: map[string]bool{}, opaque: map[string]bool{}}
	n := len(layers)
	for i := n - 1; i >= 0; i-- {
		report(layerMessage(i, n, layers[i]))
		if err := f.layer(layers[i]); err != nil {
			return fmt.Errorf("layer %d/%d: %w", i+1, n, err)
		}
	}
	return f.tw.Close()
}

// layerMessage is the progress line for reading layer i (0-based) of n. The
// first line says that layers are read from the top down.
func layerMessage(i, n int, l v1.Layer) string {
	size := "size unknown"
	if s, err := l.Size(); err == nil {
		size = units.Bytes(s)
	}
	if n > 1 && i == n-1 {
		return fmt.Sprintf("reading layer %d/%d (%s, top layer first)", i+1, n, size)
	}
	return fmt.Sprintf("reading layer %d/%d (%s)", i+1, n, size)
}

// layer merges one layer into the stream.
func (f *flattener) layer(l v1.Layer) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return fmt.Errorf("opening layer: %w", err)
	}
	defer rc.Close()

	// Opaque markers hide lower layers only, so they take effect once the
	// whole layer has been read.
	layerOpaque := map[string]bool{}
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading layer tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // archive metadata, not a file
		}
		hdr.Name = path.Clean(hdr.Name)
		if unsafeArchivePath(hdr.Name) {
			return fmt.Errorf("unsafe tar path %q", hdr.Name)
		}
		if (hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink) && unsafeRelativeLink(hdr.Name, hdr.Linkname) {
			continue
		}
		basename, dirname := path.Base(hdr.Name), path.Dir(hdr.Name)
		if basename == opaqueWhiteout {
			layerOpaque[dirname] = true
			continue
		}
		tombstone := strings.HasPrefix(basename, whiteoutPrefix)
		if tombstone {
			basename = basename[len(whiteoutPrefix):]
		}
		name := hdr.Name
		if hdr.Typeflag != tar.TypeDir {
			name = path.Join(dirname, basename)
		}
		if _, ok := f.seen[name]; ok && !tombstone {
			continue
		}
		if underMarked(f.seen, name) || underMarked(f.opaque, name) {
			continue
		}
		// A non-directory hides whatever lower layers have under the path.
		f.seen[name] = tombstone || hdr.Typeflag != tar.TypeDir
		if tombstone {
			continue
		}
		if err := f.write(hdr, tr); err != nil {
			return err
		}
	}
	for d := range layerOpaque {
		f.opaque[d] = true
	}
	// Drain what the tar reader left unread (trailing blocks) so that a
	// digest-verifying layer reader reaches EOF and checks the content.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("verifying layer: %w", err)
	}
	return nil
}

// write copies one entry to the output in a form archive/tar reads back: the
// PAX format lifts the ustar name length limits, and GNU sparse files (old
// 'S' entries as well as PAX GNU.sparse.* entries) become plain regular
// files. The layer reader already fills their holes with zeros and reports
// the logical size, so only the type flag and the sparse records have to go.
func (f *flattener) write(hdr *tar.Header, r io.Reader) error {
	hdr.Format = tar.FormatPAX
	if hdr.Typeflag == tar.TypeGNUSparse {
		hdr.Typeflag = tar.TypeReg
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, paxGNUSparsePrefix) {
			delete(hdr.PAXRecords, k)
		}
	}
	if err := f.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing entry %s: %w", hdr.Name, err)
	}
	if hdr.Size > 0 && !headerOnly(hdr.Typeflag) {
		if _, err := io.CopyN(f.tw, r, hdr.Size); err != nil {
			return fmt.Errorf("copying %s: %w", hdr.Name, err)
		}
	}
	return nil
}

// headerOnly reports whether entries of the type never carry data, whatever
// their Size field says; archive/tar reads and writes them that way.
func headerOnly(typeflag byte) bool {
	switch typeflag {
	case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
		return true
	}
	return false
}

// underMarked reports whether a parent directory of name is marked in m.
func underMarked(m map[string]bool, name string) bool {
	for {
		dir := path.Dir(name)
		if dir == name {
			return false
		}
		if m[dir] {
			return true
		}
		name = dir
	}
}

// unsafeArchivePath reports whether a cleaned entry name would leave the
// image root: a leading ".." component, a backslash-rooted name or a Windows
// drive letter.
func unsafeArchivePath(name string) bool {
	clean := cleanArchivePath(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return true
	}
	return strings.HasPrefix(name, `\`) || hasWindowsDrivePrefix(clean)
}

// unsafeRelativeLink reports whether a relative link target, resolved against
// the link's own directory, leaves the image root. Absolute targets are kept
// as they are.
func unsafeRelativeLink(name, linkname string) bool {
	clean := cleanArchivePath(linkname)
	if path.IsAbs(clean) {
		return false
	}
	if hasWindowsDrivePrefix(clean) {
		return true
	}
	resolved := path.Clean(path.Join(path.Dir(name), clean))
	return resolved == ".." || strings.HasPrefix(resolved, "../")
}

// cleanArchivePath cleans name with backslashes read as separators.
func cleanArchivePath(name string) string {
	return path.Clean(strings.ReplaceAll(name, `\`, "/"))
}

// hasWindowsDrivePrefix reports whether name starts with a drive letter and a
// colon.
func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 2 && name[1] == ':' &&
		('A' <= name[0] && name[0] <= 'Z' || 'a' <= name[0] && name[0] <= 'z')
}
