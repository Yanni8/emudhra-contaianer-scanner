package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Yanni8/emudhra-container-scanner/internal/units"
)

// maxLayoutArchiveSize caps the bytes extracted from an OCI image layout
// archive. It is a variable so that tests can lower it.
var maxLayoutArchiveSize int64 = 4 << 30

// extractLayoutArchive unpacks the OCI image layout held in the tar file at
// archive (as written by `docker buildx build -o type=oci`, `podman save
// --format oci-archive` or `skopeo copy ... oci-archive:`) into a new
// temporary directory and returns that directory. Nothing is left behind on
// error.
func extractLayoutArchive(archive string) (string, error) {
	dir, err := os.MkdirTemp("", "emudhra-container-scanner-oci-*")
	if err != nil {
		return "", fmt.Errorf("creating temporary directory: %w", err)
	}
	if err := unpackLayoutArchive(archive, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// unpackLayoutArchive extracts the layout files of the tar file at archive
// into dir. Only index.json, oci-layout and the files below blobs/ are
// extracted; other entries are ignored. Entries that would leave the archive
// root, layout entries that are neither regular files nor directories, and
// archives whose extracted content exceeds maxLayoutArchiveSize are errors.
func unpackLayoutArchive(archive, dir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	var total int64
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		name, err := layoutEntryName(hdr.Name)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeGNUSparse:
			// The reader expands sparse files, so Size is what gets written.
			if total += hdr.Size; total > maxLayoutArchiveSize {
				return fmt.Errorf("extracted content exceeds %s", units.Bytes(maxLayoutArchiveSize))
			}
			if err := writeFile(target, tr); err != nil {
				return fmt.Errorf("extracting %s: %w", name, err)
			}
		default:
			return fmt.Errorf("entry %s is a %s; only regular files and directories are supported", name, entryKind(hdr.Typeflag))
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		return errors.New("no index.json in the archive")
	}
	return nil
}

// layoutEntryName maps the name of a tar entry to its slash-separated path
// inside the layout: "index.json", "oci-layout", "blobs" or anything below
// blobs/. It returns "" for entries that are not part of the layout and an
// error for absolute names and names that escape the archive root.
func layoutEntryName(name string) (string, error) {
	clean := path.Clean(name)
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe entry name %q", name)
	}
	if strings.Contains(clean, `\`) {
		return "", nil // never a layout file; keeps backslashes off the disk
	}
	switch {
	case clean == "index.json", clean == "oci-layout", clean == "blobs", strings.HasPrefix(clean, "blobs/"):
		return clean, nil
	}
	return "", nil
}

// writeFile creates target (and its parent directories) with the content of
// r, readable by the current user only.
func writeFile(target string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// entryKind names a tar entry type for error messages.
func entryKind(typeflag byte) string {
	switch typeflag {
	case tar.TypeSymlink:
		return "symbolic link"
	case tar.TypeLink:
		return "hard link"
	case tar.TypeChar, tar.TypeBlock:
		return "device node"
	case tar.TypeFifo:
		return "named pipe"
	}
	return fmt.Sprintf("tar entry of type %q", typeflag)
}
