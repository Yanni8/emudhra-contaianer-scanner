package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Yanni8/emudhra-container-scanner/internal/units"
)

const (
	// annotationRefName is the OCI annotation that names an image inside an
	// image layout index ("latest", "app:1.0" or a full reference).
	annotationRefName = "org.opencontainers.image.ref.name"
	// annotationContainerdName is containerd's (and nerdctl's) equivalent,
	// always a full reference.
	annotationContainerdName = "io.containerd.image.name"
)

// openLocal reads the image from an OCI image layout directory, an OCI image
// layout archive or a `docker save` tarball at input.
func openLocal(ref, input string, p openParams) (*Image, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("reading local image source: %w", err)
	}
	ref = strings.TrimSpace(ref)
	if info.IsDir() {
		return openLayout(layoutSource{dir: input, reference: "oci:" + input, shown: input}, ref, p)
	}
	return openTarball(input, ref, p)
}

// layoutSource is an OCI image layout directory together with the names it
// is reported under.
type layoutSource struct {
	// dir is the layout directory.
	dir string
	// reference becomes Image.Reference ("oci:<dir>", "oci-archive:<file>").
	reference string
	// shown names the source in error messages: the directory, or the
	// archive it was extracted from.
	shown string
}

// openLayout selects an image from an OCI image layout by ref (matched
// against the ref.name annotations) and/or platform.
func openLayout(src layoutSource, ref string, p openParams) (*Image, error) {
	p.report("resolving " + src.reference)

	idx, err := layout.ImageIndexFromPath(src.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s is not an OCI image layout (no index.json): %w", src.shown, err)
		}
		return nil, fmt.Errorf("reading OCI image layout %s: %w", src.shown, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("parsing index.json of %s: %w", src.shown, err)
	}
	if len(im.Manifests) == 0 {
		return nil, fmt.Errorf("OCI image layout %s contains no images", src.shown)
	}

	names := refNames(im.Manifests)
	var top []v1.Descriptor
	if ref != "" {
		for _, d := range im.Manifests {
			if refMatches(d.Annotations, ref) {
				top = append(top, d)
			}
		}
		if len(top) == 0 {
			if len(names) == 0 {
				return nil, fmt.Errorf("image %q not found in OCI image layout %s: its manifests carry no %s annotation (omit the reference to use the layout's only image)", ref, src.shown, annotationRefName)
			}
			return nil, fmt.Errorf("image %q not found in OCI image layout %s; available: %s", ref, src.shown, strings.Join(names, ", "))
		}
	} else {
		if len(names) > 1 {
			return nil, fmt.Errorf("OCI image layout %s holds %d images (%s); pass a reference to choose one", src.shown, len(names), strings.Join(names, ", "))
		}
		top = im.Manifests
	}

	cands, attestations, err := collectCandidates(idx, top, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.reference, err)
	}
	sel, err := selectCandidate(src.reference, cands, attestations, p.want, p.explicit)
	if err != nil {
		return nil, err
	}
	img, err := sel.image()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.reference, err)
	}
	platform, _ := sel.platform() // resolved during selection; cannot fail now
	return newImage(src.reference, img, sel.desc.Digest, platform, p)
}

// openLayoutArchive reads an image from the OCI image layout held in the tar
// file at file. The layout is extracted into a temporary directory that the
// returned Image removes on Close.
func openLayoutArchive(file, ref string, p openParams) (*Image, error) {
	size := "size unknown"
	if info, err := os.Stat(file); err == nil {
		size = units.Bytes(info.Size())
	}
	p.report(fmt.Sprintf("extracting OCI image layout archive %s (%s)", file, size))
	dir, err := extractLayoutArchive(file)
	if err != nil {
		return nil, fmt.Errorf("extracting OCI image layout archive %s: %w", file, err)
	}
	im, err := openLayout(layoutSource{dir: dir, reference: "oci-archive:" + file, shown: file}, ref, p)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	im.tempDir = dir
	return im, nil
}

// refNames lists the distinct image names annotated on index entries.
func refNames(descs []v1.Descriptor) []string {
	var names []string
	seen := map[string]bool{}
	for _, d := range descs {
		n := d.Annotations[annotationRefName]
		if n == "" {
			n = d.Annotations[annotationContainerdName]
		}
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	return names
}

// refMatches reports whether an index entry's name annotations designate ref.
// Besides exact matches it accepts references that normalise to the same
// name ("app:1.0" and "index.docker.io/library/app:1.0") and bare tags
// ("1.0" against "app:1.0", in either direction), which is how the various
// tools populate the annotation.
func refMatches(annotations map[string]string, ref string) bool {
	for _, key := range []string{annotationRefName, annotationContainerdName} {
		value := annotations[key]
		if value == "" {
			continue
		}
		if value == ref || sameReference(value, ref) {
			return true
		}
		if t, err := name.NewTag(ref, name.WeakValidation); err == nil && t.TagStr() == value {
			return true
		}
		if t, err := name.NewTag(value, name.WeakValidation); err == nil && t.TagStr() == ref {
			return true
		}
	}
	return false
}

// sameReference reports whether a and b parse to the same fully qualified
// reference.
func sameReference(a, b string) bool {
	ra, err := name.ParseReference(a, name.WeakValidation)
	if err != nil {
		return false
	}
	rb, err := name.ParseReference(b, name.WeakValidation)
	if err != nil {
		return false
	}
	return ra.Name() == rb.Name()
}

// openTarball selects an image from a `docker save` archive by tag, or hands
// an OCI image layout archive over to openLayoutArchive.
func openTarball(file, ref string, p openParams) (*Image, error) {
	opener := func() (io.ReadCloser, error) { return os.Open(file) }
	manifest, err := tarball.LoadManifest(opener)
	if err != nil {
		if tarContains(file, "index.json") {
			return openLayoutArchive(file, ref, p)
		}
		return nil, fmt.Errorf("%s is not a docker-archive tarball (no readable manifest.json): %w", file, err)
	}
	reference := "docker-archive:" + file
	p.report("resolving " + reference)

	var (
		tag   *name.Tag
		label string
	)
	if ref == "" {
		switch len(manifest) {
		case 0:
			return nil, fmt.Errorf("%s contains no images", file)
		case 1:
			if tags := manifest[0].RepoTags; len(tags) > 0 {
				label = tags[0]
			}
		default:
			return nil, fmt.Errorf("%s holds %d images (%s); pass a reference to choose one", file, len(manifest), strings.Join(repoTags(manifest), ", "))
		}
	} else {
		t, err := name.NewTag(ref, name.WeakValidation)
		if err != nil {
			return nil, fmt.Errorf("images in a docker-archive are selected by tag, not by %q: %w", ref, err)
		}
		label = matchingRepoTag(manifest, t)
		if label == "" {
			available := repoTags(manifest)
			if len(available) == 0 {
				return nil, fmt.Errorf("tag %s not found in %s: the archive holds no tagged images (omit the reference to use its only image)", t.Name(), file)
			}
			return nil, fmt.Errorf("tag %s not found in %s; available tags: %s", t.Name(), file, strings.Join(available, ", "))
		}
		tag = &t
	}

	img, err := tarball.ImageFromPath(file, tag)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", reference, err)
	}
	if label != "" {
		reference += ":" + label
	}
	return newImage(reference, img, v1.Hash{}, nil, p)
}

// repoTags lists every tag in a docker-archive manifest.
func repoTags(manifest tarball.Manifest) []string {
	var tags []string
	for _, d := range manifest {
		tags = append(tags, d.RepoTags...)
	}
	return tags
}

// matchingRepoTag returns the archive's spelling of the tag that resolves to
// want, or "" when the archive does not hold it.
func matchingRepoTag(manifest tarball.Manifest, want name.Tag) string {
	for _, d := range manifest {
		for _, rt := range d.RepoTags {
			t, err := name.NewTag(rt, name.WeakValidation)
			if err != nil {
				continue
			}
			if t.Name() == want.Name() {
				return rt
			}
		}
	}
	return ""
}

// tarContains reports whether the (uncompressed) tar file has an entry with
// one of the given names. Read errors simply yield false.
func tarContains(file string, names ...string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return false
		}
		if want[path.Clean(hdr.Name)] {
			return true
		}
	}
}
