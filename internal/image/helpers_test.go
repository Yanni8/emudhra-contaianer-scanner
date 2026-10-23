package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"path"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// testEnv is the environment written into the fixture images.
var testEnv = []string{"PATH=/usr/sbin:/usr/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}

var (
	linuxAMD64   = v1.Platform{OS: "linux", Architecture: "amd64"}
	linuxARM64v8 = v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	// linuxS390X is a platform no test host has, for the "no platform
	// requested" cases.
	linuxS390X  = v1.Platform{OS: "linux", Architecture: "s390x"}
	unknownPlat = v1.Platform{OS: "unknown", Architecture: "unknown"}
)

// hostPlatform is what Open selects when no platform is requested.
func hostPlatform() v1.Platform {
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// testPlatforms lists the platforms the multi-platform fixture is built for.
// It always includes amd64 and arm64/v8 and, on other hosts, the host
// architecture so that default selection succeeds everywhere.
func testPlatforms() []v1.Platform {
	ps := []v1.Platform{linuxAMD64, linuxARM64v8}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		ps = append(ps, hostPlatform())
	}
	return ps
}

// expectedDefault is the fixture platform that default selection must pick.
func expectedDefault(t *testing.T) v1.Platform {
	t.Helper()
	for _, p := range testPlatforms() {
		if platformMatches(p, hostPlatform()) {
			return p
		}
	}
	t.Fatalf("no fixture platform matches host platform %s", hostPlatform())
	return v1.Platform{}
}

type tarEntry struct {
	name     string
	typeflag byte // 0 means regular file
	content  string
	linkname string
}

func dirEntry(name string) tarEntry { return tarEntry{name: name, typeflag: tar.TypeDir} }

func fileEntry(name, content string) tarEntry { return tarEntry{name: name, content: content} }

func symlinkEntry(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeSymlink, linkname: target}
}

func linkEntry(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeLink, linkname: target}
}

// tarArchive builds a deterministic tar with the given entries, in order.
func tarArchive(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
		switch e.typeflag {
		case tar.TypeDir:
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
		case tar.TypeSymlink:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.linkname
			hdr.Mode = 0o777
		case tar.TypeLink:
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = e.linkname
			hdr.Mode = 0o644
		default:
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0o644
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing tar header %s: %v", e.name, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatalf("writing tar entry %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return buf.Bytes()
}

// layerFromTar turns an uncompressed tar into a gzip-compressed layer.
func layerFromTar(t *testing.T, b []byte) v1.Layer {
	t.Helper()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	if err != nil {
		t.Fatalf("building layer: %v", err)
	}
	return l
}

// baseLayer is layer 1 of the fixture: an os-release file naming the
// platform, a Mozilla CA source directory and a CA bundle. Files are listed
// before their parent directories on purpose: entry order must not matter.
func baseLayer(t *testing.T, platform string) v1.Layer {
	t.Helper()
	return layerFromTar(t, tarArchive(t,
		fileEntry("etc/ssl/certs/ca-certificates.crt", "base bundle"),
		dirEntry("etc"),
		dirEntry("etc/ssl"),
		dirEntry("etc/ssl/certs"),
		fileEntry("./etc/os-release", "ID=test\nPLATFORM="+platform+"\n"),
		dirEntry("usr"),
		dirEntry("usr/share"),
		dirEntry("usr/share/ca-certificates"),
		dirEntry("usr/share/ca-certificates/mozilla"),
		fileEntry("usr/share/ca-certificates/mozilla/A.crt", "cert A"),
		fileEntry("usr/share/ca-certificates/mozilla/B.crt", "cert B"),
	))
}

// topLayer is layer 2 of the fixture: it whites out A.crt, overrides the CA
// bundle and adds a symlink to it.
func topLayer(t *testing.T) v1.Layer {
	t.Helper()
	return layerFromTar(t, tarArchive(t,
		fileEntry("usr/share/ca-certificates/mozilla/.wh.A.crt", ""),
		fileEntry("etc/ssl/certs/ca-certificates.crt", "override bundle"),
		symlinkEntry("etc/ssl/cert.pem", "certs/ca-certificates.crt"),
	))
}

// buildImage assembles an image from layers with the given platform recorded
// in its config and, when env is not nil, the given environment.
func buildImage(t *testing.T, platform v1.Platform, env []string, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("appending layers: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS = platform.OS
	cf.Architecture = platform.Architecture
	cf.Variant = platform.Variant
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatalf("setting config file: %v", err)
	}
	if env != nil {
		cfg := cf.Config
		cfg.Env = env
		if img, err = mutate.Config(img, cfg); err != nil {
			t.Fatalf("setting config: %v", err)
		}
	}
	return img
}

// fixtureImage builds the two-layer fixture image for a platform.
func fixtureImage(t *testing.T, p v1.Platform) v1.Image {
	t.Helper()
	return buildImage(t, p, testEnv, baseLayer(t, p.String()), topLayer(t))
}

// attestationImage mimics a BuildKit provenance manifest.
func attestationImage(t *testing.T) v1.Image {
	t.Helper()
	return buildImage(t, unknownPlat, nil, layerFromTar(t, tarArchive(t, fileEntry("in-toto.json", "{}"))))
}

// attestationAddendum is an index entry for an attestation manifest.
func attestationAddendum(img v1.Image) mutate.IndexAddendum {
	p := unknownPlat
	return mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{
		Platform:    &p,
		Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
	}}
}

// multiPlatformIndex builds an index holding one fixture image per test
// platform, preceded by an attestation manifest.
func multiPlatformIndex(t *testing.T) (v1.ImageIndex, map[string]v1.Image) {
	t.Helper()
	images := map[string]v1.Image{}
	adds := []mutate.IndexAddendum{attestationAddendum(attestationImage(t))}
	for _, p := range testPlatforms() {
		img := fixtureImage(t, p)
		images[p.String()] = img
		pp := p
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &pp}})
	}
	return mutate.AppendManifests(empty.Index, adds...), images
}

// indexDigest returns the digest recorded in idx for the manifest of platform p.
func indexDigest(t *testing.T, idx v1.ImageIndex, p v1.Platform) string {
	t.Helper()
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("reading index manifest: %v", err)
	}
	for _, d := range im.Manifests {
		if d.Platform != nil && d.Platform.Equals(p) {
			return d.Digest.String()
		}
	}
	t.Fatalf("platform %s not in index", p)
	return ""
}

func imageDigest(t *testing.T, img v1.Image) string {
	t.Helper()
	h, err := img.Digest()
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}
	return h.String()
}

func mustRef(t *testing.T, s string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(s, name.WeakValidation)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return ref
}

func mustTag(t *testing.T, s string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(s, name.WeakValidation)
	if err != nil {
		t.Fatalf("parsing tag %q: %v", s, err)
	}
	return tag
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// startRegistry serves an in-memory registry over plain HTTP and returns its
// host:port.
func startRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(quietLogger())))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// fixture is a registry holding a multi-platform image (with an attestation
// entry) under multiRef and a single-platform image without environment
// under singleRef.
type fixture struct {
	host      string
	multiRef  string
	singleRef string
	idx       v1.ImageIndex
	images    map[string]v1.Image
	single    v1.Image
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{host: startRegistry(t)}
	f.idx, f.images = multiPlatformIndex(t)
	f.multiRef = f.host + "/scanner/multi:latest"
	if err := remote.WriteIndex(mustRef(t, f.multiRef), f.idx, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing index: %v", err)
	}
	f.single = buildImage(t, linuxAMD64, nil, baseLayer(t, linuxAMD64.String()))
	f.singleRef = f.host + "/scanner/single:v1"
	if err := remote.Write(mustRef(t, f.singleRef), f.single, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing image: %v", err)
	}
	return f
}

// progressLog collects Progress messages; it is safe for concurrent use.
type progressLog struct {
	mu   sync.Mutex
	msgs []string
}

func (p *progressLog) add(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.msgs = append(p.msgs, msg)
}

func (p *progressLog) messages() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.msgs...)
}

type fsEntry struct {
	typeflag byte
	content  string
	linkname string
}

var dirFS = fsEntry{typeflag: tar.TypeDir}

// readFS drains the flattened filesystem of im into a map keyed by cleaned
// path.
func readFS(t *testing.T, im *Image) map[string]fsEntry {
	t.Helper()
	rc, err := im.Filesystem()
	if err != nil {
		t.Fatalf("Filesystem: %v", err)
	}
	defer rc.Close()
	got := map[string]fsEntry{}
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading filesystem tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s: %v", hdr.Name, err)
		}
		name := path.Clean(hdr.Name)
		if _, dup := got[name]; dup {
			t.Errorf("duplicate entry %q in flattened filesystem", name)
		}
		got[name] = fsEntry{typeflag: hdr.Typeflag, content: string(data), linkname: hdr.Linkname}
	}
	return got
}

// wantFS is the expected flattened fixture filesystem: A.crt whited out, the
// bundle overridden by layer 2, the symlink present, "./" cleaned away.
func wantFS(platform string) map[string]fsEntry {
	return map[string]fsEntry{
		"etc":                               dirFS,
		"etc/ssl":                           dirFS,
		"etc/ssl/certs":                     dirFS,
		"usr":                               dirFS,
		"usr/share":                         dirFS,
		"usr/share/ca-certificates":         dirFS,
		"usr/share/ca-certificates/mozilla": dirFS,
		"etc/os-release":                    {typeflag: tar.TypeReg, content: "ID=test\nPLATFORM=" + platform + "\n"},
		"etc/ssl/certs/ca-certificates.crt": {typeflag: tar.TypeReg, content: "override bundle"},
		"etc/ssl/cert.pem":                  {typeflag: tar.TypeSymlink, linkname: "certs/ca-certificates.crt"},
		"usr/share/ca-certificates/mozilla/B.crt": {typeflag: tar.TypeReg, content: "cert B"},
	}
}

func assertFS(t *testing.T, got, want map[string]fsEntry) {
	t.Helper()
	names := map[string]bool{}
	for n := range got {
		names[n] = true
	}
	for n := range want {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		g, gok := got[n]
		w, wok := want[n]
		switch {
		case !gok:
			t.Errorf("filesystem is missing %q", n)
		case !wok:
			t.Errorf("filesystem has unexpected entry %q (%+v)", n, g)
		case g != w:
			t.Errorf("filesystem entry %q = %+v, want %+v", n, g, w)
		}
	}
}

func assertStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %q, want %q", what, got, want)
		}
	}
}
