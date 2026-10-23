package image

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/units"
)

func TestOpenRegistryIndexDefaultPlatform(t *testing.T) {
	f := newFixture(t)
	want := expectedDefault(t)
	var progress progressLog

	im, err := Open(context.Background(), f.multiRef, Options{Progress: progress.add})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Reference != f.multiRef {
		t.Errorf("Reference = %q, want %q", im.Reference, f.multiRef)
	}
	if im.Platform != want.String() {
		t.Errorf("Platform = %q, want %q", im.Platform, want)
	}
	if wantDigest := indexDigest(t, f.idx, want); im.Digest != wantDigest {
		t.Errorf("Digest = %s, want %s (the pushed manifest digest)", im.Digest, wantDigest)
	}
	if im.Layers != 2 {
		t.Errorf("Layers = %d, want 2", im.Layers)
	}
	if im.CompressedSize <= 0 {
		t.Errorf("CompressedSize = %d, want > 0", im.CompressedSize)
	}
	if im.Config == nil {
		t.Fatal("Config is nil")
	}
	assertStrings(t, "Config.Config.Env", im.Config.Config.Env, testEnv)
	assertStrings(t, "Env()", im.Env(), testEnv)
	if im.Underlying() == nil {
		t.Error("Underlying() is nil")
	}

	// Env returns a copy: mutating it must not affect the image.
	env := im.Env()
	env[0] = "mutated"
	if im.Env()[0] != testEnv[0] {
		t.Error("Env() returned a slice aliasing the image configuration")
	}

	assertFS(t, readFS(t, im), wantFS(want.String()))

	// Layers are reported as they are read: the top one first.
	layers, err := f.images[want.String()].Layers()
	if err != nil {
		t.Fatal(err)
	}
	sizes := make([]int64, len(layers))
	for i, l := range layers {
		if sizes[i], err = l.Size(); err != nil {
			t.Fatal(err)
		}
	}
	assertStrings(t, "progress messages", progress.messages(), []string{
		"resolving " + f.multiRef,
		fmt.Sprintf("selected %s %s", want, im.Digest),
		fmt.Sprintf("reading layer 2/2 (%s, top layer first)", units.Bytes(sizes[1])),
		fmt.Sprintf("reading layer 1/2 (%s)", units.Bytes(sizes[0])),
	})
}

func TestOpenRegistryNoPlatformRequested(t *testing.T) {
	// Without Options.Platform a single-platform image is scanned whatever
	// its platform, whether it is a plain manifest or the only image of an
	// index; with a platform given, a mismatch is refused.
	host := startRegistry(t)
	ctx := context.Background()
	foreign := buildImage(t, linuxS390X, nil, baseLayer(t, linuxS390X.String()))
	foreignDigest := imageDigest(t, foreign)

	manifestRef := host + "/scanner/foreign:v1"
	if err := remote.Write(mustRef(t, manifestRef), foreign, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing image: %v", err)
	}
	p := linuxS390X
	idx := mutate.AppendManifests(empty.Index,
		attestationAddendum(attestationImage(t)),
		mutate.IndexAddendum{Add: foreign, Descriptor: v1.Descriptor{Platform: &p}},
	)
	indexRef := host + "/scanner/foreign-index:v1"
	if err := remote.WriteIndex(mustRef(t, indexRef), idx, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	tests := []struct {
		name             string
		ref              string
		platform         string
		wantPNF          bool
		wantAttestations int
	}{
		{name: "manifest, no platform", ref: manifestRef},
		{name: "manifest, matching platform", ref: manifestRef, platform: "linux/s390x"},
		{name: "manifest, mismatching platform", ref: manifestRef, platform: "linux/amd64", wantPNF: true},
		{name: "lone index entry, no platform", ref: indexRef},
		{name: "lone index entry, matching platform", ref: indexRef, platform: "linux/s390x"},
		{name: "lone index entry, mismatching platform", ref: indexRef, platform: "linux/amd64", wantPNF: true, wantAttestations: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			im, err := Open(ctx, tc.ref, Options{Platform: tc.platform})
			if tc.wantPNF {
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
				}
				assertStrings(t, "Available", pnf.Available, []string{"linux/s390x"})
				if pnf.Requested != tc.platform || pnf.Attestations != tc.wantAttestations {
					t.Errorf("unexpected error fields: %+v", pnf)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if im.Platform != "linux/s390x" {
				t.Errorf("Platform = %q, want linux/s390x", im.Platform)
			}
			if im.Digest != foreignDigest {
				t.Errorf("Digest = %s, want %s", im.Digest, foreignDigest)
			}
			if got := readFS(t, im)["etc/os-release"].content; got != "ID=test\nPLATFORM=linux/s390x\n" {
				t.Errorf("os-release = %q", got)
			}
		})
	}
}

func TestOpenRegistryPlatformSelection(t *testing.T) {
	f := newFixture(t)
	arm64Digest := indexDigest(t, f.idx, linuxARM64v8)
	amd64Digest := indexDigest(t, f.idx, linuxAMD64)

	tests := []struct {
		name       string
		platform   string
		wantPlat   string
		wantDigest string
		wantAvail  []string // for PlatformNotFoundError
		wantErr    string   // substring of a non-platform error
	}{
		{name: "explicit amd64", platform: "linux/amd64", wantPlat: "linux/amd64", wantDigest: amd64Digest},
		{name: "explicit arm64 with variant", platform: "linux/arm64/v8", wantPlat: "linux/arm64/v8", wantDigest: arm64Digest},
		{name: "arm64 without variant accepts v8", platform: "linux/arm64", wantPlat: "linux/arm64/v8", wantDigest: arm64Digest},
		{name: "aarch64 alias", platform: "linux/aarch64", wantPlat: "linux/arm64/v8", wantDigest: arm64Digest},
		{name: "surrounding whitespace", platform: " linux/amd64 ", wantPlat: "linux/amd64", wantDigest: amd64Digest},
		{name: "no match", platform: "linux/s390x", wantAvail: []string{"linux/amd64", "linux/arm64/v8"}},
		{name: "wrong os", platform: "windows/amd64", wantAvail: []string{"linux/amd64", "linux/arm64/v8"}},
		{name: "wrong variant", platform: "linux/arm64/v9", wantAvail: []string{"linux/amd64", "linux/arm64/v8"}},
		{name: "attestation is never selected", platform: "unknown/unknown", wantAvail: []string{"linux/amd64", "linux/arm64/v8"}},
		{name: "too many components", platform: "linux/amd64/v3/extra", wantErr: "invalid platform"},
		{name: "missing architecture", platform: "linux", wantErr: "invalid platform"},
		{name: "missing os", platform: "/amd64", wantErr: "invalid platform"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			im, err := Open(context.Background(), f.multiRef, Options{Platform: tc.platform})
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
				}
			case tc.wantAvail != nil:
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
				}
				if pnf.Reference != f.multiRef {
					t.Errorf("Reference = %q, want %q", pnf.Reference, f.multiRef)
				}
				if pnf.Requested != strings.TrimSpace(tc.platform) {
					t.Errorf("Requested = %q, want %q", pnf.Requested, tc.platform)
				}
				if pnf.Attestations != 1 {
					t.Errorf("Attestations = %d, want 1", pnf.Attestations)
				}
				for _, p := range tc.wantAvail {
					if !contains(pnf.Available, p) {
						t.Errorf("Available = %q, want it to contain %q", pnf.Available, p)
					}
				}
				if contains(pnf.Available, "unknown/unknown") {
					t.Errorf("Available = %q lists the attestation manifest", pnf.Available)
				}
				for _, p := range tc.wantAvail {
					if !strings.Contains(err.Error(), p) {
						t.Errorf("error %q does not list platform %s", err, p)
					}
				}
			default:
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if im.Platform != tc.wantPlat {
					t.Errorf("Platform = %q, want %q", im.Platform, tc.wantPlat)
				}
				if im.Digest != tc.wantDigest {
					t.Errorf("Digest = %s, want %s", im.Digest, tc.wantDigest)
				}
				assertFS(t, readFS(t, im), wantFS(tc.wantPlat))
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestOpenRegistryByDigest(t *testing.T) {
	f := newFixture(t)
	h, err := f.idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref := f.host + "/scanner/multi@" + h.String()
	im, err := Open(context.Background(), ref, Options{Platform: "linux/amd64", Insecure: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Reference != ref {
		t.Errorf("Reference = %q, want %q", im.Reference, ref)
	}
	if want := indexDigest(t, f.idx, linuxAMD64); im.Digest != want {
		t.Errorf("Digest = %s, want %s", im.Digest, want)
	}
	if im.Platform != "linux/amd64" {
		t.Errorf("Platform = %q, want linux/amd64", im.Platform)
	}
}

func TestOpenRegistrySingleImage(t *testing.T) {
	f := newFixture(t)
	wantDigest := imageDigest(t, f.single)

	t.Run("default platform accepts the only image", func(t *testing.T) {
		var progress progressLog
		im, err := Open(context.Background(), f.singleRef, Options{Progress: progress.add})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if im.Reference != f.singleRef {
			t.Errorf("Reference = %q, want %q", im.Reference, f.singleRef)
		}
		if im.Digest != wantDigest {
			t.Errorf("Digest = %s, want %s", im.Digest, wantDigest)
		}
		if im.Platform != "linux/amd64" {
			t.Errorf("Platform = %q, want linux/amd64 (from the config)", im.Platform)
		}
		if im.Layers != 1 {
			t.Errorf("Layers = %d, want 1", im.Layers)
		}
		if env := im.Env(); env != nil {
			t.Errorf("Env() = %q, want nil for an image without environment", env)
		}
		if im.Config == nil || im.Config.Config.Env != nil {
			t.Errorf("Config.Config.Env = %v, want nil", im.Config)
		}
		msgs := progress.messages()
		if len(msgs) != 2 || msgs[0] != "resolving "+f.singleRef || msgs[1] != "selected linux/amd64 "+wantDigest {
			t.Errorf("progress messages = %q", msgs)
		}
		got := readFS(t, im)
		if got["usr/share/ca-certificates/mozilla/A.crt"].content != "cert A" {
			t.Errorf("A.crt missing from single-layer image: %+v", got)
		}
		if got["etc/ssl/certs/ca-certificates.crt"].content != "base bundle" {
			t.Errorf("bundle = %+v, want base bundle", got["etc/ssl/certs/ca-certificates.crt"])
		}
	})

	t.Run("explicit matching platform", func(t *testing.T) {
		if _, err := Open(context.Background(), f.singleRef, Options{Platform: "linux/amd64"}); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})

	t.Run("explicit mismatching platform", func(t *testing.T) {
		_, err := Open(context.Background(), f.singleRef, Options{Platform: "linux/arm64"})
		var pnf *PlatformNotFoundError
		if !errors.As(err, &pnf) {
			t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
		}
		assertStrings(t, "Available", pnf.Available, []string{"linux/amd64"})
	})
}

func TestOpenRegistryErrors(t *testing.T) {
	f := newFixture(t)

	tests := []struct {
		name    string
		ref     string
		opts    Options
		ctx     func() context.Context
		wantErr string
	}{
		{name: "empty reference", ref: "", wantErr: "reference is empty"},
		{name: "url scheme", ref: "http://" + f.host + "/scanner/multi:latest", wantErr: "URL scheme"},
		{name: "unparsable reference", ref: "UPPER:CASE:::", wantErr: "parsing image reference"},
		{name: "unknown repository", ref: f.host + "/scanner/missing:latest", wantErr: "not found"},
		{name: "unknown tag", ref: f.host + "/scanner/multi:nope", wantErr: "not found"},
		{name: "unreachable registry", ref: "127.0.0.1:1/scanner/multi:latest", wantErr: "resolving 127.0.0.1:1/scanner/multi:latest"},
		{name: "cancelled context", ref: f.multiRef, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, wantErr: "context canceled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			_, err := Open(ctx, tc.ref, tc.opts)
			if err == nil {
				t.Fatal("Open succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Open error = %q, want it to contain %q", err, tc.wantErr)
			}
			var pnf *PlatformNotFoundError
			if errors.As(err, &pnf) {
				t.Errorf("Open error %v is a PlatformNotFoundError", err)
			}
		})
	}
}

func TestOpenRegistryInsecureFlag(t *testing.T) {
	f := newFixture(t)
	im, err := Open(context.Background(), f.multiRef, Options{Insecure: true, Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("Open with Insecure: %v", err)
	}
	if im.Platform != "linux/amd64" {
		t.Errorf("Platform = %q", im.Platform)
	}
}

func TestFilesystemCanBeReadRepeatedlyAndClosedEarly(t *testing.T) {
	f := newFixture(t)
	im, err := Open(context.Background(), f.multiRef, Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Close after the first entry: the extraction goroutine must stop.
	rc, err := im.Filesystem()
	if err != nil {
		t.Fatalf("Filesystem: %v", err)
	}
	if _, err := tar.NewReader(rc).Next(); err != nil {
		t.Fatalf("reading first entry: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- rc.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked")
	}

	// A fresh stream delivers the whole filesystem again.
	assertFS(t, readFS(t, im), wantFS("linux/amd64"))
	assertFS(t, readFS(t, im), wantFS("linux/amd64"))
}

func TestZeroImage(t *testing.T) {
	var nilImage *Image
	if env := nilImage.Env(); env != nil {
		t.Errorf("nil Image Env() = %v, want nil", env)
	}
	if _, err := nilImage.Filesystem(); err == nil {
		t.Error("nil Image Filesystem() succeeded")
	}
	zero := &Image{}
	if env := zero.Env(); env != nil {
		t.Errorf("zero Image Env() = %v, want nil", env)
	}
	if _, err := zero.Filesystem(); err == nil {
		t.Error("zero Image Filesystem() succeeded")
	}
	if zero.Underlying() != nil {
		t.Error("zero Image Underlying() is not nil")
	}
}

// rawManifest pushes arbitrary manifest bytes under a media type.
type rawManifest struct {
	raw []byte
	mt  types.MediaType
}

func (r rawManifest) RawManifest() ([]byte, error)        { return r.raw, nil }
func (r rawManifest) MediaType() (types.MediaType, error) { return r.mt, nil }

func TestOpenRegistrySchema1(t *testing.T) {
	host := startRegistry(t)
	ref := mustRef(t, host+"/legacy/app:v1")
	layer := baseLayer(t, "linux/amd64")
	if err := remote.WriteLayer(ref.Context(), layer); err != nil {
		t.Fatalf("pushing layer: %v", err)
	}
	digest, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"schemaVersion":1,"name":"legacy/app","tag":"v1","architecture":"amd64","fsLayers":[{"blobSum":%q}],"history":[{"v1Compatibility":"{}"}]}`, digest)
	if err := remote.Put(ref, rawManifest{raw: []byte(manifest), mt: types.DockerManifestSchema1}); err != nil {
		t.Fatalf("pushing schema 1 manifest: %v", err)
	}

	var progress progressLog
	im, err := Open(context.Background(), ref.String(), Options{Progress: progress.add})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Config != nil {
		t.Errorf("Config = %+v, want nil for a schema 1 image", im.Config)
	}
	if env := im.Env(); env != nil {
		t.Errorf("Env() = %v, want nil", env)
	}
	if im.Platform != "" {
		t.Errorf("Platform = %q, want empty", im.Platform)
	}
	if im.Layers != 1 {
		t.Errorf("Layers = %d, want 1", im.Layers)
	}
	if size, _ := layer.Size(); im.CompressedSize != size {
		t.Errorf("CompressedSize = %d, want %d", im.CompressedSize, size)
	}
	if !strings.HasPrefix(im.Digest, "sha256:") {
		t.Errorf("Digest = %q", im.Digest)
	}
	if msgs := progress.messages(); len(msgs) != 2 || msgs[1] != "selected unknown platform "+im.Digest {
		t.Errorf("progress messages = %q", msgs)
	}
	got := readFS(t, im)
	if got["etc/os-release"].content != "ID=test\nPLATFORM=linux/amd64\n" {
		t.Errorf("os-release = %+v", got["etc/os-release"])
	}

	// With a platform explicitly requested nothing is known to contradict it.
	if _, err := Open(context.Background(), ref.String(), Options{Platform: "linux/s390x"}); err != nil {
		t.Errorf("Open with explicit platform: %v", err)
	}
}

func TestOpenRegistryNestedIndexAndPlatformlessEntries(t *testing.T) {
	host := startRegistry(t)
	ctx := context.Background()

	// An index whose only entry is itself a multi-platform index.
	inner, images := multiPlatformIndex(t)
	outer := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: inner})
	nestedRef := host + "/nested/app:latest"
	if err := remote.WriteIndex(mustRef(t, nestedRef), outer, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing nested index: %v", err)
	}
	im, err := Open(ctx, nestedRef, Options{Platform: "linux/arm64"})
	if err != nil {
		t.Fatalf("Open nested: %v", err)
	}
	if want := imageDigest(t, images[linuxARM64v8.String()]); im.Digest != want {
		t.Errorf("Digest = %s, want %s", im.Digest, want)
	}
	if im.Platform != "linux/arm64/v8" {
		t.Errorf("Platform = %q", im.Platform)
	}
	assertFS(t, readFS(t, im), wantFS("linux/arm64/v8"))

	// Index entries without a platform: the config decides.
	imgA, imgB := fixtureImage(t, linuxAMD64), fixtureImage(t, linuxARM64v8)
	bare := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: imgA},
		mutate.IndexAddendum{Add: imgB},
	)
	bareRef := host + "/bare/app:latest"
	if err := remote.WriteIndex(mustRef(t, bareRef), bare, remote.WithContext(ctx)); err != nil {
		t.Fatalf("pushing index: %v", err)
	}
	im, err = Open(ctx, bareRef, Options{Platform: "linux/arm64/v8"})
	if err != nil {
		t.Fatalf("Open bare: %v", err)
	}
	if want := imageDigest(t, imgB); im.Digest != want {
		t.Errorf("Digest = %s, want %s", im.Digest, want)
	}
	if im.Platform != "linux/arm64/v8" {
		t.Errorf("Platform = %q, want linux/arm64/v8 (from the config)", im.Platform)
	}
	_, err = Open(ctx, bareRef, Options{Platform: "linux/s390x"})
	var pnf *PlatformNotFoundError
	if !errors.As(err, &pnf) {
		t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
	}
	assertStrings(t, "Available", pnf.Available, []string{"linux/amd64", "linux/arm64/v8"})
}

func TestOpenRegistryAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr []string
	}{
		{
			name: "basic authentication required",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			wantErr: []string{"requires authentication", "docker login", "private/app"},
		},
		{
			name: "access denied",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}`))
			},
			wantErr: []string{"denied access to private/app", "DENIED"},
		},
		{
			name: "manifest unknown",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`))
			},
			wantErr: []string{"not found in registry", "MANIFEST_UNKNOWN"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)
			ref := srv.Listener.Addr().String() + "/private/app:1.0"
			_, err := Open(context.Background(), ref, Options{})
			if err == nil {
				t.Fatal("Open succeeded")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			var terr *transport.Error
			if !errors.As(err, &terr) {
				t.Errorf("the registry error is no longer in the chain: %v", err)
			}
		})
	}
}

func TestOpenNilContext(t *testing.T) {
	f := newFixture(t)
	var ctx context.Context
	if _, err := Open(ctx, f.singleRef, Options{}); err != nil {
		t.Fatalf("Open with nil context: %v", err)
	}
}
