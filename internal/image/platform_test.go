package image

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"

	"github.com/Yanni8/emudhra-container-scanner/internal/units"
)

func TestParsePlatform(t *testing.T) {
	tests := []struct {
		in      string
		want    v1.Platform
		wantErr bool
	}{
		{in: "", want: v1.Platform{OS: "linux", Architecture: runtime.GOARCH}},
		{in: "   ", want: v1.Platform{OS: "linux", Architecture: runtime.GOARCH}},
		{in: "linux/amd64", want: v1.Platform{OS: "linux", Architecture: "amd64"}},
		{in: " linux/arm64/v8 ", want: v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{in: "windows/amd64:10.0.17763.1234", want: v1.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.17763.1234"}},
		{in: "linux", wantErr: true},
		{in: "linux/", wantErr: true},
		{in: "/amd64", wantErr: true},
		{in: "linux/amd64/v2/extra", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parsePlatform(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePlatform(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePlatform(%q): %v", tc.in, err)
			}
			if !got.Equals(tc.want) {
				t.Errorf("parsePlatform(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPlatformMatches(t *testing.T) {
	p := func(s string) v1.Platform {
		pp, err := v1.ParsePlatform(s)
		if err != nil {
			t.Fatal(err)
		}
		return *pp
	}
	tests := []struct {
		have, want string
		match      bool
	}{
		{"linux/amd64", "linux/amd64", true},
		{"linux/amd64", "linux/arm64", false},
		{"linux/amd64", "windows/amd64", false},
		{"linux/arm64/v8", "linux/arm64", true},
		{"linux/arm64", "linux/arm64/v8", true},
		{"linux/arm64/v8", "linux/arm64/v8", true},
		{"linux/arm/v7", "linux/arm", true},
		{"linux/arm/v6", "linux/arm/v7", false},
		{"linux/arm", "linux/arm/v7", false},
		{"linux/amd64/v3", "linux/amd64", true},
		{"linux/amd64", "linux/amd64/v3", false},
		{"linux/x86_64", "linux/amd64", true},
		{"linux/aarch64", "linux/arm64/v8", true},
		{"linux/armhf", "linux/arm/v7", true},
		{"linux/i386", "linux/386", true},
		{"Linux/AMD64", "linux/amd64", true},
		{"windows/amd64:10.0.17763.1234", "windows/amd64", true},
		{"windows/amd64:10.0.17763.1234", "windows/amd64:10.0.17763.1234", true},
		{"windows/amd64:10.0.17763.1234", "windows/amd64:10.0.20348.1", false},
		{"unknown/unknown", "linux/amd64", false},
	}
	for _, tc := range tests {
		if got := platformMatches(p(tc.have), p(tc.want)); got != tc.match {
			t.Errorf("platformMatches(%s, %s) = %v, want %v", tc.have, tc.want, got, tc.match)
		}
	}
}

func TestIsAttestation(t *testing.T) {
	unknown := v1.Platform{OS: "unknown", Architecture: "unknown"}
	linux := v1.Platform{OS: "linux", Architecture: "amd64"}
	tests := []struct {
		name string
		desc v1.Descriptor
		want bool
	}{
		{name: "unknown platform", desc: v1.Descriptor{Platform: &unknown}, want: true},
		{name: "annotation only", desc: v1.Descriptor{Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}}, want: true},
		{name: "image", desc: v1.Descriptor{Platform: &linux}, want: false},
		{name: "no platform", desc: v1.Descriptor{}, want: false},
		{name: "other annotation", desc: v1.Descriptor{Platform: &linux, Annotations: map[string]string{"vnd.docker.reference.type": "other"}}, want: false},
	}
	for _, tc := range tests {
		if got := isAttestation(tc.desc); got != tc.want {
			t.Errorf("%s: isAttestation = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPlatformNotFoundErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  PlatformNotFoundError
		want string
	}{
		{
			name: "several platforms",
			err:  PlatformNotFoundError{Reference: "r:1", Requested: "linux/s390x", Available: []string{"linux/amd64", "linux/arm64/v8"}},
			want: "r:1: no image for platform linux/s390x; available platforms: linux/amd64, linux/arm64/v8",
		},
		{
			name: "one attestation",
			err:  PlatformNotFoundError{Reference: "r:1", Requested: "linux/s390x", Available: []string{"linux/amd64"}, Attestations: 1},
			want: "r:1: no image for platform linux/s390x; available platforms: linux/amd64 (1 attestation manifest ignored)",
		},
		{
			name: "nothing available",
			err:  PlatformNotFoundError{Reference: "r:1", Requested: "linux/amd64", Attestations: 2},
			want: "r:1: no image for platform linux/amd64; available platforms: none (2 attestation manifests ignored)",
		},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%s: Error() = %q, want %q", tc.name, got, tc.want)
		}
	}
	var target *PlatformNotFoundError
	wrapped := errors.New("outer: " + (&PlatformNotFoundError{}).Error())
	if errors.As(wrapped, &target) {
		t.Error("plain error must not match *PlatformNotFoundError")
	}
}

func TestSelectCandidate(t *testing.T) {
	known := func(s string) *candidate {
		p, err := v1.ParsePlatform(s)
		if err != nil {
			t.Fatal(err)
		}
		return &candidate{desc: v1.Descriptor{Platform: p}, platResolved: true, plat: p}
	}
	unknown := func() *candidate { return &candidate{platResolved: true} }
	want := v1.Platform{OS: "linux", Architecture: "arm64"}

	tests := []struct {
		name         string
		cands        []*candidate
		attestations int
		explicit     bool
		wantIndex    int // index into cands of the expected pick, -1 for an error
		wantAvail    []string
	}{
		{name: "first match in index order wins", cands: []*candidate{known("linux/amd64"), known("linux/arm64/v8"), known("linux/arm64")}, wantIndex: 1},
		{name: "exact variant preferred when requested", cands: []*candidate{known("linux/arm64/v8"), known("linux/arm64")}, wantIndex: 0},
		{name: "nothing matches", cands: []*candidate{known("linux/amd64"), known("linux/386"), known("linux/amd64")}, attestations: 2, wantIndex: -1, wantAvail: []string{"linux/amd64", "linux/386"}},
		{name: "unknown platform used as last resort", cands: []*candidate{known("linux/amd64"), unknown()}, wantIndex: 1},
		{name: "unknown platform not used when explicit", cands: []*candidate{known("linux/amd64"), unknown()}, explicit: true, wantIndex: -1, wantAvail: []string{"linux/amd64", "unknown"}},
		{name: "known match beats unknown", cands: []*candidate{unknown(), known("linux/arm64")}, wantIndex: 1},
		{name: "no candidates", wantIndex: -1},
		{name: "lone image accepted whatever its platform", cands: []*candidate{known("linux/amd64")}, wantIndex: 0},
		{name: "lone image rejected when explicitly mismatching", cands: []*candidate{known("linux/amd64")}, explicit: true, wantIndex: -1, wantAvail: []string{"linux/amd64"}},
		{name: "lone image with matching explicit platform", cands: []*candidate{known("linux/arm64/v8")}, explicit: true, wantIndex: 0},
		{name: "lone image without platform accepted even when explicit", cands: []*candidate{unknown()}, explicit: true, wantIndex: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectCandidate("ref", tc.cands, tc.attestations, want, tc.explicit)
			if tc.wantIndex < 0 {
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("error = %v, want *PlatformNotFoundError", err)
				}
				if pnf.Reference != "ref" || pnf.Requested != "linux/arm64" || pnf.Attestations != tc.attestations {
					t.Errorf("unexpected error fields: %+v", pnf)
				}
				assertStrings(t, "Available", pnf.Available, tc.wantAvail)
				return
			}
			if err != nil {
				t.Fatalf("selectCandidate: %v", err)
			}
			if got != tc.cands[tc.wantIndex] {
				t.Errorf("selected candidate %+v, want index %d", got.desc.Platform, tc.wantIndex)
			}
		})
	}
}

func TestRefMatches(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		ref         string
		want        bool
	}{
		{map[string]string{annotationRefName: "app:1.0"}, "app:1.0", true},
		{map[string]string{annotationRefName: "app:1.0"}, "index.docker.io/library/app:1.0", true},
		{map[string]string{annotationRefName: "docker.io/library/app:1.0"}, "app:1.0", true},
		{map[string]string{annotationRefName: "1.0"}, "app:1.0", true},
		{map[string]string{annotationRefName: "app:1.0"}, "1.0", true},
		{map[string]string{annotationRefName: "latest"}, "app", true},
		{map[string]string{annotationRefName: "app:1.0"}, "app:2.0", false},
		{map[string]string{annotationRefName: "app:1.0"}, "other:1.0", false},
		{map[string]string{annotationRefName: "1.0"}, "2.0", false},
		{map[string]string{annotationContainerdName: "docker.io/library/app:1.0"}, "app:1.0", true},
		{map[string]string{"unrelated": "app:1.0"}, "app:1.0", false},
		{nil, "app:1.0", false},
		{map[string]string{annotationRefName: ""}, "", false},
		{map[string]string{annotationRefName: "sha256:abc"}, "app:1.0", false},
	}
	for _, tc := range tests {
		if got := refMatches(tc.annotations, tc.ref); got != tc.want {
			t.Errorf("refMatches(%v, %q) = %v, want %v", tc.annotations, tc.ref, got, tc.want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{-1, "size unknown"},
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{12 << 20, "12 MiB"},
		{12<<20 + 300<<10, "12.3 MiB"},
		{1 << 30, "1 GiB"},
		{1 << 40, "1 TiB"},
		{1 << 60, "1 EiB"},
	}
	for _, tc := range tests {
		if got := units.Bytes(tc.n); got != tc.want {
			t.Errorf("units.Bytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestRefNames(t *testing.T) {
	descs := []v1.Descriptor{
		{Annotations: map[string]string{annotationRefName: "a:1"}},
		{Annotations: map[string]string{annotationContainerdName: "docker.io/library/b:1"}},
		{Annotations: map[string]string{annotationRefName: "a:1"}},
		{},
	}
	assertStrings(t, "refNames", refNames(descs), []string{"a:1", "docker.io/library/b:1"})
	if got := refNames(nil); got != nil {
		t.Errorf("refNames(nil) = %v", got)
	}
	if !strings.Contains(strings.Join(refNames(descs), ","), "b:1") {
		t.Error("containerd name not listed")
	}
}

func TestCollectCandidates(t *testing.T) {
	img := fixtureImage(t, linuxAMD64)
	p := linuxAMD64
	artifact := static.NewLayer([]byte("{}"), "application/vnd.example.artifact+json")

	t.Run("artifacts and attestations are skipped", func(t *testing.T) {
		idx := mutate.AppendManifests(empty.Index,
			attestationAddendum(attestationImage(t)),
			mutate.IndexAddendum{Add: artifact},
			mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}},
		)
		im, err := idx.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		cands, attestations, err := collectCandidates(idx, im.Manifests, 0)
		if err != nil {
			t.Fatalf("collectCandidates: %v", err)
		}
		if attestations != 1 {
			t.Errorf("attestations = %d, want 1", attestations)
		}
		if len(cands) != 1 || cands[0].desc.Digest.String() != imageDigest(t, img) {
			t.Fatalf("candidates = %+v, want the one image", cands)
		}
		plat, err := cands[0].platform()
		if err != nil || plat == nil || !plat.Equals(p) {
			t.Errorf("platform() = %v, %v", plat, err)
		}
	})

	t.Run("nesting depth is bounded", func(t *testing.T) {
		nest := func(levels int) v1.ImageIndex {
			idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
			for i := 0; i < levels; i++ {
				idx = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: idx})
			}
			return idx
		}
		ok := nest(maxIndexDepth)
		im, err := ok.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		cands, _, err := collectCandidates(ok, im.Manifests, 0)
		if err != nil || len(cands) != 1 {
			t.Fatalf("%d levels: candidates = %v, err = %v", maxIndexDepth, cands, err)
		}

		tooDeep := nest(maxIndexDepth + 1)
		im, err = tooDeep.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := collectCandidates(tooDeep, im.Manifests, 0); err == nil || !strings.Contains(err.Error(), "nested more than") {
			t.Fatalf("%d levels: err = %v, want a nesting error", maxIndexDepth+1, err)
		}
	})
}

func TestConfigPlatformAndPlatformString(t *testing.T) {
	if got := configPlatform(nil); got != nil {
		t.Errorf("configPlatform(nil) = %v", got)
	}
	if got := configPlatform(&v1.ConfigFile{}); got != nil {
		t.Errorf("configPlatform(empty) = %v", got)
	}
	if got := configPlatform(&v1.ConfigFile{OSVersion: "1"}); got != nil {
		t.Errorf("configPlatform(version only) = %v", got)
	}
	got := configPlatform(&v1.ConfigFile{OS: "linux", Architecture: "arm", Variant: "v7"})
	if got == nil || got.String() != "linux/arm/v7" {
		t.Errorf("configPlatform = %v", got)
	}
	if s := platformString(nil); s != "" {
		t.Errorf("platformString(nil) = %q", s)
	}
	if s := platformString(got); s != "linux/arm/v7" {
		t.Errorf("platformString = %q", s)
	}
}
