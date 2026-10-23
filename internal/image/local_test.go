package image

import (
	"archive/tar"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const repoTag = "example.com/scanner/app:1.0"

func writeTarball(t *testing.T, tag string, img v1.Image) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(file, mustTag(t, tag), img); err != nil {
		t.Fatalf("writing tarball: %v", err)
	}
	return file
}

func TestOpenTarball(t *testing.T) {
	img := fixtureImage(t, linuxAMD64)
	file := writeTarball(t, repoTag, img)
	reloaded, err := tarball.ImageFromPath(file, nil)
	if err != nil {
		t.Fatalf("reloading tarball: %v", err)
	}
	wantDigest := imageDigest(t, reloaded)

	tests := []struct {
		name    string
		ref     string
		opts    Options
		wantRef string
		wantErr string
		wantPNF []string
	}{
		{name: "without reference", ref: "", wantRef: "docker-archive:" + file + ":" + repoTag},
		{name: "with reference", ref: repoTag, wantRef: "docker-archive:" + file + ":" + repoTag},
		{name: "with equivalent reference", ref: "example.com/scanner/app:1.0", wantRef: "docker-archive:" + file + ":" + repoTag},
		{name: "explicit matching platform", ref: "", opts: Options{Platform: "linux/amd64"}, wantRef: "docker-archive:" + file + ":" + repoTag},
		{name: "explicit mismatching platform", ref: "", opts: Options{Platform: "linux/arm64"}, wantPNF: []string{"linux/amd64"}},
		{name: "unknown tag", ref: "app:1.0", wantErr: "available tags: " + repoTag},
		{name: "digest reference", ref: "example.com/scanner/app@sha256:" + strings.Repeat("a", 64), wantErr: "selected by tag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.Input = file
			var progress progressLog
			opts.Progress = progress.add
			im, err := Open(context.Background(), tc.ref, opts)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
				}
			case tc.wantPNF != nil:
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
				}
				assertStrings(t, "Available", pnf.Available, tc.wantPNF)
			default:
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if im.Reference != tc.wantRef {
					t.Errorf("Reference = %q, want %q", im.Reference, tc.wantRef)
				}
				if im.Digest != wantDigest {
					t.Errorf("Digest = %s, want %s", im.Digest, wantDigest)
				}
				if im.Platform != "linux/amd64" {
					t.Errorf("Platform = %q, want linux/amd64", im.Platform)
				}
				if im.Layers != 2 {
					t.Errorf("Layers = %d, want 2", im.Layers)
				}
				if im.CompressedSize <= 0 {
					t.Errorf("CompressedSize = %d, want > 0", im.CompressedSize)
				}
				assertStrings(t, "Env()", im.Env(), testEnv)
				assertFS(t, readFS(t, im), wantFS("linux/amd64"))
				msgs := progress.messages()
				if len(msgs) < 2 || msgs[0] != "resolving docker-archive:"+file || !strings.HasPrefix(msgs[1], "selected linux/amd64 sha256:") {
					t.Errorf("progress messages = %q", msgs)
				}
			}
		})
	}
}

func TestOpenTarballMultipleImages(t *testing.T) {
	imgA := fixtureImage(t, linuxAMD64)
	imgB := fixtureImage(t, linuxARM64v8)
	file := filepath.Join(t.TempDir(), "multi.tar")
	err := tarball.MultiWriteToFile(file, map[name.Tag]v1.Image{
		mustTag(t, "example.com/a:latest"): imgA,
		mustTag(t, "example.com/b:latest"): imgB,
	})
	if err != nil {
		t.Fatalf("writing tarball: %v", err)
	}

	_, err = Open(context.Background(), "", Options{Input: file})
	if err == nil || !strings.Contains(err.Error(), "holds 2 images") {
		t.Fatalf("Open without reference error = %v, want one about 2 images", err)
	}

	im, err := Open(context.Background(), "example.com/b", Options{Input: file})
	if err != nil {
		t.Fatalf("Open b: %v", err)
	}
	if im.Reference != "docker-archive:"+file+":example.com/b:latest" {
		t.Errorf("Reference = %q", im.Reference)
	}
	if im.Platform != "linux/arm64/v8" {
		t.Errorf("Platform = %q, want linux/arm64/v8", im.Platform)
	}
	assertFS(t, readFS(t, im), wantFS("linux/arm64/v8"))

	im, err = Open(context.Background(), "example.com/a:latest", Options{Input: file, Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("Open a: %v", err)
	}
	assertFS(t, readFS(t, im), wantFS("linux/amd64"))
}

func TestOpenTarballInvalidInputs(t *testing.T) {
	dir := t.TempDir()

	garbage := filepath.Join(dir, "garbage.tar")
	if err := os.WriteFile(garbage, []byte("this is not a tar archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	ociArchive := filepath.Join(dir, "oci.tar")
	if err := os.WriteFile(ociArchive, tarArchive(t, fileEntry("oci-layout", `{"imageLayoutVersion":"1.0.0"}`), fileEntry("index.json", `{"manifests":[]}`)), 0o644); err != nil {
		t.Fatal(err)
	}
	noImages := filepath.Join(dir, "empty.tar")
	if err := os.WriteFile(noImages, tarArchive(t, fileEntry("manifest.json", "[]")), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "missing file", input: filepath.Join(dir, "missing.tar"), wantErr: "reading local image source"},
		{name: "not a tar", input: garbage, wantErr: "not a docker-archive tarball"},
		{name: "oci layout archive without images", input: ociArchive, wantErr: "contains no images"},
		{name: "no images", input: noImages, wantErr: "contains no images"},
		{name: "directory without index.json", input: dir, wantErr: "not an OCI image layout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(context.Background(), "", Options{Input: tc.input})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func writeLayout(t *testing.T, idx v1.ImageIndex) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "layout")
	if _, err := layout.Write(dir, idx); err != nil {
		t.Fatalf("writing layout: %v", err)
	}
	return dir
}

func TestOpenLayoutByReferenceAndPlatform(t *testing.T) {
	imgA := fixtureImage(t, linuxAMD64)
	imgB := fixtureImage(t, linuxARM64v8)
	pa, pb := linuxAMD64, linuxARM64v8
	dir := writeLayout(t, mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: imgA, Descriptor: v1.Descriptor{Platform: &pa, Annotations: map[string]string{annotationRefName: "app:1.0"}}},
		mutate.IndexAddendum{Add: imgB, Descriptor: v1.Descriptor{Platform: &pb, Annotations: map[string]string{annotationRefName: "app:2.0"}}},
	))
	digestA, digestB := imageDigest(t, imgA), imageDigest(t, imgB)

	tests := []struct {
		name       string
		ref        string
		platform   string
		wantDigest string
		wantPlat   string
		wantErr    string
		wantPNF    []string
	}{
		{name: "by tag", ref: "app:1.0", wantDigest: digestA, wantPlat: "linux/amd64"},
		{name: "by fully qualified reference", ref: "index.docker.io/library/app:1.0", wantDigest: digestA, wantPlat: "linux/amd64"},
		{name: "by bare tag", ref: "2.0", wantDigest: digestB, wantPlat: "linux/arm64/v8"},
		{name: "only image for the reference wins regardless of host platform", ref: "app:2.0", wantDigest: digestB, wantPlat: "linux/arm64/v8"},
		{name: "reference plus matching platform", ref: "app:2.0", platform: "linux/arm64", wantDigest: digestB, wantPlat: "linux/arm64/v8"},
		{name: "reference plus mismatching platform", ref: "app:2.0", platform: "linux/amd64", wantPNF: []string{"linux/arm64/v8"}},
		{name: "no reference with several images", ref: "", wantErr: "holds 2 images (app:1.0, app:2.0)"},
		{name: "unknown reference", ref: "app:3.0", wantErr: "available: app:1.0, app:2.0"},
		{name: "unknown bare tag", ref: "3.0", wantErr: "available: app:1.0, app:2.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var progress progressLog
			im, err := Open(context.Background(), tc.ref, Options{Input: dir, Platform: tc.platform, Progress: progress.add})
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
				}
			case tc.wantPNF != nil:
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
				}
				assertStrings(t, "Available", pnf.Available, tc.wantPNF)
			default:
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if im.Reference != "oci:"+dir {
					t.Errorf("Reference = %q, want %q", im.Reference, "oci:"+dir)
				}
				if im.Digest != tc.wantDigest {
					t.Errorf("Digest = %s, want %s", im.Digest, tc.wantDigest)
				}
				if im.Platform != tc.wantPlat {
					t.Errorf("Platform = %q, want %q", im.Platform, tc.wantPlat)
				}
				assertStrings(t, "Env()", im.Env(), testEnv)
				assertFS(t, readFS(t, im), wantFS(tc.wantPlat))
				if msgs := progress.messages(); len(msgs) < 2 || msgs[0] != "resolving oci:"+dir {
					t.Errorf("progress messages = %q", msgs)
				}
			}
		})
	}
}

func TestOpenLayoutSingleImageWithoutAnnotations(t *testing.T) {
	img := fixtureImage(t, linuxARM64v8)
	// Neither a platform nor a name on the descriptor: the platform comes
	// from the config.
	dir := writeLayout(t, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img}))

	im, err := Open(context.Background(), "", Options{Input: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Platform != "linux/arm64/v8" {
		t.Errorf("Platform = %q, want linux/arm64/v8", im.Platform)
	}
	if want := imageDigest(t, img); im.Digest != want {
		t.Errorf("Digest = %s, want %s", im.Digest, want)
	}
	assertFS(t, readFS(t, im), wantFS("linux/arm64/v8"))

	if _, err := Open(context.Background(), "", Options{Input: dir, Platform: "linux/arm64/v8"}); err != nil {
		t.Errorf("Open with matching explicit platform: %v", err)
	}
	_, err = Open(context.Background(), "", Options{Input: dir, Platform: "linux/amd64"})
	var pnf *PlatformNotFoundError
	if !errors.As(err, &pnf) {
		t.Errorf("Open with mismatching explicit platform error = %v, want *PlatformNotFoundError", err)
	}

	_, err = Open(context.Background(), "app:1.0", Options{Input: dir})
	if err == nil || !strings.Contains(err.Error(), "carry no "+annotationRefName) {
		t.Errorf("Open with a reference error = %v, want one about missing annotations", err)
	}
}

func TestOpenLayoutNestedIndex(t *testing.T) {
	inner, images := multiPlatformIndex(t)
	outer := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        inner,
		Descriptor: v1.Descriptor{Annotations: map[string]string{annotationRefName: "multi:latest"}},
	})
	dir := writeLayout(t, outer)

	t.Run("default platform", func(t *testing.T) {
		want := expectedDefault(t)
		im, err := Open(context.Background(), "", Options{Input: dir})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if im.Platform != want.String() {
			t.Errorf("Platform = %q, want %q", im.Platform, want)
		}
		if wantDigest := indexDigest(t, inner, want); im.Digest != wantDigest {
			t.Errorf("Digest = %s, want %s", im.Digest, wantDigest)
		}
		assertFS(t, readFS(t, im), wantFS(want.String()))
	})

	t.Run("reference and platform", func(t *testing.T) {
		im, err := Open(context.Background(), "multi:latest", Options{Input: dir, Platform: "linux/arm64"})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if im.Platform != "linux/arm64/v8" {
			t.Errorf("Platform = %q, want linux/arm64/v8", im.Platform)
		}
		if want := imageDigest(t, images[linuxARM64v8.String()]); im.Digest != want {
			t.Errorf("Digest = %s, want %s", im.Digest, want)
		}
	})

	t.Run("no match lists platforms and skips the attestation", func(t *testing.T) {
		_, err := Open(context.Background(), "multi:latest", Options{Input: dir, Platform: "linux/s390x"})
		var pnf *PlatformNotFoundError
		if !errors.As(err, &pnf) {
			t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
		}
		if pnf.Attestations != 1 {
			t.Errorf("Attestations = %d, want 1", pnf.Attestations)
		}
		if !contains(pnf.Available, "linux/amd64") || !contains(pnf.Available, "linux/arm64/v8") || contains(pnf.Available, "unknown/unknown") {
			t.Errorf("Available = %q", pnf.Available)
		}
	})

	t.Run("attestation never selected", func(t *testing.T) {
		_, err := Open(context.Background(), "", Options{Input: dir, Platform: "unknown/unknown"})
		var pnf *PlatformNotFoundError
		if !errors.As(err, &pnf) {
			t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
		}
	})
}

func TestOpenLayoutDirectoryReferenceSpelling(t *testing.T) {
	// A layout path may be given with a trailing separator; the reference
	// reports it as given.
	img := fixtureImage(t, hostPlatform())
	dir := writeLayout(t, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img}))
	input := dir + string(os.PathSeparator)
	im, err := Open(context.Background(), "", Options{Input: input})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Reference != "oci:"+input {
		t.Errorf("Reference = %q, want %q", im.Reference, "oci:"+input)
	}
	if im.Platform != "linux/"+runtime.GOARCH {
		t.Errorf("Platform = %q", im.Platform)
	}
	if got := readFS(t, im)["etc/os-release"]; got.typeflag != tar.TypeReg {
		t.Errorf("os-release = %+v", got)
	}
}

func TestOpenTarballNoPlatformRequested(t *testing.T) {
	file := writeTarball(t, repoTag, fixtureImage(t, linuxS390X))
	im, err := Open(context.Background(), "", Options{Input: file})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.Platform != "linux/s390x" {
		t.Errorf("Platform = %q, want linux/s390x (the only image, whatever the host)", im.Platform)
	}
	assertFS(t, readFS(t, im), wantFS("linux/s390x"))
	if err := im.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	_, err = Open(context.Background(), "", Options{Input: file, Platform: "linux/amd64"})
	var pnf *PlatformNotFoundError
	if !errors.As(err, &pnf) {
		t.Fatalf("Open with mismatching platform error = %v, want *PlatformNotFoundError", err)
	}
	assertStrings(t, "Available", pnf.Available, []string{"linux/s390x"})
}

// archiveLayout packs the OCI image layout directory dir the way
// `tar -cf out.tar -C dir .` does ("./"-prefixed names, directory entries),
// followed by extra entries, and returns the archive's path.
func archiveLayout(t *testing.T, dir string, extra ...tarEntry) string {
	t.Helper()
	entries := []tarEntry{dirEntry("./")}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		name := "./" + filepath.ToSlash(rel)
		if d.IsDir() {
			entries = append(entries, dirEntry(name))
			return nil
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		entries = append(entries, fileEntry(name, string(content)))
		return nil
	})
	if err != nil {
		t.Fatalf("walking layout: %v", err)
	}
	entries = append(entries, extra...)
	file := filepath.Join(t.TempDir(), "oci-archive.tar")
	if err := os.WriteFile(file, tarArchive(t, entries...), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// scratchTempDir points os.TempDir at a fresh, empty directory and returns
// it, so that the test can see what Open leaves behind, together with a work
// directory outside it for the test's own files.
func scratchTempDir(t *testing.T) (tmp, work string) {
	t.Helper()
	work = t.TempDir()
	tmp = filepath.Join(work, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	return tmp, work
}

func assertTempDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("temporary directory %s left behind", e.Name())
	}
}

func TestOpenLayoutArchive(t *testing.T) {
	tmp, _ := scratchTempDir(t)
	imgA, imgB := fixtureImage(t, linuxAMD64), fixtureImage(t, linuxS390X)
	pa, pb := linuxAMD64, linuxS390X
	dir := writeLayout(t, mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: imgA, Descriptor: v1.Descriptor{Platform: &pa, Annotations: map[string]string{annotationRefName: "app:1.0"}}},
		mutate.IndexAddendum{Add: imgB, Descriptor: v1.Descriptor{Platform: &pb, Annotations: map[string]string{annotationRefName: "app:2.0"}}},
	))
	file := archiveLayout(t, dir, fileEntry("./README", "not part of the layout"))
	digestA, digestB := imageDigest(t, imgA), imageDigest(t, imgB)

	tests := []struct {
		name       string
		ref        string
		platform   string
		wantDigest string
		wantPlat   string
		wantErr    string
		wantPNF    []string
	}{
		{name: "by tag, no platform requested", ref: "app:2.0", wantDigest: digestB, wantPlat: "linux/s390x"},
		{name: "by tag with matching platform", ref: "app:1.0", platform: "linux/amd64", wantDigest: digestA, wantPlat: "linux/amd64"},
		{name: "by tag with mismatching platform", ref: "app:2.0", platform: "linux/amd64", wantPNF: []string{"linux/s390x"}},
		{name: "no reference with several images", ref: "", wantErr: "OCI image layout " + file + " holds 2 images (app:1.0, app:2.0)"},
		{name: "unknown reference", ref: "app:3.0", wantErr: "not found in OCI image layout " + file + "; available: app:1.0, app:2.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var progress progressLog
			im, err := Open(context.Background(), tc.ref, Options{Input: file, Platform: tc.platform, Progress: progress.add})
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
				}
			case tc.wantPNF != nil:
				var pnf *PlatformNotFoundError
				if !errors.As(err, &pnf) {
					t.Fatalf("Open error = %v, want *PlatformNotFoundError", err)
				}
				assertStrings(t, "Available", pnf.Available, tc.wantPNF)
			default:
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if im.Reference != "oci-archive:"+file {
					t.Errorf("Reference = %q, want %q", im.Reference, "oci-archive:"+file)
				}
				if im.Digest != tc.wantDigest {
					t.Errorf("Digest = %s, want %s", im.Digest, tc.wantDigest)
				}
				if im.Platform != tc.wantPlat {
					t.Errorf("Platform = %q, want %q", im.Platform, tc.wantPlat)
				}
				if im.Layers != 2 {
					t.Errorf("Layers = %d, want 2", im.Layers)
				}
				assertStrings(t, "Env()", im.Env(), testEnv)
				assertFS(t, readFS(t, im), wantFS(tc.wantPlat))
				msgs := progress.messages()
				if len(msgs) < 3 || !strings.HasPrefix(msgs[0], "extracting OCI image layout archive "+file+" (") || msgs[1] != "resolving oci-archive:"+file {
					t.Errorf("progress messages = %q", msgs)
				}

				// The extracted layout lives until Close.
				if im.tempDir == "" {
					t.Fatal("no temporary directory recorded")
				}
				if _, err := os.Stat(filepath.Join(im.tempDir, "index.json")); err != nil {
					t.Errorf("extracted index.json: %v", err)
				}
				if filepath.Dir(im.tempDir) != tmp {
					t.Errorf("temporary directory %s is not under TMPDIR %s", im.tempDir, tmp)
				}
				extracted := im.tempDir
				if err := im.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
				if _, err := os.Stat(extracted); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("after Close, Stat(%s) = %v, want not exist", extracted, err)
				}
				if err := im.Close(); err != nil {
					t.Errorf("second Close: %v", err)
				}
			}
			assertTempDirEmpty(t, tmp)
		})
	}
}

func TestOpenLayoutArchiveErrors(t *testing.T) {
	tmp, work := scratchTempDir(t)
	index := fileEntry("index.json", `{"schemaVersion":2,"manifests":[]}`)
	tests := []struct {
		name    string
		entries []tarEntry
		maxSize int64
		wantErr string
	}{
		{name: "entry escaping the root", entries: []tarEntry{index, fileEntry("../index.json", "{}")}, wantErr: `unsafe entry name "../index.json"`},
		{name: "blob escaping the root", entries: []tarEntry{index, fileEntry("blobs/sha256/../../../x", "")}, wantErr: "unsafe entry name"},
		{name: "absolute entry", entries: []tarEntry{index, fileEntry("/blobs/sha256/abc", "")}, wantErr: `unsafe entry name "/blobs/sha256/abc"`},
		{name: "symbolic link in blobs", entries: []tarEntry{index, symlinkEntry("blobs/sha256/abc", "/etc/passwd")}, wantErr: "entry blobs/sha256/abc is a symbolic link"},
		{name: "hard link in blobs", entries: []tarEntry{index, linkEntry("blobs/sha256/abc", "index.json")}, wantErr: "entry blobs/sha256/abc is a hard link"},
		{name: "content over the size cap", entries: []tarEntry{index, fileEntry("blobs/sha256/abc", strings.Repeat("x", 100))}, maxSize: 64, wantErr: "extracted content exceeds 64 B"},
		{name: "unparsable index.json", entries: []tarEntry{fileEntry("oci-layout", `{"imageLayoutVersion":"1.0.0"}`), fileEntry("index.json", "not json")}, wantErr: "parsing index.json of"},
		{name: "no images", entries: []tarEntry{index}, wantErr: "contains no images"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.maxSize > 0 {
				old := maxLayoutArchiveSize
				maxLayoutArchiveSize = tc.maxSize
				t.Cleanup(func() { maxLayoutArchiveSize = old })
			}
			file := filepath.Join(work, strings.ReplaceAll(tc.name, " ", "-")+".tar")
			if err := os.WriteFile(file, tarArchive(t, tc.entries...), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Open(context.Background(), "", Options{Input: file})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Open error = %v, want one containing %q", err, tc.wantErr)
			}
			assertTempDirEmpty(t, tmp)
		})
	}
}

func TestLayoutEntryName(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "index.json", want: "index.json"},
		{in: "./index.json", want: "index.json"},
		{in: "oci-layout", want: "oci-layout"},
		{in: "./blobs/", want: "blobs"},
		{in: "blobs/sha256/abc", want: "blobs/sha256/abc"},
		{in: "./blobs/sha256/./abc", want: "blobs/sha256/abc"},
		{in: "manifest.json"},
		{in: "./README"},
		{in: "blobsy/x"},
		{in: `blobs/sha256/..\x`},
		{in: "/index.json", wantErr: true},
		{in: "../index.json", wantErr: true},
		{in: "blobs/../../x", wantErr: true},
		{in: "..", wantErr: true},
	}
	for _, tc := range tests {
		got, err := layoutEntryName(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("layoutEntryName(%q) error = %v, want error %v", tc.in, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("layoutEntryName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCloseWithoutTemporaryFiles(t *testing.T) {
	var nilImage *Image
	if err := nilImage.Close(); err != nil {
		t.Errorf("nil Image Close() = %v", err)
	}
	if err := (&Image{}).Close(); err != nil {
		t.Errorf("zero Image Close() = %v", err)
	}

	file := writeTarball(t, repoTag, fixtureImage(t, linuxAMD64))
	im, err := Open(context.Background(), "", Options{Input: file})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if im.tempDir != "" {
		t.Errorf("docker-archive image records temporary directory %q", im.tempDir)
	}
	if err := im.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// The source is untouched and still readable.
	assertFS(t, readFS(t, im), wantFS("linux/amd64"))

	dir := writeLayout(t, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: fixtureImage(t, linuxAMD64)}))
	im, err = Open(context.Background(), "", Options{Input: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := im.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		t.Errorf("Close removed the user's layout directory: %v", err)
	}
}
