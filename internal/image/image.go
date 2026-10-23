// Package image pulls container images and exposes their root filesystem as a
// single flattened tar stream.
//
// Images are fetched straight from the registry with go-containerregistry, so
// no Docker daemon is needed; credentials come from the usual Docker
// configuration (~/.docker/config.json and credential helpers). Images can
// also be read from a `docker save` tarball, an OCI image layout directory or
// an OCI image layout archive.
package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Options configures Open.
type Options struct {
	// Platform selects the manifest from a multi-platform index, as
	// "os/arch" or "os/arch/variant".
	//
	// Empty means that no platform was requested: a single-platform image
	// (a plain manifest, or an index holding one image) is accepted whatever
	// its platform and Image.Platform reports the real one, while a
	// multi-platform index resolves to linux/<runtime.GOARCH>. A non-empty
	// value is enforced: an image whose platform differs is refused with a
	// *PlatformNotFoundError. A multi-platform index without a matching entry
	// fails with that error either way.
	Platform string
	// Input, when set, reads the image from a local source instead of a
	// registry: a `docker save` tarball (file), an OCI image layout
	// (directory) or an OCI image layout archive (file, as written by
	// `docker buildx build -o type=oci`, `podman save --format oci-archive`
	// and skopeo's oci-archive: transport). ref then selects the image inside
	// the source and may be empty when the source holds a single image. An
	// archive is extracted into a temporary directory that Image.Close
	// removes.
	Input string
	// Insecure allows plain-HTTP registries and skips TLS certificate
	// verification. Off by default.
	Insecure bool
	// RejectSPKIHashes lists SHA-256 hashes of public keys that must never
	// appear in the TLS chain of a registry connection; the connection is
	// refused if one does. This mirrors Go 1.27.3's crypto/x509 mitigation so
	// the scanner itself cannot be intercepted with the leaked eMudhra keys even
	// when built with an older toolchain.
	RejectSPKIHashes [][32]byte
	// Progress, when set, receives one-line status messages ("resolving
	// manifest", "reading layer 7/7 (12 MiB, top layer first)").
	Progress func(msg string)
}

// Image is an opened image.
type Image struct {
	// Reference is the fully qualified reference that was resolved, for
	// example "index.docker.io/library/debian:latest".
	Reference string
	// Digest is the manifest digest of the selected image ("sha256:...").
	Digest string
	// Platform is the platform of the selected image ("linux/amd64").
	Platform string
	// Config is the image configuration (environment, labels, entrypoint...).
	Config *v1.ConfigFile
	// Layers is the number of layers.
	Layers int
	// CompressedSize is the sum of the compressed layer sizes in bytes, or -1
	// when unknown.
	CompressedSize int64

	img      v1.Image
	progress func(string)
	// tempDir is the directory into which an OCI image layout archive was
	// extracted, removed by Close; empty for other sources.
	tempDir string
}

// openParams carries the per-call settings shared by the registry and local
// openers.
type openParams struct {
	// want is the requested platform (defaulted when not explicit).
	want v1.Platform
	// explicit is set when Options.Platform was given.
	explicit bool
	// report is never nil.
	report func(string)
	// progress is Options.Progress as given (possibly nil); it is kept on
	// the Image for Filesystem.
	progress func(string)
	// allowNoConfig tolerates images without a config (legacy schema 1).
	allowNoConfig bool
}

// Open resolves ref and returns the image. For registry pulls only the
// manifest and config are fetched eagerly; layers stream on demand from
// Filesystem.
//
// Multi-platform images resolve to the manifest for Options.Platform (default
// linux/<runtime.GOARCH>); when none matches the error is a
// *PlatformNotFoundError listing the available platforms. A single-platform
// image is accepted as is unless a platform was explicitly requested and
// differs. ctx governs every request made for the image, including the layer
// downloads performed later by Filesystem. Close the image when done with it.
func Open(ctx context.Context, ref string, opts Options) (*Image, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	want, err := parsePlatform(opts.Platform)
	if err != nil {
		return nil, err
	}
	p := openParams{
		want:     want,
		explicit: strings.TrimSpace(opts.Platform) != "",
		report:   reporter(opts.Progress),
		progress: opts.Progress,
	}
	if opts.Input != "" {
		return openLocal(ref, opts.Input, p)
	}
	return openRemote(ctx, ref, opts, p)
}

// newImage fills an Image from a resolved go-containerregistry image. digest
// may be zero (it is then computed) and platform nil (it is then taken from
// the config).
func newImage(reference string, img v1.Image, digest v1.Hash, platform *v1.Platform, p openParams) (*Image, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		if !p.allowNoConfig {
			return nil, fmt.Errorf("reading config of %s: %w", reference, err)
		}
		cf = nil
	}
	if platform == nil {
		platform = configPlatform(cf)
	}
	if p.explicit && platform != nil && !platformMatches(*platform, p.want) {
		return nil, &PlatformNotFoundError{
			Reference: reference,
			Requested: p.want.String(),
			Available: []string{platform.String()},
		}
	}
	if digest == (v1.Hash{}) {
		if digest, err = img.Digest(); err != nil {
			return nil, fmt.Errorf("computing digest of %s: %w", reference, err)
		}
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("listing layers of %s: %w", reference, err)
	}
	var size int64
	for _, l := range layers {
		s, err := l.Size()
		if err != nil {
			size = -1
			break
		}
		size += s
	}

	im := &Image{
		Reference:      reference,
		Digest:         digest.String(),
		Platform:       platformString(platform),
		Config:         cf,
		Layers:         len(layers),
		CompressedSize: size,
		img:            img,
		progress:       p.progress,
	}
	shown := im.Platform
	if shown == "" {
		shown = "unknown platform"
	}
	p.report(fmt.Sprintf("selected %s %s", shown, im.Digest))
	return im, nil
}

// Filesystem returns the flattened root filesystem as a tar stream: later
// layers override earlier ones, whiteouts remove files and opaque directories
// hide the contents of lower layers. GNU sparse files come out as plain
// regular files with their holes filled. The caller must Close the stream.
//
// Layers are read lazily while the stream is consumed, top layer first, under
// the context that was passed to Open; errors surface from Read.
// Options.Progress, when set, is told as each layer starts streaming
// ("reading layer 7/7 (12 MiB, top layer first)"), from the goroutine that
// produces the tar. Every call streams the layers afresh.
func (im *Image) Filesystem() (io.ReadCloser, error) {
	if im == nil || im.img == nil {
		return nil, errors.New("image: Filesystem called on an image that was not returned by Open")
	}
	layers, err := im.img.Layers()
	if err != nil {
		return nil, fmt.Errorf("listing layers of %s: %w", im.Reference, err)
	}
	pr, pw := io.Pipe()
	go func() {
		// A non-nil error is returned by the reader's next Read; nil means
		// EOF. Closing the reader early makes the writes fail, which stops
		// the extraction.
		pw.CloseWithError(flatten(layers, pw, reporter(im.progress)))
	}()
	return pr, nil
}

// Close releases what the image holds on disk: the temporary directory into
// which an OCI image layout archive was extracted. It is a no-op for images
// from other sources and may be called more than once. Call it after the
// last Filesystem stream has been read, because the layers are served from
// those files.
func (im *Image) Close() error {
	if im == nil || im.tempDir == "" {
		return nil
	}
	dir := im.tempDir
	im.tempDir = ""
	return os.RemoveAll(dir)
}

// Env returns the image's environment variables ("KEY=value"), or nil.
func (im *Image) Env() []string {
	if im == nil || im.Config == nil || len(im.Config.Config.Env) == 0 {
		return nil
	}
	return slices.Clone(im.Config.Config.Env)
}

// Underlying returns the go-containerregistry image, for callers that need
// more than this package exposes.
func (im *Image) Underlying() v1.Image { return im.img }
