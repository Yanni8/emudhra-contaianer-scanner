package image

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// openRemote resolves ref against its registry.
func openRemote(ctx context.Context, ref string, opts Options, p openParams) (*Image, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("image reference is empty")
	}
	nameOpts := []name.Option{name.WeakValidation}
	if opts.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}
	full := parsed.Name()
	p.report("resolving " + full)

	desc, err := remote.Get(parsed,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(newTransport(opts)),
		remote.WithPlatform(p.want),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", full, annotateRegistryError(parsed, err))
	}

	var (
		img      v1.Image
		digest   = desc.Digest
		platform *v1.Platform
	)
	switch {
	case desc.MediaType.IsIndex():
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("reading image index of %s: %w", full, annotateRegistryError(parsed, err))
		}
		sel, err := selectFromIndex(idx, full, p.want, p.explicit)
		if err != nil {
			return nil, annotateRegistryError(parsed, err)
		}
		if img, err = sel.image(); err != nil {
			return nil, fmt.Errorf("fetching platform manifest of %s: %w", full, annotateRegistryError(parsed, err))
		}
		digest = sel.desc.Digest
		platform, _ = sel.platform() // resolved during selection; cannot fail now
	case desc.MediaType.IsSchema1():
		// Legacy Docker schema 1 manifests carry no usable config, but their
		// layers can still be extracted and scanned.
		if img, err = desc.Schema1(); err != nil {
			return nil, fmt.Errorf("reading legacy manifest of %s: %w", full, err)
		}
		p.allowNoConfig = true
	default:
		if img, err = desc.Image(); err != nil {
			return nil, fmt.Errorf("reading manifest of %s: %w", full, annotateRegistryError(parsed, err))
		}
	}

	im, err := newImage(full, img, digest, platform, p)
	if err != nil {
		return nil, annotateRegistryError(parsed, err)
	}
	return im, nil
}

// annotateRegistryError prefixes registry responses that users commonly run
// into (authentication required, access denied, unknown image) with a plain
// explanation. Other errors are returned unchanged; the original error is
// always kept in the chain.
func annotateRegistryError(ref name.Reference, err error) error {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return err
	}
	codes := make(map[transport.ErrorCode]bool, len(terr.Errors))
	for _, d := range terr.Errors {
		codes[d.Code] = true
	}
	registry := ref.Context().RegistryStr()
	repo := ref.Context().RepositoryStr()
	switch {
	case terr.StatusCode == http.StatusUnauthorized || codes[transport.UnauthorizedErrorCode]:
		return fmt.Errorf("registry %s requires authentication for %s (or the repository does not exist); run `docker login %s` or check ~/.docker/config.json: %w", registry, repo, registry, err)
	case terr.StatusCode == http.StatusForbidden || codes[transport.DeniedErrorCode]:
		return fmt.Errorf("registry %s denied access to %s; check that the configured credentials may pull it: %w", registry, repo, err)
	case terr.StatusCode == http.StatusNotFound || codes[transport.ManifestUnknownErrorCode] || codes[transport.NameUnknownErrorCode]:
		return fmt.Errorf("image %s not found in registry %s (unknown repository, tag or digest): %w", ref.Name(), registry, err)
	case terr.StatusCode == http.StatusTooManyRequests || codes[transport.TooManyRequestsErrorCode]:
		return fmt.Errorf("registry %s is rate limiting pulls; retry later or authenticate: %w", registry, err)
	}
	return err
}
