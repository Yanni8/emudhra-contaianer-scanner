package image

import (
	"fmt"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// PlatformNotFoundError is returned (possibly wrapped) by Open when the image
// has no manifest for the requested platform. It lists the platforms that are
// available so that the user can pick one.
type PlatformNotFoundError struct {
	// Reference names the image that was being resolved.
	Reference string
	// Requested is the platform that was asked for ("linux/arm64").
	Requested string
	// Available lists the platforms of the selectable image manifests in
	// index order, without duplicates. "unknown" stands for a manifest that
	// declares no platform at all.
	Available []string
	// Attestations counts the attestation manifests (platform
	// unknown/unknown, as produced by BuildKit provenance/SBOM) that were
	// ignored because they are not images.
	Attestations int
}

// Error implements error.
func (e *PlatformNotFoundError) Error() string {
	available := "none"
	if len(e.Available) > 0 {
		available = strings.Join(e.Available, ", ")
	}
	msg := fmt.Sprintf("%s: no image for platform %s; available platforms: %s", e.Reference, e.Requested, available)
	switch e.Attestations {
	case 0:
	case 1:
		msg += " (1 attestation manifest ignored)"
	default:
		msg += fmt.Sprintf(" (%d attestation manifests ignored)", e.Attestations)
	}
	return msg
}

// maxIndexDepth bounds the recursion into nested image indexes.
const maxIndexDepth = 4

// defaultPlatform is the platform used when Options.Platform is empty.
func defaultPlatform() v1.Platform {
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// parsePlatform parses "os/arch" or "os/arch/variant" (optionally followed
// by ":osversion"). An empty string yields the default platform.
func parsePlatform(s string) (v1.Platform, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultPlatform(), nil
	}
	p, err := v1.ParsePlatform(s)
	if err != nil {
		return v1.Platform{}, fmt.Errorf("invalid platform %q (want os/arch or os/arch/variant): %w", s, err)
	}
	if p.OS == "" || p.Architecture == "" {
		return v1.Platform{}, fmt.Errorf("invalid platform %q (want os/arch or os/arch/variant)", s)
	}
	return *p, nil
}

// normalizePlatform folds the aliases that are commonly found in the wild so
// that "linux/arm64" and "linux/arm64/v8" compare equal, as containerd does.
func normalizePlatform(p v1.Platform) v1.Platform {
	p.OS = strings.ToLower(strings.TrimSpace(p.OS))
	p.Architecture = strings.ToLower(strings.TrimSpace(p.Architecture))
	p.Variant = strings.ToLower(strings.TrimSpace(p.Variant))
	switch p.Architecture {
	case "x86_64", "x86-64":
		p.Architecture = "amd64"
	case "aarch64":
		p.Architecture = "arm64"
	case "armhf":
		p.Architecture = "arm"
		if p.Variant == "" {
			p.Variant = "v7"
		}
	case "i386", "x86", "i686":
		p.Architecture = "386"
	}
	if p.Architecture == "arm64" && p.Variant == "v8" {
		p.Variant = ""
	}
	return p
}

// platformMatches reports whether an image of platform have satisfies the
// request want. OS and architecture must be identical; a variant or OS
// version is only compared when the request specifies one, so a request for
// linux/arm accepts linux/arm/v7 (the first such entry in index order wins,
// which is also what go-containerregistry picks).
func platformMatches(have, want v1.Platform) bool {
	h, w := normalizePlatform(have), normalizePlatform(want)
	if h.OS != w.OS || h.Architecture != w.Architecture {
		return false
	}
	if w.Variant != "" && h.Variant != w.Variant {
		return false
	}
	if w.OSVersion != "" && h.OSVersion != w.OSVersion {
		return false
	}
	return true
}

// platformString formats a platform for Image.Platform and messages, or
// returns "" when nothing is known about it.
func platformString(p *v1.Platform) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// isAttestation reports whether an index entry is a BuildKit attestation
// manifest (provenance or SBOM) rather than an image. Those are published
// with the pseudo platform unknown/unknown and must never be selected.
func isAttestation(d v1.Descriptor) bool {
	if d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown" {
		return true
	}
	return d.Annotations["vnd.docker.reference.type"] == "attestation-manifest"
}

// candidate is one selectable image manifest found in an index.
type candidate struct {
	desc   v1.Descriptor
	parent v1.ImageIndex

	img          v1.Image
	plat         *v1.Platform
	platResolved bool
}

// image loads (once) the image the candidate describes.
func (c *candidate) image() (v1.Image, error) {
	if c.img == nil {
		img, err := c.parent.Image(c.desc.Digest)
		if err != nil {
			return nil, fmt.Errorf("loading manifest %s: %w", c.desc.Digest, err)
		}
		c.img = img
	}
	return c.img, nil
}

// platform returns the candidate's platform: the one declared in the index
// or, failing that, the one recorded in the image config. nil means unknown.
func (c *candidate) platform() (*v1.Platform, error) {
	if c.platResolved {
		return c.plat, nil
	}
	c.platResolved = true
	if c.desc.Platform != nil {
		p := *c.desc.Platform
		c.plat = &p
		return c.plat, nil
	}
	img, err := c.image()
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading config of manifest %s: %w", c.desc.Digest, err)
	}
	c.plat = configPlatform(cf)
	return c.plat, nil
}

// configPlatform extracts the platform recorded in an image config, or nil
// when the config does not say.
func configPlatform(cf *v1.ConfigFile) *v1.Platform {
	if cf == nil {
		return nil
	}
	p := cf.Platform()
	if p == nil || (p.OS == "" && p.Architecture == "") {
		return nil
	}
	return p
}

// collectCandidates flattens the image manifests reachable from descs,
// descending into nested indexes and skipping attestation manifests and
// non-image artifacts. It returns the candidates in index order and the
// number of attestation manifests skipped.
func collectCandidates(parent v1.ImageIndex, descs []v1.Descriptor, depth int) ([]*candidate, int, error) {
	var (
		cands        []*candidate
		attestations int
	)
	for _, d := range descs {
		if isAttestation(d) {
			attestations++
			continue
		}
		switch {
		case d.MediaType.IsIndex():
			if depth >= maxIndexDepth {
				return nil, 0, fmt.Errorf("image index %s is nested more than %d levels deep", d.Digest, maxIndexDepth)
			}
			child, err := parent.ImageIndex(d.Digest)
			if err != nil {
				return nil, 0, fmt.Errorf("reading nested index %s: %w", d.Digest, err)
			}
			cm, err := child.IndexManifest()
			if err != nil {
				return nil, 0, fmt.Errorf("parsing nested index %s: %w", d.Digest, err)
			}
			sub, a, err := collectCandidates(child, cm.Manifests, depth+1)
			if err != nil {
				return nil, 0, err
			}
			cands = append(cands, sub...)
			attestations += a
		case d.MediaType.IsImage(), d.MediaType == "":
			cands = append(cands, &candidate{desc: d, parent: parent})
		default:
			// Signatures, SBOMs, Helm charts and other artifacts are not
			// images and cannot be scanned.
		}
	}
	return cands, attestations, nil
}

// selectCandidate picks the candidate for the requested platform.
//
// A lone candidate is the image, whatever its platform, and is accepted unless
// the platform was explicitly requested and the candidate's known platform
// differs. Among several, the first (in index order) whose platform matches
// wins; a candidate without any platform information is used only as a last
// resort and only when the platform was not explicitly requested.
func selectCandidate(ref string, cands []*candidate, attestations int, want v1.Platform, explicit bool) (*candidate, error) {
	notFound := func(available []string) error {
		return &PlatformNotFoundError{
			Reference:    ref,
			Requested:    want.String(),
			Available:    available,
			Attestations: attestations,
		}
	}
	if len(cands) == 0 {
		return nil, notFound(nil)
	}
	if len(cands) == 1 {
		c := cands[0]
		p, err := c.platform()
		if err != nil {
			return nil, err
		}
		if explicit && p != nil && !platformMatches(*p, want) {
			return nil, notFound([]string{p.String()})
		}
		return c, nil
	}

	var (
		wildcard  *candidate
		available []string
		seen      = map[string]bool{}
	)
	for _, c := range cands {
		p, err := c.platform()
		if err != nil {
			return nil, err
		}
		if p == nil {
			if wildcard == nil {
				wildcard = c
			}
			if !seen["unknown"] {
				seen["unknown"] = true
				available = append(available, "unknown")
			}
			continue
		}
		if platformMatches(*p, want) {
			return c, nil
		}
		if s := p.String(); !seen[s] {
			seen[s] = true
			available = append(available, s)
		}
	}
	if wildcard != nil && !explicit {
		return wildcard, nil
	}
	return nil, notFound(available)
}

// selectFromIndex resolves an image index to the image for the requested
// platform. ref is used in error messages only.
func selectFromIndex(idx v1.ImageIndex, ref string, want v1.Platform, explicit bool) (*candidate, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("parsing image index of %s: %w", ref, err)
	}
	cands, attestations, err := collectCandidates(idx, im.Manifests, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	return selectCandidate(ref, cands, attestations, want, explicit)
}
