package scan

import (
	"bytes"
	"strings"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/stores"
)

// Rust packs string literals back to back, so a version string has no
// boundary before it and other components embed look-alikes (the
// OpenTelemetry exporter inside Deno carries "OTel-OTLP-Exporter-Deno/0.82.0"
// next to the real "Deno/2.9.8" user agent). The probe therefore reads every
// occurrence and keeps the highest version: a binary's own version is never
// lower than the versions of the components and fixtures it embeds.

// probeCarry is the number of bytes kept between chunks so that a version
// string cut by a chunk boundary is still found; every pattern plus the
// longest version it can precede fits in it.
const probeCarry = 64

// probePattern is a literal that a runtime binary embeds right before its
// own version: Node.js' release download URL, the Deno, Bun and uv user
// agents.
type probePattern struct {
	manager string
	prefix  []byte
}

// runtimeProbes maps the runtime name of an embedded-runtime store to the
// patterns that reveal its version. Only the binary's own patterns are
// looked for, so the Node.js compatibility strings inside Bun do not count.
var runtimeProbes = map[string][]probePattern{
	"Node.js":                          {{"node", []byte("nodejs.org/download/release/v")}, {"node", []byte("nodejs.org/download/nightly/v")}},
	"Node.js (libnode shared library)": {{"node", []byte("nodejs.org/download/release/v")}},
	"Deno":                             {{"deno", []byte("Deno/")}},
	"Bun":                              {{"bun", []byte("Bun v")}, {"bun", []byte("bun/")}},
	"uv":                               {{"uv", []byte("uv/")}},
}

// runtimeName strips the store-name suffix of an embedded-runtime store.
func runtimeName(s stores.Store) string {
	return strings.TrimSuffix(s.Name, " (embedded root store)")
}

// versionProbe is an io.Writer that looks for runtime version strings in
// the bytes of an executable while they stream past the certificate finder
// (through io.TeeReader). It never buffers the file: each chunk is searched
// as it comes, with probeCarry bytes kept from the previous one.
type versionProbe struct {
	patterns []probePattern
	carry    []byte
	versions map[string]string // manager -> highest version seen
}

// newVersionProbe returns a probe for the runtime, or nil when the runtime
// embeds no known version string.
func newVersionProbe(runtime string) *versionProbe {
	patterns := runtimeProbes[runtime]
	if len(patterns) == 0 {
		return nil
	}
	return &versionProbe{patterns: patterns, versions: map[string]string{}}
}

// Write implements io.Writer; it never fails.
func (v *versionProbe) Write(p []byte) (int, error) {
	if len(v.carry) > 0 {
		edge := append(append(make([]byte, 0, 2*probeCarry), v.carry...), p[:min(len(p), probeCarry)]...)
		v.scan(edge)
	}
	v.scan(p)
	if len(p) >= probeCarry {
		v.carry = append(v.carry[:0], p[len(p)-probeCarry:]...)
	} else {
		v.carry = append(v.carry, p...)
		if len(v.carry) > probeCarry {
			v.carry = append(v.carry[:0:0], v.carry[len(v.carry)-probeCarry:]...)
		}
	}
	return len(p), nil
}

// scan looks for every pattern in buf and keeps the highest version found.
func (v *versionProbe) scan(buf []byte) {
	for _, pat := range v.patterns {
		for _, version := range findVersions(buf, pat.prefix) {
			if cur, ok := v.versions[pat.manager]; !ok || stores.CompareVersion(version, cur) > 0 {
				v.versions[pat.manager] = version
			}
		}
	}
}

// findVersions returns the semantic versions that follow the complete
// occurrences of prefix in buf. An occurrence whose version runs into the
// end of buf is left for the next chunk.
func findVersions(buf, prefix []byte) []string {
	var out []string
	pos := 0
	for {
		i := bytes.Index(buf[pos:], prefix)
		if i < 0 {
			return out
		}
		start := pos + i + len(prefix)
		version, ok, complete := semverAt(buf[start:])
		switch {
		case ok:
			out = append(out, version)
		case !complete:
			return out
		}
		pos = pos + i + 1
	}
}

// semverAt reads "major.minor.patch" at the start of b. complete is false
// when b ends before the version can be judged.
func semverAt(b []byte) (version string, ok, complete bool) {
	i := 0
	for part := 0; part < 3; part++ {
		digits := 0
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
			digits++
		}
		if i == len(b) {
			return "", false, false
		}
		if digits == 0 || digits > 6 {
			return "", false, true
		}
		if part < 2 {
			if b[i] != '.' {
				return "", false, true
			}
			i++
		}
	}
	return string(b[:i]), true, true
}
