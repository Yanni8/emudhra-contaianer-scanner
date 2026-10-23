package scan

import (
	"strconv"
	"strings"

	"emudhra-container-scanner/internal/rpmdb"
	"emudhra-container-scanner/internal/stores"
)

// packages assembles the package status list: distribution packages
// relevant to trust from the dpkg, status.d, apk and rpm databases (with
// the ca-certificates and JDK fix comparisons), then the versions found in
// Python dist-info directories, pip's vendor list, JDK release files, the
// Node.js version header, the Go VERSION file and runtime binaries, then
// the versions the image environment states for runtimes not seen on disk.
// It also records the distribution packages in w.facts.
func (w *walker) packages(os stores.OSInfo) []PackageStatus {
	fix, fixOK := stores.CACertificatesFix(os)
	var distro []stores.Package
	if w.dpkgStatus != nil {
		distro = append(distro, stores.ParseDpkgStatus(w.dpkgStatus, stores.TrustPackages)...)
	}
	for _, d := range w.statusD {
		distro = append(distro, stores.ParseDpkgStatusD(d, stores.TrustPackages)...)
	}
	for _, a := range w.apkInstalled {
		distro = append(distro, stores.ParseApkInstalled(a, stores.TrustPackages)...)
	}
	distro = append(distro, w.rpmPackages...)
	w.facts.Packages = distro

	out := make([]PackageStatus, 0, len(distro)+len(w.versions))
	for _, p := range distro {
		out = append(out, distroStatus(p, fix, fixOK))
	}
	out = append(out, w.versions...)
	out = append(out, w.envVersions(out)...)
	w.packageRows = out
	return out
}

// rpmTrustPackage selects the rpm packages worth reporting: the trust
// store and TLS libraries and the distribution JDKs (java-17-openjdk,
// java-21-openjdk-headless, ...). gpg-pubkey pseudo packages are not.
func rpmTrustPackage(name string) bool {
	switch name {
	case "ca-certificates", "ca-certificates-mozilla", "openssl", "openssl-libs", "p11-kit", "p11-kit-trust", "nss":
		return true
	}
	return strings.HasPrefix(name, "java-") && (strings.HasSuffix(name, "-openjdk") || strings.HasSuffix(name, "-openjdk-headless"))
}

// isCACertificatesPackage reports whether the package carries the system
// trust store (ca-certificates, Alpine's ca-certificates-bundle, SUSE's
// ca-certificates-mozilla).
func isCACertificatesPackage(name string) bool {
	switch name {
	case "ca-certificates", "ca-certificates-bundle", "ca-certificates-mozilla":
		return true
	}
	return false
}

// distroStatus builds the status of a distribution package: the
// ca-certificates comparison with the distribution's fix, the JDK
// comparison for openjdk packages.
func distroStatus(p stores.Package, fix stores.Fix, fixOK bool) PackageStatus {
	ps := PackageStatus{Name: p.Name, Version: p.Version, Manager: p.Manager}
	switch {
	case isCACertificatesPackage(p.Name):
		ps.FixedVersion, ps.Reference, ps.Note = fix.FixedVersion, fix.Reference, fix.Note
		if fixOK && fix.FixedVersion != "" {
			outdated := compareDistroVersion(p.Manager, p.Version, fix.FixedVersion) < 0
			ps.Outdated = &outdated
		}
	case strings.Contains(p.Name, "openjdk"):
		if major, normalised, ok := stores.JavaVersionMajor(stripEpoch(p.Version)); ok {
			applyJavaFix(&ps, major, normalised)
		}
	}
	return ps
}

// compareDistroVersion compares package versions with the rules of their
// package manager: rpm's EVR comparison (an epoch, "_" as a separator, a
// fixed version without release matching every release) or dpkg's.
func compareDistroVersion(manager, a, b string) int {
	if manager == "rpm" {
		return rpmdb.CompareEVR(a, b)
	}
	return stores.CompareDebVersion(a, b)
}

// stripEpoch removes a leading "epoch:" from a package version.
func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// applyJavaFix fills the verdict for a Java release line: lines with a
// fixed release are compared, Java 8 (no fixed release yet) is outdated
// with the advisory's note, unknown lines get no verdict.
func applyJavaFix(ps *PackageStatus, major int, normalised string) {
	lf, ok := stores.JavaFix(major)
	if !ok {
		ps.Note = "no fix data for the Java " + strconv.Itoa(major) + " release line"
		return
	}
	ps.FixedVersion, ps.Reference, ps.Note = lf.FixedVersion, lf.Reference, lf.Note
	outdated := true
	if lf.FixedVersion != "" {
		outdated = stores.CompareVersion(normalised, lf.FixedVersion) < 0
	}
	ps.Outdated = &outdated
}

// javaStatus builds the status of a JDK or JRE installation.
func javaStatus(impl, version, manager, where string) PackageStatus {
	ps := PackageStatus{Name: "java (" + impl + ")", Version: version, Manager: manager, Path: where}
	if major, normalised, ok := stores.JavaVersionMajor(version); ok {
		applyJavaFix(&ps, major, normalised)
	}
	return ps
}

// applyLineFix fills the verdict from a per-line fix: an end-of-life line
// is outdated with no fixed version, a line with a fixed release is
// compared, a line without fix data gets the note only.
func applyLineFix(ps *PackageStatus, lf stores.LineFix) {
	ps.FixedVersion, ps.Reference, ps.Note = lf.FixedVersion, lf.Reference, lf.Note
	switch {
	case lf.EOL:
		outdated := true
		ps.Outdated = &outdated
	case lf.FixedVersion != "":
		outdated := stores.CompareVersion(ps.Version, lf.FixedVersion) < 0
		ps.Outdated = &outdated
	}
}

// nodeStatus builds the status of a Node.js installation from its version.
func nodeStatus(version, where string) PackageStatus {
	ps := PackageStatus{Name: "node", Version: version, Manager: "node", Path: where}
	major, _, _ := strings.Cut(strings.TrimPrefix(version, "v"), ".")
	if m, err := strconv.Atoi(major); err == nil {
		applyLineFix(&ps, stores.NodeFix(m))
	}
	return ps
}

// goStatus builds the status of a Go toolchain from its version ("1.25.14").
func goStatus(version, where string) PackageStatus {
	ps := PackageStatus{Name: "go", Version: version, Manager: "go", Path: where}
	parts := strings.SplitN(strings.TrimPrefix(version, "go"), ".", 3)
	if len(parts) < 2 {
		return ps
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 == nil && err2 == nil {
		applyLineFix(&ps, stores.GoFix(major, minor))
	}
	return ps
}

// runtimeStatus builds the status of a runtime found by a binary probe or
// an environment variable: node, deno, bun or uv.
func runtimeStatus(manager, version, where string) PackageStatus {
	switch manager {
	case "node":
		return nodeStatus(version, where)
	case "go":
		return goStatus(version, where)
	}
	ps := PackageStatus{Name: manager, Version: version, Manager: manager, Path: where}
	switch manager {
	case "deno":
		applyLineFix(&ps, stores.DenoFix())
	case "bun":
		applyLineFix(&ps, stores.BunFix())
	case "uv":
		applyLineFix(&ps, stores.UVFix())
	}
	return ps
}

// pythonPackage builds the status of certifi or pip found at a path.
func pythonPackage(pkg, version, where string) PackageStatus {
	ps := PackageStatus{Name: pkg, Version: version, Manager: "pip", Path: where}
	switch pkg {
	case "certifi":
		applyLineFix(&ps, stores.CertifiFix())
	case "pip":
		applyLineFix(&ps, stores.PipFix())
	}
	return ps
}

// envVersionVars maps the environment variables that state a runtime
// version (the official images set them) to the manager of the row.
var envVersionVars = []struct{ variable, manager string }{
	{"NODE_VERSION", "node"}, {"DENO_VERSION", "deno"}, {"BUN_VERSION", "bun"}, {"UV_VERSION", "uv"},
	{"GOLANG_VERSION", "go"}, {"JAVA_VERSION", "jdk"},
}

// envVersions adds rows for runtimes whose version only the image
// environment states (no release file, header or binary gave one).
func (w *walker) envVersions(existing []PackageStatus) []PackageStatus {
	present := map[string]bool{}
	for _, ps := range existing {
		present[ps.Manager] = true
	}
	env := map[string]string{}
	for _, kv := range w.opts.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	var out []PackageStatus
	for _, ev := range envVersionVars {
		value := strings.TrimPrefix(env[ev.variable], "v")
		if value == "" {
			continue
		}
		where := ev.variable + " (image environment)"
		switch ev.manager {
		case "jdk":
			if present["jdk"] || present["jre"] {
				continue
			}
			value = strings.TrimPrefix(strings.TrimPrefix(value, "jdk-"), "jre-")
			out = append(out, javaStatus("from JAVA_VERSION", value, "jdk", where))
		default:
			if present[ev.manager] {
				continue
			}
			out = append(out, runtimeStatus(ev.manager, value, where))
		}
	}
	return out
}

// runtimeManagers maps embedded-runtime store names to the manager of the
// package rows that carry their version.
var runtimeManagers = map[string]string{
	"Node.js": "node", "Node.js (libnode shared library)": "node", "Deno": "deno", "Bun": "bun", "uv": "uv",
}

// runtimeVerdict is the detected version of a runtime and its verdict.
type runtimeVerdict struct {
	version, fixed string
	outdated       bool
}

// runtimeVersion returns the version row of the runtime behind an
// embedded-runtime store, when one with a verdict was found.
func (w *walker) runtimeVersion(st stores.Store) (runtimeVerdict, bool) {
	manager := runtimeManagers[runtimeName(st)]
	if manager == "" {
		return runtimeVerdict{}, false
	}
	for _, ps := range w.packageRows {
		if ps.Manager == manager && ps.Outdated != nil {
			return runtimeVerdict{version: ps.Version, fixed: ps.FixedVersion, outdated: *ps.Outdated}, true
		}
	}
	return runtimeVerdict{}, false
}
