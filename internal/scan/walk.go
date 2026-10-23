package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Yanni8/emudhra-container-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-container-scanner/internal/certs"
	"github.com/Yanni8/emudhra-container-scanner/internal/rpmdb"
	"github.com/Yanni8/emudhra-container-scanner/internal/stores"
	"github.com/Yanni8/emudhra-container-scanner/internal/units"
)

// Sizes and limits of the walk.
const (
	// headerSize is the number of leading bytes handed to stores.Classify
	// and the version sniffers, and kept per store for re-classification.
	headerSize = 4096
	// captureLimit bounds configuration files and small package databases
	// that are kept whole; dpkgLimit and rpmdbLimit bound the big ones.
	captureLimit = 4 << 20
	dpkgLimit    = 32 << 20
	rpmdbLimit   = 256 << 20
	// progressEvery is the file interval of progress messages.
	progressEvery = 2000
	// maxLinkHops bounds symlink chains when resolving aliases.
	maxLinkHops = 16
)

// candidate is a certificate (or bare key) that matched the blocklist, before
// trust and severity are resolved.
type candidate struct {
	path string
	info CertInfo
	// identity names the certificate across stores: its fingerprint, or the
	// listed certificate's fingerprint for a bare-key match.
	identity string
	trust    certs.TrustState
	detail   string
	purposes map[certs.Purpose]certs.TrustState
	note     string
	matches  []blocklist.Match
	// alsoAt lists the offsets of further copies of the same certificate in
	// the same file.
	alsoAt []int64
}

// certID identifies a certificate by its fingerprint and public-key hash.
type certID struct {
	sha256, spki string
}

// storeState accumulates what was found in one file.
type storeState struct {
	// store is the classification of the real path; final is the strongest
	// classification over the real path and its aliases, decided in
	// finish(), and via names the alias that gave it ("" for the real path).
	store stores.Store
	final stores.Store
	via   string
	head  []byte
	// certs counts distinct certificates, blocks every occurrence.
	certs    int
	blocks   int
	findings int
	// ids lists the distinct certificates; distrusted those that a p11-kit
	// object marks x-distrusted.
	ids        []certID
	distrusted []certID
	// seen maps a certificate identity to the index of its candidate in
	// walker.candidates, or -1 when it matched nothing.
	seen map[string]int
}

// walker holds the state of one scan.
type walker struct {
	ctx      context.Context
	opts     Options
	bl       *blocklist.List
	certOpts certs.Options
	start    time.Time

	symlinks  map[string]string // absolute link name -> absolute target
	hardlinks map[string]string // absolute link name -> absolute target
	stores    map[string]*storeState
	storeList []string // insertion order of stores

	candidates []candidate
	warnings   []string
	files      int
	bytes      int64
	certsFound int

	// Captured configuration and package databases.
	caConf       []byte
	osRelease    []byte
	libOSRelease []byte
	dpkgStatus   []byte
	statusD      [][]byte
	apkInstalled [][]byte
	rpmPackages  []stores.Package
	packageDBs   []string // labels for Summary.PackageDatabase
	// Facts about the image's tooling, for stores.SystemRemediation.
	updateCACerts bool
	pkgManager    bool

	versions    []PackageStatus // from dist-info directories, release files, headers, binaries
	versionSeen map[string]bool
	packageRows []PackageStatus // the final package list, for the runtime verdicts
	warnPath    string

	// Context assembled by finish() for resolving trust.
	os       stores.OSInfo
	facts    stores.SystemFacts
	conf     *stores.DebianConf
	hints    []stores.EnvHint
	aliases  map[string][]string
	bundleFP map[string]string // fingerprint -> first system bundle holding it
	distrust distrustIndex
}

func newWalker(ctx context.Context, opts Options) *walker {
	w := &walker{
		ctx:         ctx,
		opts:        opts,
		bl:          opts.Blocklist,
		start:       time.Now(),
		symlinks:    map[string]string{},
		hardlinks:   map[string]string{},
		stores:      map[string]*storeState{},
		versionSeen: map[string]bool{},
	}
	if w.bl == nil {
		w.bl = blocklist.Default()
	}
	var patterns []certs.SPKIPattern
	for _, p := range w.bl.SPKIPatterns() {
		patterns = append(patterns, certs.SPKIPattern{ID: p.Entry.ID, Pattern: p.Pattern})
	}
	w.certOpts = certs.Options{
		SPKIPatterns:      patterns,
		MaxBuffer:         opts.MaxBuffer,
		KeystorePasswords: opts.KeystorePasswords,
		Warn:              func(msg string) { w.warnf("%s: %s", w.warnPath, msg) },
	}
	return w
}

func (w *walker) warnf(format string, args ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, args...))
}

func (w *walker) progress(format string, args ...any) {
	if w.opts.Progress != nil {
		w.opts.Progress(fmt.Sprintf(format, args...))
	}
}

// absPath normalises a tar entry name to a clean absolute path.
func absPath(name string) string {
	return path.Clean("/" + strings.TrimSpace(name))
}

// resolveTarget turns a symlink target into an absolute path relative to the
// link's directory.
func resolveTarget(link, target string) string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	return path.Clean(path.Join(path.Dir(link), target))
}

// walk reads every entry of the tar stream.
func (w *walker) walk(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		if err := w.ctx.Err(); err != nil {
			return fmt.Errorf("scan cancelled: %w", err)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading image filesystem: %w", err)
		}
		name := absPath(hdr.Name)
		if name == "/" {
			continue
		}
		w.noteTool(name)
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			w.symlinks[name] = resolveTarget(name, hdr.Linkname)
		case tar.TypeLink:
			w.hardlinks[name] = absPath(hdr.Linkname)
		case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse:
			// archive/tar expands the holes of sparse entries, so they read
			// like regular files.
			if err := w.file(name, hdr.Size, tr); err != nil {
				return err
			}
		case tar.TypeDir:
			w.noteVersionDir(name)
		}
	}
	w.progress("scanned %d files (%s)", w.files, units.Bytes(w.bytes))
	return nil
}

// file scans one regular file.
func (w *walker) file(name string, size int64, r io.Reader) error {
	w.files++
	w.bytes += size
	if w.files%progressEvery == 0 {
		w.progress("scanning... %d files (%s)", w.files, units.Bytes(w.bytes))
	}
	w.warnPath = name
	w.noteVersionDir(name)

	head := make([]byte, min(size, headerSize))
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("reading %s from the image filesystem: %w", name, err)
	}
	head = head[:n]
	store := stores.Classify(name, head)

	var body io.Reader = io.MultiReader(bytes.NewReader(head), r)
	var probe *versionProbe
	if store.Class == stores.ClassEmbeddedRuntime {
		if probe = newVersionProbe(runtimeName(store)); probe != nil {
			body = io.TeeReader(body, probe)
		}
	}

	var found []certs.Found
	limit := w.captureLimit(name)
	switch {
	case limit > 0 && size <= limit:
		data, err := io.ReadAll(io.LimitReader(body, limit+1))
		if err != nil {
			return fmt.Errorf("reading %s from the image filesystem: %w", name, err)
		}
		w.capture(name, data)
		found = certs.ScanBytes(data, name, w.certOpts)
	default:
		if limit > 0 {
			w.captureSkipped(name, size, limit)
		}
		found, err = certs.Scan(body, name, size, w.certOpts)
		if err != nil {
			return fmt.Errorf("reading %s from the image filesystem: %w", name, err)
		}
	}
	if probe != nil {
		w.noteProbe(name, probe)
	}
	w.noteVersionFile(name, head)
	w.record(name, store, head, found)
	return nil
}

// captureLimit returns the size limit for files whose content the engine
// needs after the walk, or 0 for ordinary files.
func (w *walker) captureLimit(name string) int64 {
	switch name {
	case "/etc/ca-certificates.conf", "/etc/os-release", "/usr/lib/os-release",
		"/lib/apk/db/installed", "/usr/lib/apk/db/installed":
		return captureLimit
	case "/var/lib/dpkg/status":
		return dpkgLimit
	}
	if isStatusDFile(name) || strings.HasSuffix(name, "/pip/_vendor/vendor.txt") || isGoVersionFile(name) {
		return captureLimit
	}
	if _, ok := rpmdb.IsDatabasePath(name); ok {
		return rpmdbLimit
	}
	return 0
}

// isStatusDFile reports whether name is a package stanza file of a
// distroless image (/var/lib/dpkg/status.d/<package>; the *.md5sums files
// next to them are file lists).
func isStatusDFile(name string) bool {
	const dir = "/var/lib/dpkg/status.d/"
	if !strings.HasPrefix(name, dir) {
		return false
	}
	base := name[len(dir):]
	return base != "" && !strings.Contains(base, "/") && !strings.HasSuffix(base, ".md5sums")
}

// isGoVersionFile reports whether name is a Go toolchain's VERSION file
// (/usr/local/go/VERSION in the official images).
func isGoVersionFile(name string) bool {
	return path.Base(name) == "VERSION" && strings.HasPrefix(path.Base(path.Dir(name)), "go")
}

// capture stores the content of a configuration file or package database.
func (w *walker) capture(name string, data []byte) {
	switch name {
	case "/etc/ca-certificates.conf":
		w.caConf = data
	case "/etc/os-release":
		w.osRelease = data
	case "/usr/lib/os-release":
		w.libOSRelease = data
	case "/var/lib/dpkg/status":
		w.dpkgStatus = data
		w.packageDBs = append(w.packageDBs, "dpkg")
	case "/lib/apk/db/installed", "/usr/lib/apk/db/installed":
		w.apkInstalled = append(w.apkInstalled, data)
		w.packageDBs = append(w.packageDBs, "apk")
	}
	switch {
	case isStatusDFile(name):
		if len(w.statusD) == 0 {
			w.packageDBs = append(w.packageDBs, "dpkg (status.d)")
		}
		w.statusD = append(w.statusD, data)
	case strings.HasSuffix(name, "/pip/_vendor/vendor.txt"):
		w.noteVendoredCertifi(name, data)
	case isGoVersionFile(name):
		w.noteGoVersionFile(name, data)
	}
	if format, ok := rpmdb.IsDatabasePath(name); ok {
		w.captureRPM(name, format, data)
	}
}

// captureSkipped records a package database that was too large to read.
func (w *walker) captureSkipped(name string, size, limit int64) {
	if format, ok := rpmdb.IsDatabasePath(name); ok {
		w.packageDBs = append(w.packageDBs, fmt.Sprintf("rpm (%s, not parsed: %s is larger than the %s limit)", format, units.Bytes(size), units.Bytes(limit)))
		w.warnf("%s: rpm database not read: %s is larger than the %s limit", name, units.Bytes(size), units.Bytes(limit))
	}
}

// captureRPM parses an rpm database and keeps its trust-relevant packages.
func (w *walker) captureRPM(name, format string, data []byte) {
	pkgs, err := rpmdb.Parse(format, data)
	if err != nil {
		reason := err.Error()
		if errors.Is(err, rpmdb.ErrUnsupported) {
			reason = "unsupported variant: " + reason
		}
		w.packageDBs = append(w.packageDBs, fmt.Sprintf("rpm (%s, not parsed: %s)", format, reason))
		w.warnf("%s: rpm database not read: %v", name, err)
		return
	}
	w.packageDBs = append(w.packageDBs, "rpm ("+format+")")
	for _, p := range pkgs {
		if rpmTrustPackage(p.Name) {
			w.rpmPackages = appendPackage(w.rpmPackages, stores.Package{Name: p.Name, Version: p.EVR(), Manager: "rpm"})
		}
	}
}

// appendPackage adds p unless an identical entry is present.
func appendPackage(list []stores.Package, p stores.Package) []stores.Package {
	for _, q := range list {
		if q == p {
			return list
		}
	}
	return append(list, p)
}

// binDirs are the directories in which the package managers and trust
// tools are looked for (merged-/usr layouts expose /bin as /usr/bin too).
var binDirs = map[string]bool{
	"/bin/": true, "/sbin/": true, "/usr/bin/": true, "/usr/sbin/": true,
	"/usr/local/bin/": true, "/usr/local/sbin/": true,
}

// noteTool records the presence of package managers and of
// update-ca-certificates from entry names (files, links or symlinks alike).
func (w *walker) noteTool(name string) {
	dir, base := path.Split(name)
	if !binDirs[dir] {
		return
	}
	switch base {
	case "update-ca-certificates":
		w.updateCACerts = true
	case "apt", "apt-get", "dpkg", "apk", "dnf", "dnf-3", "dnf5", "yum", "microdnf", "tdnf", "rpm", "zypper", "pacman":
		w.pkgManager = true
	}
}

// record registers the objects found in one file and matches them against
// the blocklist. A certificate that appears several times in the file is
// counted and matched once, at its first offset.
func (w *walker) record(name string, store stores.Store, head []byte, found []certs.Found) {
	keep := len(found) > 0
	switch store.Class {
	case stores.ClassSystemBundle, stores.ClassJavaKeystore, stores.ClassNSSDB:
		keep = true
	}
	if !keep {
		return
	}
	ss := w.storeFor(name, store, head)
	for _, f := range found {
		var (
			matches []blocklist.Match
			info    CertInfo
			id      string
		)
		if f.Kind == certs.KindSPKI {
			e := w.bl.ByID(f.PatternID)
			if e == nil {
				continue
			}
			matches = []blocklist.Match{{Entry: e, Kind: blocklist.MatchSPKI}}
			info = spkiInfo(e, f)
			id = "spki:" + e.SPKISHA256
		} else {
			if f.Certificate == nil {
				continue
			}
			info = certInfo(f)
			id = info.SHA256
			w.certsFound++
			ss.blocks++
		}
		if idx, dup := ss.seen[id]; dup {
			if idx >= 0 {
				w.candidates[idx].alsoAt = append(w.candidates[idx].alsoAt, f.Offset)
			}
			continue
		}
		ss.seen[id] = -1
		if f.Kind != certs.KindSPKI {
			ss.certs++
			cid := certID{sha256: info.SHA256, spki: info.SPKISHA256}
			ss.ids = append(ss.ids, cid)
			if f.Kind == certs.KindP11Kit && f.Trust == certs.TrustDistrusted {
				ss.distrusted = append(ss.distrusted, cid)
			}
			matches = w.bl.MatchCertificate(f.Certificate)
		}
		if len(matches) == 0 {
			continue
		}
		if matches[0].Kind == blocklist.MatchOperator && !w.opts.IncludeOperatorHeuristic {
			continue
		}
		ss.seen[id] = len(w.candidates)
		identity := info.SHA256
		if f.Kind == certs.KindSPKI {
			identity = matches[0].Entry.SHA256
		}
		w.candidates = append(w.candidates, candidate{
			path:     name,
			info:     info,
			identity: identity,
			trust:    f.Trust,
			detail:   f.TrustDetail,
			purposes: f.Purposes,
			note:     f.Note,
			matches:  matches,
		})
	}
}

func (w *walker) storeFor(name string, store stores.Store, head []byte) *storeState {
	ss, ok := w.stores[name]
	if !ok {
		ss = &storeState{store: store, final: store, head: append([]byte(nil), head...), seen: map[string]int{}}
		w.stores[name] = ss
		w.storeList = append(w.storeList, name)
	}
	return ss
}

// certInfo summarises a found certificate.
func certInfo(f certs.Found) CertInfo {
	c := f.Certificate
	fp := sha256.Sum256(c.Raw)
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	serial := ""
	if c.SerialNumber != nil {
		serial = strings.ToLower(c.SerialNumber.Text(16))
	}
	return CertInfo{
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		Serial:     serial,
		SHA256:     hex.EncodeToString(fp[:]),
		SPKISHA256: hex.EncodeToString(spki[:]),
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		Label:      f.Label,
		Kind:       f.Kind,
		Offset:     f.Offset,
	}
}

// spkiInfo summarises a bare public-key match with the names of the listed
// certificate that carries the key, taken from its parsed certificate so
// that the RDN order agrees with certificates found in files.
func spkiInfo(e *blocklist.Entry, f certs.Found) CertInfo {
	info := CertInfo{Subject: e.Subject, Issuer: e.Issuer, Serial: e.Serial, SPKISHA256: e.SPKISHA256, Label: f.Label, Kind: f.Kind, Offset: f.Offset}
	if c := e.Certificate; c != nil {
		info.Subject = c.Subject.String()
		info.Issuer = c.Issuer.String()
		if c.SerialNumber != nil {
			info.Serial = strings.ToLower(c.SerialNumber.Text(16))
		}
	}
	return info
}

var (
	distInfoRE  = regexp.MustCompile(`(?i)(?:^|/)(certifi|pip)-([0-9][^/]*?)(?:\.dist-info|-py[0-9.]+\.egg-info|\.egg-info)(?:/|$)`)
	javaVerRE   = regexp.MustCompile(`(?m)^JAVA_VERSION="?([^"\n]+)"?`)
	javaImplRE  = regexp.MustCompile(`(?m)^IMPLEMENTOR="?([^"\n]+)"?`)
	javaTypeRE  = regexp.MustCompile(`(?m)^IMAGE_TYPE="?([^"\n]+)"?`)
	nodeMajorRE = regexp.MustCompile(`(?m)^#define NODE_MAJOR_VERSION (\d+)`)
	nodeMinorRE = regexp.MustCompile(`(?m)^#define NODE_MINOR_VERSION (\d+)`)
	nodePatchRE = regexp.MustCompile(`(?m)^#define NODE_PATCH_VERSION (\d+)`)
	vendorRE    = regexp.MustCompile(`(?m)^\s*certifi==([0-9][^\s#]*)`)
	goVersionRE = regexp.MustCompile(`^go([0-9][0-9.]*[0-9])`)
)

// noteVersionDir records Python package versions from dist-info directory
// names on the path (directories or files below them).
func (w *walker) noteVersionDir(name string) {
	m := distInfoRE.FindStringSubmatchIndex(name)
	if m == nil {
		return
	}
	dir := strings.TrimSuffix(name[:m[1]], "/")
	pkg := strings.ToLower(name[m[2]:m[3]])
	w.addVersion("pip|"+dir, pythonPackage(pkg, name[m[4]:m[5]], dir))
}

// noteVersionFile records versions from file contents: JDK release files and
// the Node.js version header.
func (w *walker) noteVersionFile(name string, head []byte) {
	switch {
	case path.Base(name) == "release" && bytes.Contains(head, []byte("JAVA_VERSION=")):
		m := javaVerRE.FindSubmatch(head)
		if m == nil {
			return
		}
		impl := "OpenJDK"
		if im := javaImplRE.FindSubmatch(head); im != nil {
			impl = strings.TrimSpace(string(im[1]))
		}
		manager := "jdk"
		if it := javaTypeRE.FindSubmatch(head); it != nil && strings.EqualFold(strings.TrimSpace(string(it[1])), "JRE") {
			manager = "jre"
		}
		dir := path.Dir(name)
		w.addVersion("java|"+dir, javaStatus(impl, strings.TrimSpace(string(m[1])), manager, dir))
	case path.Base(name) == "node_version.h" && bytes.Contains(head, []byte("NODE_MAJOR_VERSION")):
		ma, mi, pa := nodeMajorRE.FindSubmatch(head), nodeMinorRE.FindSubmatch(head), nodePatchRE.FindSubmatch(head)
		if ma == nil || mi == nil || pa == nil {
			return
		}
		version := fmt.Sprintf("%s.%s.%s", ma[1], mi[1], pa[1])
		w.addVersion("node|"+version, nodeStatus(version, name))
	}
}

// noteGoVersionFile records the toolchain version from a Go VERSION file
// ("go1.25.14", possibly followed by a "time" line).
func (w *walker) noteGoVersionFile(name string, data []byte) {
	m := goVersionRE.FindSubmatch(bytes.TrimSpace(data))
	if m == nil {
		return
	}
	version := string(m[1])
	w.addVersion("go|"+version, goStatus(version, path.Dir(name)))
}

// noteVendoredCertifi records the certifi version vendored by pip.
func (w *walker) noteVendoredCertifi(name string, data []byte) {
	m := vendorRE.FindSubmatch(data)
	if m == nil {
		return
	}
	p := pythonPackage("certifi", string(m[1]), path.Dir(name))
	p.Name = "certifi (vendored in pip)"
	w.addVersion("pip-vendored|"+p.Path, p)
}

// noteProbe records the runtime versions a binary probe found.
func (w *walker) noteProbe(name string, p *versionProbe) {
	for manager, version := range p.versions {
		w.addVersion(manager+"|"+version, runtimeStatus(manager, version, name))
	}
}

// addVersion appends a version row unless one with the same key (install
// location for packages, version for runtimes) was recorded before.
func (w *walker) addVersion(key string, ps PackageStatus) {
	if w.versionSeen[key] {
		return
	}
	w.versionSeen[key] = true
	w.versions = append(w.versions, ps)
}
