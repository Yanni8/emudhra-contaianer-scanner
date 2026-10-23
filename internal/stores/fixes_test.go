package stores

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCACertificatesFix(t *testing.T) {
	tests := []struct {
		name      string
		os        OSInfo
		ok        bool
		component string // substring, "" to skip
		version   string // exact FixedVersion
		reference string // substring
		note      string // substring, "" to skip
	}{
		{"debian13", OSInfo{ID: "debian", VersionID: "13"}, true, "Debian 13", "20250419+deb13u1", "msg00487", ""},
		{"debian12", OSInfo{ID: "debian", VersionID: "12"}, true, "Debian 12", "20250419~deb12u2", "DLA-4845-1", ""},
		{"debian-unstable", OSInfo{ID: "debian", PrettyName: "Debian GNU/Linux forky/sid"}, true, "unstable", "20260816+nmu1", "debian.org", ""},
		{"debian11", OSInfo{ID: "debian", VersionID: "11"}, false, "", "", "", ""},
		{"debian-dotted", OSInfo{ID: "debian", VersionID: "13.1"}, true, "Debian 13", "20250419+deb13u1", "", ""},
		{"debian-upper", OSInfo{ID: "Debian", VersionID: "13"}, true, "Debian 13", "20250419+deb13u1", "", ""},
		{"ubuntu22.04", OSInfo{ID: "ubuntu", VersionID: "22.04"}, true, "Ubuntu 22.04", "20260816ubuntu0.22.04.1", "USN-8944-1", ""},
		{"ubuntu24.04", OSInfo{ID: "ubuntu", IDLike: "debian", VersionID: "24.04"}, true, "Ubuntu 24.04", "20260816ubuntu0.24.04.1", "USN-8944-1", ""},
		{"ubuntu26.04", OSInfo{ID: "ubuntu", VersionID: "26.04"}, true, "Ubuntu 26.04", "20260816ubuntu0.26.04.1", "USN-8944-1", ""},
		{"ubuntu26.10", OSInfo{ID: "ubuntu", VersionID: "26.10"}, true, "Ubuntu 26.10", "20260816ubuntu0.26.10.1", "USN-8944-1", ""},
		{"ubuntu20.04-esm", OSInfo{ID: "ubuntu", VersionID: "20.04"}, true, "Ubuntu 20.04", "20240203~20.04.1ubuntu0.1~esm2", "USN-8944-2", "Ubuntu Pro"},
		{"ubuntu18.04", OSInfo{ID: "ubuntu", VersionID: "18.04"}, false, "", "", "", ""},
		{"ubuntu-no-version", OSInfo{ID: "ubuntu"}, false, "", "", "", ""},
		{"alpine", OSInfo{ID: "alpine", VersionID: "3.20.3"}, true, "Alpine", "20261020-r0", "alpinelinux", ""},
		{"alpine-edge", OSInfo{ID: "alpine"}, true, "Alpine", "20261020-r0", "", ""},
		{"fedora", OSInfo{ID: "fedora", VersionID: "41"}, true, "Fedora", "2026.2.92_v9.0.319-2", "fedoraproject", "-1 build still ships emSign Root CS CA - G3"},
		{"arch", OSInfo{ID: "arch"}, true, "Arch", "3.131.1-1", "archlinux.org/packages/core/x86_64/", ""},
		{"rhel", OSInfo{ID: "rhel", IDLike: "fedora", VersionID: "9.4"}, false, "Red Hat", "", "RHSB-2026-012", "pending"},
		{"centos", OSInfo{ID: "centos", IDLike: "rhel fedora", VersionID: "9"}, false, "Red Hat", "", "RHSB-2026-012", "pending"},
		{"rocky", OSInfo{ID: "rocky", IDLike: "rhel centos fedora", VersionID: "9.3"}, false, "Red Hat", "", "RHSB-2026-012", ""},
		{"alma", OSInfo{ID: "almalinux", IDLike: "rhel centos fedora"}, false, "Red Hat", "", "RHSB-2026-012", ""},
		{"oracle", OSInfo{ID: "ol", IDLike: "fedora"}, false, "Red Hat", "", "RHSB-2026-012", ""},
		{"amazon-linux", OSInfo{ID: "amzn", IDLike: "fedora", VersionID: "2023"}, false, "Amazon Linux", "", "alas.aws.amazon.com", "no fixed version known"},
		{"opensuse", OSInfo{ID: "opensuse-leap", IDLike: "suse opensuse", VersionID: "15.6"}, false, "SUSE", "", CommunityTrackerURL, "no fixed version known"},
		{"sles", OSInfo{ID: "sles", VersionID: "15.6"}, false, "SUSE", "", "", "no fixed version known"},
		{"wolfi", OSInfo{ID: "wolfi", VersionID: "20230201"}, false, "Wolfi", "", "wolfi-dev", "no fixed version known as of 2026-10-23"},
		{"chainguard", OSInfo{ID: "chainguard"}, false, "Wolfi", "", "wolfi-dev", "no fixed version known"},
		{"unknown", OSInfo{}, false, "", "", "", ""},
		// ID_LIKE fallbacks.
		{"raspbian", OSInfo{ID: "raspbian", IDLike: "debian", VersionID: "12"}, true, "Debian 12", "20250419~deb12u2", "", ""},
		{"kali", OSInfo{ID: "kali", IDLike: "debian", VersionID: "2026.3"}, false, "", "", "", ""},
		{"debian-derivative-no-version", OSInfo{ID: "devuan", IDLike: "debian"}, false, "", "", "", ""},
		{"neon", OSInfo{ID: "neon", IDLike: "ubuntu debian", VersionID: "24.04"}, true, "Ubuntu 24.04", "20260816ubuntu0.24.04.1", "", ""},
		{"mint", OSInfo{ID: "linuxmint", IDLike: "ubuntu debian", VersionID: "22"}, false, "", "", "", ""},
		{"manjaro", OSInfo{ID: "manjaro", IDLike: "arch"}, true, "Arch", "3.131.1-1", "", ""},
		{"rhel-like-unknown", OSInfo{ID: "eurolinux", IDLike: "RHEL CentOS Fedora"}, false, "Red Hat", "", "RHSB-2026-012", ""},
		{"postmarketos", OSInfo{ID: "postmarketos", IDLike: "alpine"}, true, "Alpine", "20261020-r0", "", ""},
		{"suse-like", OSInfo{ID: "bci", IDLike: "suse"}, false, "SUSE", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix, ok := CACertificatesFix(tt.os)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (fix %+v)", ok, tt.ok, fix)
			}
			if tt.component != "" && !strings.Contains(fix.Component, tt.component) {
				t.Errorf("component %q does not contain %q", fix.Component, tt.component)
			}
			if fix.FixedVersion != tt.version {
				t.Errorf("version = %q, want %q", fix.FixedVersion, tt.version)
			}
			if tt.reference != "" && !strings.Contains(fix.Reference, tt.reference) {
				t.Errorf("reference %q does not contain %q", fix.Reference, tt.reference)
			}
			if tt.note != "" && !strings.Contains(fix.Note, tt.note) {
				t.Errorf("note %q does not contain %q", fix.Note, tt.note)
			}
			if ok && (fix.Component == "" || fix.Reference == "") {
				t.Errorf("incomplete fix %+v", fix)
			}
			if !ok && fix.Component != "" && fix.Note == "" {
				t.Errorf("a fix without a version needs a note: %+v", fix)
			}
		})
	}
}

func TestCACertificatesFixVersionsOrder(t *testing.T) {
	// The fixed versions sort above the versions shipped before the incident.
	tests := []struct {
		os      OSInfo
		shipped string
	}{
		{OSInfo{ID: "debian", VersionID: "13"}, "20250419"},
		{OSInfo{ID: "debian", VersionID: "12"}, "20230311"},
		{OSInfo{ID: "debian", VersionID: "12"}, "20250419~deb12u1"},
		{OSInfo{ID: "debian"}, "20250419+deb13u1"},
		{OSInfo{ID: "ubuntu", VersionID: "24.04"}, "20240203"},
		{OSInfo{ID: "ubuntu", VersionID: "22.04"}, "20230311ubuntu0.22.04.1"},
		{OSInfo{ID: "ubuntu", VersionID: "26.04"}, "20260601~26.04.1"},
		{OSInfo{ID: "ubuntu", VersionID: "20.04"}, "20240203~20.04.1"},
		{OSInfo{ID: "ubuntu", VersionID: "20.04"}, "20240203~20.04.1ubuntu0.1~esm1"},
		{OSInfo{ID: "alpine"}, "20240705-r0"},
		{OSInfo{ID: "alpine"}, "20260413-r0"},
		{OSInfo{ID: "fedora"}, "2026.2.92_v9.0.319-1"},
		{OSInfo{ID: "fedora"}, "2025.2.80_v8.0.303-1"},
		{OSInfo{ID: "arch"}, "3.130-1"},
	}
	for _, tt := range tests {
		fix, ok := CACertificatesFix(tt.os)
		if !ok {
			t.Fatalf("%+v: no fix", tt.os)
		}
		if CompareDebVersion(tt.shipped, fix.FixedVersion) >= 0 {
			t.Errorf("%+v: shipped %q should sort below fixed %q", tt.os, tt.shipped, fix.FixedVersion)
		}
	}
}

func TestOSFamily(t *testing.T) {
	tests := []struct {
		os   OSInfo
		want string
	}{
		{OSInfo{}, ""},
		{OSInfo{ID: "debian"}, "debian"},
		{OSInfo{ID: "ubuntu", IDLike: "debian"}, "ubuntu"},
		{OSInfo{ID: "raspbian", IDLike: "debian"}, "debian"},
		{OSInfo{ID: "neon", IDLike: "ubuntu debian"}, "ubuntu"},
		{OSInfo{ID: "alpine"}, "alpine"},
		{OSInfo{ID: "postmarketos", IDLike: "alpine"}, "alpine"},
		{OSInfo{ID: "rhel", IDLike: "fedora"}, "rhel"},
		{OSInfo{ID: "centos", IDLike: "rhel fedora"}, "rhel"},
		{OSInfo{ID: "rocky", IDLike: "rhel centos fedora"}, "rhel"},
		{OSInfo{ID: "almalinux", IDLike: "rhel centos fedora"}, "rhel"},
		{OSInfo{ID: "ol", IDLike: "fedora"}, "rhel"},
		{OSInfo{ID: "eurolinux", IDLike: "rhel centos fedora"}, "rhel"},
		{OSInfo{ID: "nobara", IDLike: "fedora"}, "rhel"},
		{OSInfo{ID: "fedora"}, "fedora"},
		{OSInfo{ID: "amzn", IDLike: "fedora"}, "amzn"},
		{OSInfo{ID: "opensuse-leap", IDLike: "suse opensuse"}, "suse"},
		{OSInfo{ID: "opensuse-tumbleweed", IDLike: "opensuse suse"}, "suse"},
		{OSInfo{ID: "sles"}, "suse"},
		{OSInfo{ID: "sle-micro"}, "suse"},
		{OSInfo{ID: "arch"}, "arch"},
		{OSInfo{ID: "archlinux"}, "arch"},
		{OSInfo{ID: "manjaro", IDLike: "arch"}, "arch"},
		{OSInfo{ID: "wolfi"}, "wolfi"},
		{OSInfo{ID: "chainguard"}, "wolfi"},
		{OSInfo{ID: "DEBIAN"}, "debian"},
		{OSInfo{ID: " alpine "}, "alpine"},
		{OSInfo{ID: "nixos"}, ""},
		{OSInfo{ID: "freebsd"}, ""},
	}
	for _, tt := range tests {
		if got := OSFamily(tt.os); got != tt.want {
			t.Errorf("OSFamily(%+v) = %q, want %q", tt.os, got, tt.want)
		}
	}
}

func TestEcosystemFixes(t *testing.T) {
	fixes := EcosystemFixes()
	if len(fixes) < 24 {
		t.Fatalf("only %d fixes", len(fixes))
	}
	seen := map[string]bool{}
	for _, f := range fixes {
		if f.Component == "" || f.Reference == "" {
			t.Errorf("incomplete fix %+v", f)
		}
		if f.FixedVersion == "" && f.Note == "" {
			t.Errorf("fix without version or note: %+v", f)
		}
		if !strings.HasPrefix(f.Reference, "https://") {
			t.Errorf("%s: reference %q is not an https URL", f.Component, f.Reference)
		}
		if strings.Contains(f.FixedVersion, "pending") || strings.Contains(f.FixedVersion, "see ") {
			t.Errorf("%s: FixedVersion %q is prose, not a version (use Note)", f.Component, f.FixedVersion)
		}
		if seen[f.Component] {
			t.Errorf("duplicate component %q", f.Component)
		}
		seen[f.Component] = true
	}
	want := map[string]struct{ version, note string }{
		"Go":                 {"1.27.3 / 1.26.10", ""},
		"Node.js":            {"22.23.4 / 24.22.1 / 26.12.1", "18, 20, 23 and 25 are end-of-life"},
		"Python certifi":     {"2026.10.18", "2026.10.19 recommended"},
		"pip":                {"26.2.2", ""},
		"uv":                 {"0.13.4", "0.13.5 also blocks the compromised keys"},
		"Java/OpenJDK":       {"27.0.1.0.2 / 25.0.5.0.2 / 21.0.13.0.2 / 17.0.21.0.2 / 11.0.33.0.2", "no fixed 8u release as of 2026-10-23"},
		"webpki-roots":       {"1.0.10", ""},
		"rustls-webpki":      {"0.103.16", ""},
		"Deno":               {"2.9.8", ""},
		"Bun":                {"1.4.4", ""},
		"Electron":           {"44.9.1 / 43.8.1 / 42.11.16", ""},
		"Mozilla::CA":        {"20261020", ""},
		"composer/ca-bundle": {"1.6.0 / 1.4.16", ""},
		"NSS":                {"3.131.1", ""},
		"Firefox":            {"158.0.1 / ESR 153.5.1 / ESR 115.43.1", ""},
		"Homebrew":           {"2026-09-25_1", ""},
		"Arch":               {"3.131.1-1", ""},
		"Fedora":             {"2026.2.92_v9.0.319-2", "-1 build"},
		"Alpine":             {"20261020-r0", ""},
		"Debian":             {"20250419+deb13u1", ""},
		"Ubuntu":             {"20260816ubuntu0.22.04.1", "Ubuntu Pro"},
		"Red Hat":            {"", "RHSB-2026-012"},
		"Amazon Linux":       {"", "no fixed version known"},
		"SUSE":               {"", "no fixed version known"},
		"Wolfi":              {"", "no fixed version known as of 2026-10-23"},
		"Erlang/Elixir":      {"", "pending"},
		"Community":          {"", "see reference"},
	}
	for sub, w := range want {
		found := false
		for _, f := range fixes {
			if strings.Contains(f.Component, sub) && strings.Contains(f.FixedVersion, w.version) && strings.Contains(f.Note, w.note) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no fix with component containing %q, version containing %q and note containing %q", sub, w.version, w.note)
		}
	}
	if f, ok := fixByComponent(fixJava); !ok || strings.Contains(f.FixedVersion, "8u") || !strings.Contains(f.Note, "8u512") {
		t.Errorf("Java fix must not list an 8u version: %+v", f)
	}
	var tracker, redhat, goFix, usn bool
	for _, f := range fixes {
		tracker = tracker || f.Reference == CommunityTrackerURL
		redhat = redhat || strings.Contains(f.Reference, "RHSB-2026-012")
		goFix = goFix || (strings.Contains(f.Component, "CVE-2026-111943") && strings.Contains(f.Reference, "golang/go/issues/82345"))
		usn = usn || f.Reference == "https://ubuntu.com/security/notices/USN-8944-1"
		if strings.Contains(f.Reference, "USN-8947-1") || strings.Contains(f.Reference, "/core/any/") {
			t.Errorf("%s: stale reference %q", f.Component, f.Reference)
		}
	}
	if !tracker || !redhat || !goFix || !usn {
		t.Errorf("tracker=%v redhat=%v go=%v usn=%v", tracker, redhat, goFix, usn)
	}

	// Callers get their own copy.
	fixes[0].Component = "mutated"
	if EcosystemFixes()[0].Component == "mutated" {
		t.Error("EcosystemFixes shares its backing array with the caller")
	}
}

func TestNodeFix(t *testing.T) {
	tests := []struct {
		major int
		fixed string
		eol   bool
	}{
		{22, "22.23.4", false},
		{24, "24.22.1", false},
		{26, "26.12.1", false},
		{18, "", true},
		{20, "", true},
		{23, "", true},
		{25, "", true},
		{27, "", true},
		{0, "", true},
	}
	for _, tt := range tests {
		lf := NodeFix(tt.major)
		if lf.Component != "Node.js" || lf.FixedVersion != tt.fixed || lf.EOL != tt.eol {
			t.Errorf("NodeFix(%d) = %+v, want fixed %q eol %v", tt.major, lf, tt.fixed, tt.eol)
		}
		if lf.Reference == "" || !strings.HasPrefix(lf.Reference, "https://nodejs.org/") {
			t.Errorf("NodeFix(%d): reference %q", tt.major, lf.Reference)
		}
		if tt.fixed != "" {
			if lf.Reference != "https://nodejs.org/en/blog/release/v"+tt.fixed || lf.Note != "" {
				t.Errorf("NodeFix(%d) = %+v: want the per-line release post and no note", tt.major, lf)
			}
			continue
		}
		for _, v := range []string{"22.23.4", "24.22.1", "26.12.1"} {
			if !strings.Contains(lf.Note, v) {
				t.Errorf("NodeFix(%d) note %q does not name %s", tt.major, lf.Note, v)
			}
		}
		if eol := strings.Contains(lf.Note, "end-of-life"); eol != (tt.major < 27) {
			t.Errorf("NodeFix(%d) note %q: end-of-life wording = %v", tt.major, lf.Note, eol)
		}
	}
	if lf := NodeFix(20); lf.Line != "20" {
		t.Errorf("Line = %q, want 20", lf.Line)
	}
}

func TestJavaFix(t *testing.T) {
	tests := []struct {
		major int
		ok    bool
		fixed string
		note  string
	}{
		{27, true, "27.0.1.0.2", ""},
		{25, true, "25.0.5.0.2", ""},
		{21, true, "21.0.13.0.2", ""},
		{17, true, "17.0.21.0.2", ""},
		{11, true, "11.0.33.0.2", "expected, not yet tagged as of 2026-10-23"},
		{8, true, "", "no fixed 8u release as of 2026-10-23: 8u512 and earlier are affected; apply the blocked.certs mitigation from the OpenJDK advisory of 2026-10-21"},
		{9, false, "", ""},
		{22, false, "", ""},
		{7, false, "", ""},
		{0, false, "", ""},
	}
	for _, tt := range tests {
		lf, ok := JavaFix(tt.major)
		if ok != tt.ok {
			t.Errorf("JavaFix(%d) ok = %v, want %v", tt.major, ok, tt.ok)
			continue
		}
		if !ok {
			if lf != (LineFix{}) {
				t.Errorf("JavaFix(%d) = %+v, want zero", tt.major, lf)
			}
			continue
		}
		if lf.FixedVersion != tt.fixed || lf.Note != tt.note || lf.EOL {
			t.Errorf("JavaFix(%d) = %+v, want fixed %q note %q", tt.major, lf, tt.fixed, tt.note)
		}
		if lf.Reference != "https://openjdk.org/groups/vulnerability/advisories/2026-10-21" || lf.Component != fixJava {
			t.Errorf("JavaFix(%d): reference %q component %q", tt.major, lf.Reference, lf.Component)
		}
	}
}

func TestGoFix(t *testing.T) {
	tests := []struct {
		major, minor int
		fixed        string
		eol          bool
		note         string
	}{
		{1, 27, "1.27.3", false, ""},
		{1, 26, "1.26.10", false, ""},
		{1, 25, "", true, "no fixed release in this line; build with 1.26.10 or 1.27.3"},
		{1, 22, "", true, "no fixed release in this line; build with 1.26.10 or 1.27.3"},
		{1, 28, "", false, "newer than the fix data"},
		{2, 0, "", false, "newer than the fix data"},
	}
	for _, tt := range tests {
		lf := GoFix(tt.major, tt.minor)
		if lf.FixedVersion != tt.fixed || lf.EOL != tt.eol || !strings.Contains(lf.Note, tt.note) || lf.Reference != "https://github.com/golang/go/issues/82345" {
			t.Errorf("GoFix(%d, %d) = %+v", tt.major, tt.minor, lf)
		}
		if tt.fixed != "" && lf.Note != "" {
			t.Errorf("GoFix(%d, %d): unexpected note %q", tt.major, tt.minor, lf.Note)
		}
	}
	if lf := GoFix(1, 25); lf.Line != "1.25" {
		t.Errorf("Line = %q, want 1.25", lf.Line)
	}
}

func TestSingleLineFixes(t *testing.T) {
	tests := []struct {
		name      string
		fix       LineFix
		component string
		fixed     string
		note      string
	}{
		{"certifi", CertifiFix(), "Python certifi", "2026.10.18", "2026.10.19 recommended: it restores the unaffected emSign G1/C1/C3 roots"},
		{"pip", PipFix(), "pip (vendored certifi)", "26.2.2", ""},
		{"deno", DenoFix(), "Deno", "2.9.8", ""},
		{"bun", BunFix(), "Bun", "1.4.4", ""},
		{"uv", UVFix(), "uv", "0.13.4", "0.13.5 also blocks the compromised keys"},
	}
	for _, tt := range tests {
		f := tt.fix
		if f.Component != tt.component || f.FixedVersion != tt.fixed || !strings.Contains(f.Note, tt.note) || f.EOL || f.Line != "" {
			t.Errorf("%s: %+v", tt.name, f)
		}
		if tt.note == "" && f.Note != "" {
			t.Errorf("%s: unexpected note %q", tt.name, f.Note)
		}
		if !strings.HasPrefix(f.Reference, "https://") {
			t.Errorf("%s: reference %q", tt.name, f.Reference)
		}
	}
}

// The fix table, the line functions, the catalogue texts and the runtime
// remediations all come from the same version data.
func TestFixDataIsSingleSourced(t *testing.T) {
	byComponent := func(c string) Fix {
		f, ok := fixByComponent(c)
		if !ok {
			t.Fatalf("no fix for %q", c)
		}
		return f
	}
	var nodeVersions []string
	for _, major := range []int{22, 24, 26} {
		nodeVersions = append(nodeVersions, NodeFix(major).FixedVersion)
	}
	if got := byComponent(fixNode).FixedVersion; got != strings.Join(nodeVersions, " / ") {
		t.Errorf("Node.js table %q != lines %v", got, nodeVersions)
	}
	var javaVersions []string
	for _, major := range []int{27, 25, 21, 17, 11} {
		lf, _ := JavaFix(major)
		javaVersions = append(javaVersions, lf.FixedVersion)
	}
	if got := byComponent(fixJava).FixedVersion; got != strings.Join(javaVersions, " / ") {
		t.Errorf("Java table %q != lines %v", got, javaVersions)
	}
	if got := byComponent(fixGo).FixedVersion; got != GoFix(1, 27).FixedVersion+" / "+GoFix(1, 26).FixedVersion {
		t.Errorf("Go table %q != lines", got)
	}
	for _, tt := range []struct {
		component string
		line      LineFix
	}{
		{fixCertifi, CertifiFix()}, {fixPip, PipFix()}, {fixDeno, DenoFix()}, {fixBun, BunFix()}, {fixUV, UVFix()},
	} {
		f := byComponent(tt.component)
		if f.FixedVersion != tt.line.FixedVersion || f.Note != tt.line.Note || f.Reference != tt.line.Reference {
			t.Errorf("%s: table %+v != line %+v", tt.component, f, tt.line)
		}
	}

	// Catalogue remediation texts name the same versions.
	for _, tt := range []struct {
		path     string
		versions []string
	}{
		{"/usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", []string{PipFix().FixedVersion}},
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", []string{CertifiFix().FixedVersion, certifiRecommended}},
		{"/usr/share/perl5/Mozilla/CA/cacert.pem", []string{byComponent(fixMozillaCA).FixedVersion}},
		{"/app/vendor/composer/ca-bundle/res/cacert.pem", []string{composerCAFixed, composerCALegacyFixed}},
		{"/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem", []string{byComponent(fixHomebrew).FixedVersion}},
		{"/etc/pki/nssdb/cert9.db", []string{byComponent(fixNSS).FixedVersion}},
		{"/usr/src/certdata.txt", []string{byComponent(fixNSS).FixedVersion}},
		{"/root/go/pkg/mod/x/y.pem", []string{GoFix(1, 27).FixedVersion, GoFix(1, 26).FixedVersion}},
	} {
		s := Classify(tt.path, nil)
		for _, v := range tt.versions {
			if !strings.Contains(s.Remediation, v) {
				t.Errorf("%s: remediation %q lacks %q", tt.path, s.Remediation, v)
			}
		}
	}
	bin := Classify("/usr/bin/python3", elfHeader)
	for _, v := range []string{GoFix(1, 27).FixedVersion, webpkiRootsFixed, rustlsWebpkiFixed} {
		if !strings.Contains(bin.Remediation, v) {
			t.Errorf("embedded-binary remediation %q lacks %q", bin.Remediation, v)
		}
	}
	for _, tt := range []struct {
		path    string
		version string
	}{
		{"/usr/local/bin/node", byComponent(fixNode).FixedVersion},
		{"/usr/bin/deno", DenoFix().FixedVersion},
		{"/usr/local/bin/bun", BunFix().FixedVersion},
		{"/usr/local/bin/uv", UVFix().FixedVersion},
	} {
		if s := Classify(tt.path, elfHeader); !strings.Contains(s.Remediation, tt.version) {
			t.Errorf("%s: remediation %q lacks %q", tt.path, s.Remediation, tt.version)
		}
	}
}

// Every version literal lives in versions.go: the other source files of the
// package reference the constants instead of repeating the strings.
func TestVersionsStatedOnce(t *testing.T) {
	literals := []string{
		goFixed127, goFixed126, nodeFixed22, nodeFixed24, nodeFixed26, certifiFixed, certifiRecommended,
		pipFixed, uvFixed, uvKeyBlocking, java27Fixed, java25Fixed, java21Fixed, java17Fixed, java11Fixed,
		webpkiRootsFixed, rustlsWebpkiFixed, denoFixed, bunFixed, mozillaCAFixed, composerCAFixed,
		composerCALegacyFixed, homebrewFixed, archFixed, fedoraFixed, alpineFixed, debian13Fixed,
		debian12Fixed, debianSidFixed, ubuntuESM2004Fixed, nssFixed, electronFixed, firefoxFixed,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "versions.go" || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		// Documentation may quote versions; code must not.
		var code []string
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				code = append(code, line)
			}
		}
		src := strings.Join(code, "\n")
		for _, lit := range literals {
			if strings.Contains(src, `"`+lit+`"`) || strings.Contains(src, " "+lit+" ") || strings.Contains(src, lit+" /") {
				t.Errorf("%s repeats the version literal %q; reference the constant in versions.go instead", name, lit)
			}
		}
	}
}

func TestFixForStore(t *testing.T) {
	tests := []struct {
		path      string
		header    []byte
		component string // substring, "" when no fix is expected
	}{
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", nil, "Python certifi"},
		{"/usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", nil, "pip"},
		{"/usr/lib/google-cloud-sdk/platform/bundledpythonunix/lib/python3.14/site-packages/pip/_vendor/certifi/cacert.pem", nil, "pip"},
		{"/usr/share/perl5/Mozilla/CA/cacert.pem", nil, "Mozilla::CA"},
		{"/app/vendor/composer/ca-bundle/res/cacert.pem", nil, "composer/ca-bundle"},
		{"/app/deps/certifi/priv/cacerts.pem", nil, "Erlang/Elixir certifi"},
		{"/app/lib/certifi-2.14.0/priv/cacerts.pem", nil, "Erlang/Elixir certifi"},
		{"/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem", nil, "Homebrew"},
		{"/opt/homebrew/Cellar/ca-certificates/2026-10-21/share/ca-certificates/cacert.pem", nil, "Homebrew"},
		{"/usr/lib/jvm/java-17/lib/security/cacerts", nil, "Java/OpenJDK"},
		{"/opt/java/openjdk/lib/security/jssecacerts", nil, ""},
		{"/etc/pki/nssdb/cert9.db", nil, "NSS"},
		{"/usr/src/certdata.txt", nil, "NSS"},
		{"/usr/local/bin/node", elfHeader, "Node.js"},
		{"/usr/lib/libnode.so.115", nil, "Node.js"},
		{"/usr/bin/deno", elfHeader, "Deno"},
		{"/usr/local/bin/bun", elfHeader, "Bun"},
		{"/opt/app/electron", elfHeader, "Electron"},
		{"/usr/lib/nss/libnssckbi.so", elfHeader, "NSS"},
		{"/usr/local/bin/uv", elfHeader, "uv"},
		{"/opt/google/chrome/chrome", elfHeader, ""},
		{"/usr/lib/dart/bin/dart", elfHeader, ""},
		{"/etc/ssl/certs/ca-certificates.crt", nil, ""},
		// Generated Java cacerts follow the system store, not the JDK.
		{"/etc/pki/ca-trust/extracted/java/cacerts", nil, ""},
		{"/etc/pki/java/cacerts", nil, ""},
		{"/etc/ca-certificates/extracted/java-cacerts", nil, ""},
		{"/var/lib/ca-certificates/java-cacerts", nil, ""},
		{"/etc/ssl/certs/java/cacerts", nil, ""},
		{"/usr/local/lib/python3.12/site-packages/botocore/cacert.pem", nil, ""},
		{"/app/lib/castore-1.0.9/priv/cacerts.pem", nil, ""},
		{"/opt/app/random.pem", nil, ""},
		{"/usr/bin/python3", elfHeader, ""},
	}
	for _, tt := range tests {
		s := Classify(tt.path, tt.header)
		fix, ok := FixForStore(s)
		if ok != (tt.component != "") {
			t.Errorf("FixForStore(%q) ok = %v, want %v (fix %+v)", tt.path, ok, tt.component != "", fix)
			continue
		}
		if ok && !strings.Contains(fix.Component, tt.component) {
			t.Errorf("FixForStore(%q) = %q, want component containing %q", tt.path, fix.Component, tt.component)
		}
	}
	if _, ok := FixForStore(Store{}); ok {
		t.Error("zero Store must have no fix")
	}
	if _, ok := FixForStore(Store{Class: ClassEmbeddedRuntime, Name: "Something else"}); ok {
		t.Error("unknown runtime store must have no fix")
	}
	// The name the scan engine has relied on keeps its Java fix.
	if fix, ok := FixForStore(Store{Class: ClassJavaKeystore, Name: "Java cacerts truststore"}); !ok || fix.Component != fixJava {
		t.Errorf("FixForStore(Java cacerts truststore) = %+v, %v", fix, ok)
	}
}

// storeFixes keys are catalogue store names and its values are fix table
// components, so a renamed store cannot silently lose its fix.
func TestStoreFixesAreConsistent(t *testing.T) {
	names := map[string]bool{}
	for _, r := range catalogue {
		names[r.store.Name] = true
	}
	for name, component := range storeFixes {
		if !names[name] {
			t.Errorf("storeFixes names %q, which no catalogue rule produces", name)
		}
		if _, ok := fixByComponent(component); !ok {
			t.Errorf("storeFixes maps %q to unknown component %q", name, component)
		}
	}
	for _, rt := range runtimes {
		if rt.Fix != "" {
			if _, ok := fixByComponent(rt.Fix); !ok {
				t.Errorf("runtime %s maps to unknown component %q", rt.Runtime, rt.Fix)
			}
		}
	}
}
