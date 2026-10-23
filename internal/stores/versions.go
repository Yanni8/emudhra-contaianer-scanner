package stores

import (
	"strconv"
	"strings"
)

// This file is the single source of truth for every fixed version the
// package reports. Each version string is written exactly once here; the
// fix table (fixes.go), the catalogue remediation texts (classify.go), the
// system remediation (remediation.go) and the per-release-line functions
// (NodeFix, JavaFix, GoFix, ...) are all derived from these values.

const (
	// dataDate is the day the data below was last verified against the
	// primary sources (advisories, release posts, package trackers).
	dataDate = "2026-10-23"
	// incidentFixDate is the day the first fixed trust-store packages were
	// published; base images built before it still trust the compromised CAs.
	incidentFixDate = "2026-10-20"

	// Go: crypto/x509 blocks the compromised keys (CVE-2026-111943).
	goFixed127 = "1.27.3"
	goFixed126 = "1.26.10"

	// Node.js security releases per maintained line; every other line
	// (18, 20, 23, 25) is end-of-life without a fix.
	nodeFixed22 = "22.23.4"
	nodeFixed24 = "24.22.1"
	nodeFixed26 = "26.12.1"

	// Python: certifi 2026.10.18 is the first release without the
	// compromised root; 2026.10.19 restores the unaffected emSign roots.
	certifiFixed       = "2026.10.18"
	certifiRecommended = "2026.10.19"
	pipFixed           = "26.2.2" // first pip vendoring a fixed certifi
	uvFixed            = "0.13.4" // replaced the bundled roots (webpki-root-certs 1.0.10)
	uvKeyBlocking      = "0.13.5" // additionally rejects the compromised keys

	// Java/OpenJDK (CVE-2026-91403): the October CPU builds are affected,
	// the .0.2 re-releases carry the fix. 8u has no fixed release yet and
	// the 11 line's re-release was not tagged as of dataDate.
	java27Fixed   = "27.0.1.0.2"
	java25Fixed   = "25.0.5.0.2"
	java21Fixed   = "21.0.13.0.2"
	java17Fixed   = "17.0.21.0.2"
	java11Fixed   = "11.0.33.0.2"
	java8Affected = "8u512"

	// Rust, JavaScript runtimes and browsers.
	webpkiRootsFixed  = "1.0.10"
	rustlsWebpkiFixed = "0.103.16"
	denoFixed         = "2.9.8"
	bunFixed          = "1.4.4"
	electronFixed     = "44.9.1 / 43.8.1 / 42.11.16"
	nssFixed          = "3.131.1"
	firefoxFixed      = "158.0.1 / ESR 153.5.1 / ESR 115.43.1"

	// Language bundles.
	mozillaCAFixed        = "20261020"
	composerCAFixed       = "1.6.0"
	composerCALegacyFixed = "1.4.16"
	homebrewFixed         = "2026-09-25_1"

	// Distribution packages.
	archFixed          = "3.131.1-1"
	fedoraFixed        = "2026.2.92_v9.0.319-2"
	alpineFixed        = "20261020-r0"
	debian13Fixed      = "20250419+deb13u1"
	debian12Fixed      = "20250419~deb12u2"
	debianSidFixed     = "20260816+nmu1"
	ubuntuFixedPrefix  = "20260816ubuntu0." // + "<release>.1"
	ubuntuESM2004Fixed = "20240203~20.04.1ubuntu0.1~esm2"
)

// Notes that qualify a fix, shared by the fix table and the line functions.
const (
	certifiNote      = certifiRecommended + " recommended: it restores the unaffected emSign G1/C1/C3 roots"
	uvNote           = uvKeyBlocking + " also blocks the compromised keys (rustls-webpki " + rustlsWebpkiFixed + ")"
	java11Note       = "expected, not yet tagged as of " + dataDate
	java8Note        = "no fixed 8u release as of " + dataDate + ": " + java8Affected + " and earlier are affected; apply the blocked.certs mitigation from the OpenJDK advisory of 2026-10-21"
	fedoraNote       = "the -1 build still ships emSign Root CS CA - G3"
	ubuntuESMNote    = "requires Ubuntu Pro (ESM)"
	redHatNote       = "pending (not released as of " + dataDate + ", RHSB-2026-012)"
	noFixKnownNote   = "no fixed version known as of " + dataDate
	erlangPending    = "pending as of " + dataDate
	goEOLNote        = "no fixed release in this line; build with " + goFixed126 + " or " + goFixed127
	nodeFixedVersion = nodeFixed22 + " / " + nodeFixed24 + " / " + nodeFixed26
	nodeFixedProse   = nodeFixed22 + ", " + nodeFixed24 + " or " + nodeFixed26
	nodeFixedLines   = nodeFixed22 + ", " + nodeFixed24 + " and " + nodeFixed26
	nodeEOLNote      = "end-of-life with no fixed release: use " + nodeFixedProse
	javaFixedVersion = java27Fixed + " / " + java25Fixed + " / " + java21Fixed + " / " + java17Fixed + " / " + java11Fixed
	javaNote         = "11.0.33.0.2: " + java11Note + "; 8u: " + java8Note
)

// Reference URLs.
const (
	refGo             = "https://github.com/golang/go/issues/82345"
	refNodeReleases   = "https://nodejs.org/en/about/previous-releases"
	refNodeBlog       = "https://nodejs.org/en/blog/release/v"
	refCertifi        = "https://pypi.org/project/certifi/"
	refPip            = "https://pypi.org/project/pip/"
	refUV             = "https://github.com/astral-sh/uv/releases/tag/" + uvFixed
	refOpenJDK        = "https://openjdk.org/groups/vulnerability/advisories/2026-10-21"
	refWebpkiRoots    = "https://crates.io/crates/webpki-roots"
	refRustlsWebpki   = "https://crates.io/crates/rustls-webpki"
	refDeno           = "https://github.com/denoland/deno/releases/tag/v" + denoFixed
	refBun            = "https://bun.sh/blog"
	refElectron       = "https://releases.electronjs.org/"
	refMozillaCA      = "https://metacpan.org/dist/Mozilla-CA"
	refComposerCA     = "https://github.com/composer/ca-bundle/releases"
	refNSS            = "https://firefox-source-docs.mozilla.org/security/nss/releases/index.html"
	refFirefox        = "https://www.mozilla.org/security/advisories/"
	refHomebrew       = "https://formulae.brew.sh/formula/ca-certificates"
	refArch           = "https://archlinux.org/packages/core/x86_64/ca-certificates-mozilla/"
	refFedora         = "https://bodhi.fedoraproject.org/updates/?packages=ca-certificates"
	refAlpine         = "https://pkgs.alpinelinux.org/packages?name=ca-certificates"
	refDebianDSA      = "https://lists.debian.org/debian-security-announce/2026/msg00487.html"
	refDebianDLA      = "https://security-tracker.debian.org/tracker/DLA-4845-1"
	refDebianUnstable = "https://tracker.debian.org/pkg/ca-certificates"
	refUbuntuUSN      = "https://ubuntu.com/security/notices/USN-8944-1"
	refUbuntuESM      = "https://ubuntu.com/security/notices/USN-8944-2"
	refRedHat         = "https://access.redhat.com/security/vulnerabilities/RHSB-2026-012"
	refAmazon         = "https://alas.aws.amazon.com/"
	refWolfi          = "https://github.com/wolfi-dev/os"
	refErlangCertifi  = "https://hex.pm/packages/certifi"
)

// nodeLine is one maintained Node.js release line.
type nodeLine struct {
	major int
	fixed string
}

// nodeLines lists the lines that received a security release, ascending.
var nodeLines = []nodeLine{{22, nodeFixed22}, {24, nodeFixed24}, {26, nodeFixed26}}

// javaLine is one Java release line; fixed is "" when no fixed release
// exists in the line.
type javaLine struct {
	major int
	fixed string
	note  string
}

// javaLines lists the lines the OpenJDK advisory covers, newest first.
var javaLines = []javaLine{
	{27, java27Fixed, ""},
	{25, java25Fixed, ""},
	{21, java21Fixed, ""},
	{17, java17Fixed, ""},
	{11, java11Fixed, java11Note},
	{8, "", java8Note},
}

// goLine is one Go release line.
type goLine struct {
	major, minor int
	fixed        string
}

// goLines lists the lines with a fixed release, newest first.
var goLines = []goLine{{1, 27, goFixed127}, {1, 26, goFixed126}}

// nodeFix implements NodeFix.
func nodeFix(major int) LineFix {
	lf := LineFix{Component: fixNode, Line: strconv.Itoa(major)}
	for _, l := range nodeLines {
		if l.major == major {
			lf.FixedVersion = l.fixed
			lf.Reference = refNodeBlog + l.fixed
			return lf
		}
	}
	lf.EOL = true
	lf.Reference = refNodeReleases
	if major > nodeLines[len(nodeLines)-1].major {
		lf.Note = "no Node.js " + lf.Line + " release with the fix is known as of " + dataDate + ": the fixed lines are " + nodeFixedLines
		return lf
	}
	lf.Note = "Node.js " + lf.Line + " is " + nodeEOLNote
	return lf
}

// javaFix implements JavaFix.
func javaFix(major int) (LineFix, bool) {
	for _, l := range javaLines {
		if l.major == major {
			return LineFix{Component: fixJava, Line: strconv.Itoa(major), FixedVersion: l.fixed, Reference: refOpenJDK, Note: l.note}, true
		}
	}
	return LineFix{}, false
}

// goFix implements GoFix.
func goFix(major, minor int) LineFix {
	lf := LineFix{Component: fixGo, Line: strconv.Itoa(major) + "." + strconv.Itoa(minor), Reference: refGo}
	for _, l := range goLines {
		if l.major == major && l.minor == minor {
			lf.FixedVersion = l.fixed
			return lf
		}
	}
	newest := goLines[0]
	if major > newest.major || (major == newest.major && minor > newest.minor) {
		lf.Note = "newer than the fix data of " + dataDate + ": " + goFixed127 + " and " + goFixed126 + " carry the fix and later lines are expected to"
		return lf
	}
	lf.EOL = true
	lf.Note = goEOLNote
	return lf
}

// certifiFix implements CertifiFix.
func certifiFix() LineFix {
	return LineFix{Component: fixCertifi, FixedVersion: certifiFixed, Reference: refCertifi, Note: certifiNote}
}

// pipFix implements PipFix.
func pipFix() LineFix {
	return LineFix{Component: fixPip, FixedVersion: pipFixed, Reference: refPip}
}

// denoFix implements DenoFix.
func denoFix() LineFix {
	return LineFix{Component: fixDeno, FixedVersion: denoFixed, Reference: refDeno}
}

// bunFix implements BunFix.
func bunFix() LineFix {
	return LineFix{Component: fixBun, FixedVersion: bunFixed, Reference: refBun}
}

// uvFix implements UVFix.
func uvFix() LineFix {
	return LineFix{Component: fixUV, FixedVersion: uvFixed, Reference: refUV, Note: uvNote}
}

// ubuntuFixedVersion builds the LTS/interim ca-certificates version for an
// Ubuntu release ("24.04" -> "20260816ubuntu0.24.04.1").
func ubuntuFixedVersion(release string) string {
	return ubuntuFixedPrefix + strings.TrimSpace(release) + ".1"
}
