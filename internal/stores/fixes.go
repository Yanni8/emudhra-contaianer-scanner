package stores

import "strings"

// CommunityTrackerURL tracks the fix status of every ecosystem affected by the
// eMudhra compromise.
const CommunityTrackerURL = "https://emudhra.we-have-a-problem.com/"

// Component names used by EcosystemFixes, FixForStore, the line functions and
// the runtime table.
const (
	fixGo            = "Go (crypto/x509 blocks the compromised keys, CVE-2026-111943; binaries must be rebuilt)"
	fixNode          = "Node.js"
	fixCertifi       = "Python certifi"
	fixPip           = "pip (vendored certifi)"
	fixUV            = "uv"
	fixJava          = "Java/OpenJDK (cacerts and SPKI blocklist, CVE-2026-91403)"
	fixWebpkiRoots   = "Rust webpki-roots / webpki-root-certs"
	fixRustlsWebpki  = "Rust rustls-webpki"
	fixDeno          = "Deno"
	fixBun           = "Bun"
	fixElectron      = "Electron"
	fixMozillaCA     = "Perl Mozilla::CA (CVE-2026-113812)"
	fixComposerCA    = "PHP composer/ca-bundle"
	fixNSS           = "NSS (libnssckbi built-in roots)"
	fixFirefox       = "Firefox"
	fixHomebrew      = "Homebrew ca-certificates"
	fixArch          = "ca-certificates-mozilla (Arch Linux)"
	fixFedora        = "ca-certificates (Fedora)"
	fixAlpine        = "ca-certificates / ca-certificates-bundle (Alpine)"
	fixDebian        = "ca-certificates (Debian)"
	fixUbuntu        = "ca-certificates (Ubuntu)"
	fixRedHat        = "ca-certificates (Red Hat Enterprise Linux, CentOS Stream, Rocky, Alma, UBI)"
	fixAmazon        = "ca-certificates (Amazon Linux)"
	fixSUSE          = "ca-certificates-mozilla (SUSE)"
	fixWolfi         = "ca-certificates-bundle (Wolfi)"
	fixErlangCertifi = "Erlang/Elixir certifi"
	fixTracker       = "Community fix tracker (all ecosystems)"
)

// ecosystemFixes is the fixed-version table, in display order. Every version
// in it comes from versions.go.
var ecosystemFixes = buildEcosystemFixes()

func buildEcosystemFixes() []Fix {
	return []Fix{
		{Component: fixGo, FixedVersion: goFixed127 + " / " + goFixed126, Reference: refGo},
		{Component: fixNode, FixedVersion: nodeFixedVersion, Reference: refNodeBlog + nodeFixed22, Note: "lines 18, 20, 23 and 25 are " + nodeEOLNote},
		{Component: fixCertifi, FixedVersion: certifiFixed, Reference: refCertifi, Note: certifiNote},
		{Component: fixPip, FixedVersion: pipFixed, Reference: refPip},
		{Component: fixUV, FixedVersion: uvFixed, Reference: refUV, Note: uvNote},
		{Component: fixJava, FixedVersion: javaFixedVersion, Reference: refOpenJDK, Note: javaNote},
		{Component: fixWebpkiRoots, FixedVersion: webpkiRootsFixed, Reference: refWebpkiRoots},
		{Component: fixRustlsWebpki, FixedVersion: rustlsWebpkiFixed, Reference: refRustlsWebpki},
		{Component: fixDeno, FixedVersion: denoFixed, Reference: refDeno},
		{Component: fixBun, FixedVersion: bunFixed, Reference: refBun},
		{Component: fixElectron, FixedVersion: electronFixed, Reference: refElectron},
		{Component: fixMozillaCA, FixedVersion: mozillaCAFixed, Reference: refMozillaCA},
		{Component: fixComposerCA, FixedVersion: composerCAFixed + " / " + composerCALegacyFixed, Reference: refComposerCA},
		{Component: fixNSS, FixedVersion: nssFixed, Reference: refNSS},
		{Component: fixFirefox, FixedVersion: firefoxFixed, Reference: refFirefox},
		{Component: fixHomebrew, FixedVersion: homebrewFixed, Reference: refHomebrew},
		{Component: fixArch, FixedVersion: archFixed, Reference: refArch},
		{Component: fixFedora, FixedVersion: fedoraFixed, Reference: refFedora, Note: fedoraNote},
		{Component: fixAlpine, FixedVersion: alpineFixed, Reference: refAlpine},
		{Component: fixDebian, FixedVersion: debian13Fixed + " (Debian 13) / " + debian12Fixed + " (Debian 12) / " + debianSidFixed + " (unstable)", Reference: refDebianDSA},
		{Component: fixUbuntu, FixedVersion: ubuntuFixedVersion("22.04") + " / " + ubuntuFixedVersion("24.04") + " / " + ubuntuFixedVersion("26.04") + " / " + ubuntuFixedVersion("26.10") + " / " + ubuntuESM2004Fixed + " (20.04 ESM)", Reference: refUbuntuUSN, Note: "20.04 " + ubuntuESMNote + ", USN-8944-2"},
		{Component: fixRedHat, Reference: refRedHat, Note: redHatNote},
		{Component: fixAmazon, Reference: refAmazon, Note: noFixKnownNote},
		{Component: fixSUSE, Reference: CommunityTrackerURL, Note: noFixKnownNote},
		{Component: fixWolfi, Reference: refWolfi, Note: noFixKnownNote},
		{Component: fixErlangCertifi, Reference: refErlangCertifi, Note: erlangPending},
		{Component: fixTracker, Reference: CommunityTrackerURL, Note: "see reference"},
	}
}

// ecosystemFixesCopy implements EcosystemFixes.
func ecosystemFixesCopy() []Fix {
	return append([]Fix(nil), ecosystemFixes...)
}

// fixByComponent looks a fix up by its exact component name.
func fixByComponent(component string) (Fix, bool) {
	if component == "" {
		return Fix{}, false
	}
	for _, f := range ecosystemFixes {
		if f.Component == component {
			return f, true
		}
	}
	return Fix{}, false
}

// storeFixes maps catalogue store names to fix components.
var storeFixes = map[string]string{
	nameCertifi:     fixCertifi,
	namePipCertifi:  fixPip,
	nameMozillaCA:   fixMozillaCA,
	nameComposerCA:  fixComposerCA,
	nameErlangCert:  fixErlangCertifi,
	nameJavaCacerts: fixJava,
	nameHomebrew:    fixHomebrew,
	nameCertdata:    fixNSS,
	nameNSSDB9:      fixNSS,
	nameNSSDB8:      fixNSS,
}

// FixForStore returns the ecosystem fix that applies to a store returned by
// Classify: the library or runtime that ships the store (certifi, pip,
// Mozilla::CA, composer/ca-bundle, Java, Node.js, Deno, Bun, Electron, NSS,
// uv, Homebrew, ...). System stores depend on the distribution; use
// CACertificatesFix with the detected OS for those. Java cacerts files that
// the distribution regenerates from its trust store (SystemGenerated) have no
// Java fix either. ok is false when no fix is known.
func FixForStore(s Store) (fix Fix, ok bool) {
	if component, found := storeFixes[s.Name]; found {
		return fixByComponent(component)
	}
	if s.Class == ClassEmbeddedRuntime {
		for _, rt := range runtimes {
			if rt.Runtime+" (embedded root store)" == s.Name {
				return fixByComponent(rt.Fix)
			}
		}
	}
	return Fix{}, false
}

// family groups distributions by their trust-store tooling.
type family string

const (
	familyUnknown family = ""
	familyDebian  family = "debian"
	familyUbuntu  family = "ubuntu"
	familyAlpine  family = "alpine"
	familyRHEL    family = "rhel"
	familyFedora  family = "fedora"
	familyAmazon  family = "amzn"
	familySUSE    family = "suse"
	familyArch    family = "arch"
	familyWolfi   family = "wolfi"
)

// osFamily implements OSFamily: the ID decides, then ID_LIKE.
func osFamily(o OSInfo) family {
	switch strings.ToLower(strings.TrimSpace(o.ID)) {
	case "debian":
		return familyDebian
	case "ubuntu":
		return familyUbuntu
	case "alpine":
		return familyAlpine
	case "fedora":
		return familyFedora
	case "arch", "archlinux":
		return familyArch
	case "rhel", "centos", "rocky", "almalinux", "ol", "scientific", "ubi":
		return familyRHEL
	case "amzn":
		return familyAmazon
	case "wolfi", "chainguard":
		return familyWolfi
	case "sles", "sle-micro", "sle_hpc", "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "opensuse-microos", "opensuse-slowroll":
		return familySUSE
	}
	like := strings.Fields(strings.ToLower(o.IDLike))
	switch {
	case hasWord(like, "ubuntu"):
		return familyUbuntu
	case hasWord(like, "debian"):
		return familyDebian
	case hasWord(like, "alpine"):
		return familyAlpine
	case hasWord(like, "arch"), hasWord(like, "archlinux"):
		return familyArch
	case hasWord(like, "suse"), hasWord(like, "opensuse"):
		return familySUSE
	case hasWord(like, "wolfi"):
		return familyWolfi
	case hasWord(like, "rhel"), hasWord(like, "centos"), hasWord(like, "fedora"):
		// Unknown Fedora-like distributions get the Red Hat status: their
		// ca-certificates follows RHEL, not Fedora's rawhide builds.
		return familyRHEL
	}
	return familyUnknown
}

func hasWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// caCertificatesFix implements CACertificatesFix.
func caCertificatesFix(o OSInfo) (Fix, bool) {
	ver := strings.TrimSpace(o.VersionID)
	switch osFamily(o) {
	case familyDebian:
		return debianFix(ver, strings.EqualFold(strings.TrimSpace(o.ID), "debian"))
	case familyUbuntu:
		return ubuntuFix(ver)
	case familyAlpine:
		return Fix{Component: fixAlpine, FixedVersion: alpineFixed, Reference: refAlpine}, true
	case familyFedora:
		return Fix{Component: fixFedora, FixedVersion: fedoraFixed, Reference: refFedora, Note: fedoraNote}, true
	case familyArch:
		return Fix{Component: fixArch, FixedVersion: archFixed, Reference: refArch}, true
	case familyRHEL:
		return redHatPending(), false
	case familyAmazon:
		return Fix{Component: fixAmazon, Reference: refAmazon, Note: noFixKnownNote}, false
	case familySUSE:
		return Fix{Component: fixSUSE, Reference: CommunityTrackerURL, Note: noFixKnownNote}, false
	case familyWolfi:
		return Fix{Component: fixWolfi, Reference: refWolfi, Note: noFixKnownNote}, false
	}
	return Fix{}, false
}

// redHatPending describes the not-yet-released Red Hat fix; callers get
// ok=false with it so that the advisory can still be shown.
func redHatPending() Fix {
	return Fix{Component: fixRedHat, Reference: refRedHat, Note: redHatNote}
}

// debianFix maps a Debian VERSION_ID to the fixed ca-certificates version.
// unstable enables the "no VERSION_ID means unstable/testing" rule, which only
// holds for Debian itself, not for derivatives.
func debianFix(ver string, unstable bool) (Fix, bool) {
	major, _, _ := strings.Cut(ver, ".")
	switch major {
	case "13":
		return Fix{Component: "ca-certificates (Debian 13)", FixedVersion: debian13Fixed, Reference: refDebianDSA}, true
	case "12":
		return Fix{Component: "ca-certificates (Debian 12)", FixedVersion: debian12Fixed, Reference: refDebianDLA}, true
	case "":
		if unstable {
			return Fix{Component: "ca-certificates (Debian unstable/testing)", FixedVersion: debianSidFixed, Reference: refDebianUnstable}, true
		}
	}
	return Fix{}, false
}

// ubuntuFix maps an Ubuntu VERSION_ID to the fixed ca-certificates version.
func ubuntuFix(ver string) (Fix, bool) {
	switch ver {
	case "22.04", "24.04", "26.04", "26.10":
		return Fix{Component: "ca-certificates (Ubuntu " + ver + ")", FixedVersion: ubuntuFixedVersion(ver), Reference: refUbuntuUSN}, true
	case "20.04":
		return Fix{Component: "ca-certificates (Ubuntu 20.04 ESM)", FixedVersion: ubuntuESM2004Fixed, Reference: refUbuntuESM, Note: ubuntuESMNote}, true
	}
	return Fix{}, false
}
