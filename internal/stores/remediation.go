package stores

// Sentences shared by several branches of systemRemediation.
const (
	rhelBlocklistAction = "copy the certificate's PEM into /etc/pki/ca-trust/source/blocklist/ and run update-ca-trust"
	suseBlocklistAction = "copy the certificate's PEM into /etc/pki/trust/blocklist/ and run update-ca-certificates"
	archBlocklistAction = "copy the certificate's PEM into /etc/ca-certificates/trust-source/blocklist/ and run update-ca-trust"
	stripAction         = "strip the certificate from the bundle at build time"
)

// systemRemediation implements SystemRemediation.
func systemRemediation(o OSInfo, facts SystemFacts) string {
	fix, fixOK := caCertificatesFix(o)
	fam := osFamily(o)
	if fam == familyWolfi {
		return "No fixed ca-certificates-bundle is known for Wolfi/Chainguard as of " + dataDate + ": rebuild on a newer base image once one ships, or " + stripAction + "."
	}
	if !facts.HasPackageManager {
		return rebuildSentence(fix, fixOK)
	}
	switch fam {
	case familyDebian, familyUbuntu:
		return debianRemediation(fix, fixOK, facts)
	case familyAlpine:
		return alpineRemediation(facts)
	case familyRHEL:
		return "No fixed ca-certificates package has been released for Red Hat Enterprise Linux and its rebuilds yet (RHSB-2026-012): " + rhelBlocklistAction + ", then rebuild the image."
	case familyFedora:
		return "Upgrade ca-certificates to " + fedoraFixed + " or later (dnf upgrade ca-certificates; " + fedoraNote + "); until then " + rhelBlocklistAction + "."
	case familyAmazon:
		return "No fixed ca-certificates package is known for Amazon Linux as of " + dataDate + ": " + rhelBlocklistAction + ", then rebuild the image."
	case familySUSE:
		return "No fixed ca-certificates-mozilla package is known for SUSE as of " + dataDate + ": " + suseBlocklistAction + ", then rebuild the image."
	case familyArch:
		return "Upgrade ca-certificates-mozilla to " + archFixed + " or later (pacman -Syu ca-certificates-mozilla); until then " + archBlocklistAction + "."
	}
	return "Upgrade the distribution's ca-certificates package to a build that removes the certificate (no fix data for this distribution as of " + dataDate + "), or remove the certificate from the system bundle at build time and rebuild the image."
}

// rebuildSentence is the advice for images without a package manager
// (distroless, scratch-based, stripped-down bases).
func rebuildSentence(fix Fix, ok bool) string {
	s := "Rebuild on a base image published after " + incidentFixDate
	if ok {
		s += " that ships ca-certificates " + fix.FixedVersion + " or later"
	} else {
		s += " whose trust store no longer carries the certificate"
	}
	return s + ", or " + stripAction + "."
}

// debianRemediation covers Debian, Ubuntu and their derivatives.
func debianRemediation(fix Fix, ok bool, facts SystemFacts) string {
	clause := deselectClause(facts)
	if !ok {
		if clause != "" {
			return "No fixed ca-certificates is known for this release as of " + dataDate + ": " + clause + ", or move to a supported release."
		}
		return "No fixed ca-certificates is known for this release as of " + dataDate + ": move to a supported release or " + stripAction + "."
	}
	s := "Upgrade ca-certificates to " + fix.FixedVersion + " or later (apt-get update && apt-get install --only-upgrade ca-certificates"
	if fix.Note != "" {
		s += "; " + fix.Note
	}
	return s + ")" + untilThen(clause) + "."
}

// alpineRemediation distinguishes images with the full ca-certificates
// package (configuration and update-ca-certificates) from those with only
// the pre-generated ca-certificates-bundle.
func alpineRemediation(facts SystemFacts) string {
	if !hasPackage(facts.Packages, "ca-certificates") && !facts.HasDebianConf {
		return "Upgrade ca-certificates-bundle to " + alpineFixed + " or later (apk upgrade ca-certificates-bundle) and rebuild the image."
	}
	facts.HasDebianConf = true
	return "Upgrade ca-certificates and ca-certificates-bundle to " + alpineFixed + " or later (apk upgrade ca-certificates ca-certificates-bundle)" + untilThen(deselectClause(facts)) + "."
}

// deselectClause is the interim '!' workaround ("deselect the certificate in
// /etc/ca-certificates.conf ... and run update-ca-certificates"), or "" when
// the image has no configuration file to edit.
func deselectClause(facts SystemFacts) string {
	if !facts.HasDebianConf {
		return ""
	}
	tool := "run update-ca-certificates"
	if !facts.HasUpdateCACertificates {
		tool = "regenerate the bundle (update-ca-certificates is not in the image)"
	}
	return "deselect the certificate in /etc/ca-certificates.conf (prefix its line with '!') and " + tool
}

// untilThen attaches an interim workaround clause to an upgrade sentence.
func untilThen(clause string) string {
	if clause == "" {
		return ""
	}
	return "; until then " + clause
}

// hasPackage reports whether a package of that name is in the list.
func hasPackage(list []Package, name string) bool {
	for _, p := range list {
		if p.Name == name {
			return true
		}
	}
	return false
}
