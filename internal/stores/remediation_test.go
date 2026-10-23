package stores

import (
	"strings"
	"testing"
)

func TestSystemRemediation(t *testing.T) {
	full := SystemFacts{HasDebianConf: true, HasUpdateCACertificates: true, HasPackageManager: true}
	withPkg := func(f SystemFacts, names ...string) SystemFacts {
		for _, n := range names {
			f.Packages = append(f.Packages, Package{Name: n, Version: "1", Manager: "apk"})
		}
		return f
	}
	tests := []struct {
		name  string
		os    OSInfo
		facts SystemFacts
		want  []string // substrings
		not   []string // substrings that must be absent
	}{
		{"debian12", OSInfo{ID: "debian", VersionID: "12"}, full,
			[]string{"Upgrade ca-certificates to 20250419~deb12u2 or later", "apt-get install --only-upgrade ca-certificates", "prefix its line with '!'", "run update-ca-certificates"}, nil},
		{"debian13-no-conf", OSInfo{ID: "debian", VersionID: "13"}, SystemFacts{HasPackageManager: true},
			[]string{"20250419+deb13u1", "apt-get install --only-upgrade ca-certificates"}, []string{"'!'", "update-ca-certificates"}},
		{"debian-conf-without-tool", OSInfo{ID: "debian", VersionID: "12"}, SystemFacts{HasDebianConf: true, HasPackageManager: true},
			[]string{"20250419~deb12u2", "prefix its line with '!'", "update-ca-certificates is not in the image"}, []string{"run update-ca-certificates"}},
		{"debian11-unsupported", OSInfo{ID: "debian", VersionID: "11"}, full,
			[]string{"No fixed ca-certificates is known for this release as of 2026-10-23", "prefix its line with '!'", "supported release"}, []string{"apt-get"}},
		{"debian11-unsupported-no-conf", OSInfo{ID: "debian", VersionID: "11"}, SystemFacts{HasPackageManager: true},
			[]string{"No fixed ca-certificates is known", "strip the certificate from the bundle at build time"}, []string{"'!'"}},
		{"ubuntu24.04", OSInfo{ID: "ubuntu", IDLike: "debian", VersionID: "24.04"}, full,
			[]string{"20260816ubuntu0.24.04.1", "apt-get install --only-upgrade ca-certificates", "'!'"}, []string{"Ubuntu Pro"}},
		{"ubuntu20.04-esm", OSInfo{ID: "ubuntu", VersionID: "20.04"}, full,
			[]string{"20240203~20.04.1ubuntu0.1~esm2", "requires Ubuntu Pro (ESM)", "apt-get install --only-upgrade ca-certificates"}, nil},
		{"alpine-bundle-only", OSInfo{ID: "alpine", VersionID: "3.20.10"}, withPkg(SystemFacts{HasPackageManager: true}, "ca-certificates-bundle"),
			[]string{"Upgrade ca-certificates-bundle to 20261020-r0 or later", "apk upgrade ca-certificates-bundle"}, []string{"'!'", "/etc/ca-certificates.conf", "apk upgrade ca-certificates ca-certificates-bundle"}},
		{"alpine-no-package-list", OSInfo{ID: "alpine"}, SystemFacts{HasPackageManager: true},
			[]string{"apk upgrade ca-certificates-bundle"}, []string{"'!'"}},
		{"alpine-full", OSInfo{ID: "alpine", VersionID: "3.22"}, withPkg(full, "ca-certificates-bundle", "ca-certificates"),
			[]string{"apk upgrade ca-certificates ca-certificates-bundle", "20261020-r0", "prefix its line with '!'", "run update-ca-certificates"}, nil},
		{"alpine-full-by-package", OSInfo{ID: "alpine"}, withPkg(SystemFacts{HasPackageManager: true, HasUpdateCACertificates: true}, "ca-certificates"),
			[]string{"apk upgrade ca-certificates ca-certificates-bundle", "'!'"}, nil},
		{"rhel-ubi", OSInfo{ID: "rhel", IDLike: "fedora", VersionID: "9.6"}, SystemFacts{HasPackageManager: true},
			[]string{"RHSB-2026-012", "/etc/pki/ca-trust/source/blocklist/", "update-ca-trust"}, []string{"dnf upgrade", "apt-get"}},
		{"rocky", OSInfo{ID: "rocky", IDLike: "rhel centos fedora", VersionID: "9.3"}, SystemFacts{HasPackageManager: true},
			[]string{"RHSB-2026-012", "/etc/pki/ca-trust/source/blocklist/"}, nil},
		{"fedora", OSInfo{ID: "fedora", VersionID: "43"}, SystemFacts{HasPackageManager: true},
			[]string{"Upgrade ca-certificates to 2026.2.92_v9.0.319-2 or later", "dnf upgrade ca-certificates", "the -1 build still ships emSign Root CS CA - G3", "/etc/pki/ca-trust/source/blocklist/"}, nil},
		{"amazon-linux", OSInfo{ID: "amzn", IDLike: "fedora", VersionID: "2023"}, SystemFacts{HasPackageManager: true},
			[]string{"No fixed ca-certificates package is known for Amazon Linux as of 2026-10-23", "/etc/pki/ca-trust/source/blocklist/", "update-ca-trust"}, []string{"RHSB"}},
		{"opensuse", OSInfo{ID: "opensuse-leap", IDLike: "suse opensuse", VersionID: "15.6"}, SystemFacts{HasPackageManager: true, HasUpdateCACertificates: true},
			[]string{"No fixed ca-certificates-mozilla package is known for SUSE", "/etc/pki/trust/blocklist/", "update-ca-certificates"}, []string{"'!'"}},
		{"sles-bci", OSInfo{ID: "sles", VersionID: "15.6"}, SystemFacts{HasPackageManager: true},
			[]string{"/etc/pki/trust/blocklist/"}, nil},
		{"arch", OSInfo{ID: "arch"}, SystemFacts{HasPackageManager: true},
			[]string{"Upgrade ca-certificates-mozilla to 3.131.1-1 or later", "pacman -Syu ca-certificates-mozilla", "/etc/ca-certificates/trust-source/blocklist/", "update-ca-trust"}, nil},
		{"wolfi", OSInfo{ID: "wolfi", VersionID: "20230201"}, SystemFacts{HasPackageManager: true},
			[]string{"No fixed ca-certificates-bundle is known for Wolfi/Chainguard as of 2026-10-23", "rebuild on a newer base image"}, []string{"apk upgrade"}},
		{"chainguard-no-apk", OSInfo{ID: "chainguard"}, SystemFacts{},
			[]string{"Wolfi/Chainguard", "rebuild"}, nil},
		{"distroless-debian12", OSInfo{ID: "debian", VersionID: "12", PrettyName: "Distroless"}, SystemFacts{},
			[]string{"Rebuild on a base image published after 2026-10-20", "ca-certificates 20250419~deb12u2 or later", "strip the certificate from the bundle at build time"}, []string{"apt-get", "'!'"}},
		{"scratch-unknown-os", OSInfo{}, SystemFacts{},
			[]string{"Rebuild on a base image published after 2026-10-20", "strip the certificate from the bundle at build time"}, []string{"ca-certificates  "}},
		{"ubi-micro-no-manager", OSInfo{ID: "rhel", IDLike: "fedora", VersionID: "9.6"}, SystemFacts{},
			[]string{"Rebuild on a base image published after 2026-10-20", "no longer carries the certificate"}, []string{"update-ca-trust"}},
		{"unknown-with-manager", OSInfo{ID: "nixos"}, SystemFacts{HasPackageManager: true},
			[]string{"no fix data for this distribution as of 2026-10-23", "rebuild the image"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SystemRemediation(tt.os, tt.facts)
			if got == "" || !strings.HasSuffix(got, ".") {
				t.Fatalf("not a sentence: %q", got)
			}
			if strings.Contains(strings.TrimSuffix(got, "."), ". ") {
				t.Errorf("more than one sentence: %q", got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("%q\n  lacks %q", got, w)
				}
			}
			for _, n := range tt.not {
				if strings.Contains(got, n) {
					t.Errorf("%q\n  must not contain %q", got, n)
				}
			}
		})
	}
}

// The versions SystemRemediation quotes are the ones CACertificatesFix reports.
func TestSystemRemediationQuotesFixVersions(t *testing.T) {
	for _, o := range []OSInfo{
		{ID: "debian", VersionID: "13"}, {ID: "debian", VersionID: "12"}, {ID: "debian"},
		{ID: "ubuntu", VersionID: "22.04"}, {ID: "ubuntu", VersionID: "26.10"}, {ID: "ubuntu", VersionID: "20.04"},
		{ID: "alpine"}, {ID: "fedora"}, {ID: "arch"},
	} {
		fix, ok := CACertificatesFix(o)
		if !ok {
			t.Fatalf("%+v: no fix", o)
		}
		for _, facts := range []SystemFacts{{HasPackageManager: true}, {}} {
			if got := SystemRemediation(o, facts); !strings.Contains(got, fix.FixedVersion) {
				t.Errorf("%+v %+v: %q does not quote %q", o, facts, got, fix.FixedVersion)
			}
		}
	}
}
