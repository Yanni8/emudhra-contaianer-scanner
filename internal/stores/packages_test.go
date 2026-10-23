package stores

import (
	"reflect"
	"testing"
)

const sampleDpkgStatus = `Package: adduser
Status: install ok installed
Priority: important
Section: admin
Version: 3.134
Description: add and remove users and groups
 This package includes the 'adduser' and 'deluser' commands.

Package: ca-certificates
Status: install ok installed
Priority: standard
Section: misc
Installed-Size: 384
Maintainer: Julien Cristau <jcristau@debian.org>
Architecture: all
Multi-Arch: foreign
Version: 20230311
Depends: openssl (>= 1.1.1), debconf (>= 0.5) | debconf-2.0
Description: Common CA certificates
 Contains the certificate authorities shipped with Mozilla's browser to allow
 SSL-based applications to check for the authenticity of SSL connections.
 .
 Please note that Debian can neither confirm nor deny whether the
 certificate authorities whose certificates are included in this package
 have in any way been audited for trustworthiness or RFC 3647 compliance.

Package: libssl3
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Version: 3.0.15-1~deb12u1

Package: libssl3
Status: install ok installed
Architecture: i386
Multi-Arch: same
Version: 3.0.15-1~deb12u1

Package: libnss3
Status: deinstall ok config-files
Version: 2:3.87.1-1+deb12u1

Package: p11-kit
Status: install ok half-configured
Version: 0.24.1-2

Package: openssl
Status: hold ok installed
Version: 3.0.15-1~deb12u1

package: shouty
status: install ok installed
version: 1.0

Package: ca-certificates-java
Status: install ok triggers-awaited
Version: 20230710~deb12u1

Package: openjdk-17-jre-headless
Status: install ok unpacked
Version: 17.0.13+11-2~deb12u1

Package: default-jre-headless
Status: install ok installed
Version: 2:1.17-74`

func TestParseDpkgStatus(t *testing.T) {
	got := ParseDpkgStatus([]byte(sampleDpkgStatus), TrustPackages)
	want := []Package{
		{Name: "ca-certificates", Version: "20230311", Manager: "dpkg"},
		{Name: "libssl3", Version: "3.0.15-1~deb12u1", Manager: "dpkg"},
		{Name: "openssl", Version: "3.0.15-1~deb12u1", Manager: "dpkg"},
		{Name: "ca-certificates-java", Version: "20230710~deb12u1", Manager: "dpkg"},
		{Name: "default-jre-headless", Version: "2:1.17-74", Manager: "dpkg"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDpkgStatus =\n  %+v\nwant\n  %+v", got, want)
	}

	if got := ParseDpkgStatus([]byte(sampleDpkgStatus), []string{"adduser", "shouty"}); !reflect.DeepEqual(got, []Package{
		{Name: "adduser", Version: "3.134", Manager: "dpkg"},
		{Name: "shouty", Version: "1.0", Manager: "dpkg"},
	}) {
		t.Errorf("name filter / case-insensitive fields: got %+v", got)
	}
	if got := ParseDpkgStatus([]byte(sampleDpkgStatus), nil); got != nil {
		t.Errorf("no names: got %+v, want nil", got)
	}
	if got := ParseDpkgStatus(nil, TrustPackages); got != nil {
		t.Errorf("no data: got %+v, want nil", got)
	}
	if got := ParseDpkgStatus([]byte("Package: openssl\nVersion: 1.0\n"), TrustPackages); got != nil {
		t.Errorf("stanza without Status must not count as installed: got %+v", got)
	}
	if got := ParseDpkgStatus([]byte("Package: openssl\nStatus: install ok installed\n"), TrustPackages); !reflect.DeepEqual(got, []Package{{Name: "openssl", Manager: "dpkg"}}) {
		t.Errorf("stanza without Version: got %+v", got)
	}
	if got := ParseDpkgStatus([]byte("Package: openssl\r\nStatus: install ok installed\r\nVersion: 3.0\r\n"), TrustPackages); !reflect.DeepEqual(got, []Package{{Name: "openssl", Version: "3.0", Manager: "dpkg"}}) {
		t.Errorf("CRLF stanza: got %+v", got)
	}
}

func TestDpkgInstalled(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"install ok installed", true},
		{"hold ok installed", true},
		{"install ok triggers-awaited", true},
		{"install ok triggers-pending", true},
		{"deinstall ok config-files", false},
		{"install ok half-configured", false},
		{"install ok half-installed", false},
		{"install ok unpacked", false},
		{"purge ok not-installed", false},
		{"installed", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := dpkgInstalled(tt.status); got != tt.want {
			t.Errorf("dpkgInstalled(%q) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

const sampleApkInstalled = `C:Q1abc=
P:busybox
V:1.36.1-r29
A:x86_64
S:508814
I:962560
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Sören Tempel <soeren+alpine@soeren-tempel.net>
t:1718108824
c:abc
D:so:libc.musl-x86_64.so.1
p:/bin/sh cmd:busybox=1.36.1-r29
F:bin
R:busybox
a:0:0:755
Z:Q1xyz=

C:Q1def=
P:ca-certificates-bundle
V:20240705-r0
A:x86_64
T:Pre generated bundle of Mozilla certificates
o:ca-certificates
F:etc/ssl/certs
R:ca-certificates.crt
Z:Q1ghi=

C:Q1jkl=
P:libssl3
V:3.3.2-r0
o:openssl

C:Q1mno=
P:ca-certificates
V:20240705-r0
o:ca-certificates`

func TestParseApkInstalled(t *testing.T) {
	got := ParseApkInstalled([]byte(sampleApkInstalled), TrustPackages)
	want := []Package{
		{Name: "ca-certificates-bundle", Version: "20240705-r0", Manager: "apk"},
		{Name: "libssl3", Version: "3.3.2-r0", Manager: "apk"},
		{Name: "ca-certificates", Version: "20240705-r0", Manager: "apk"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseApkInstalled =\n  %+v\nwant\n  %+v", got, want)
	}
	if got := ParseApkInstalled([]byte(sampleApkInstalled), []string{"busybox"}); !reflect.DeepEqual(got, []Package{{Name: "busybox", Version: "1.36.1-r29", Manager: "apk"}}) {
		t.Errorf("busybox: got %+v", got)
	}
	if got := ParseApkInstalled(nil, TrustPackages); got != nil {
		t.Errorf("no data: got %+v", got)
	}
	if got := ParseApkInstalled([]byte("P:openssl\nV:3.3.2-r0\n\nP:openssl\nV:3.3.2-r0\n"), []string{"openssl"}); len(got) != 1 {
		t.Errorf("duplicate stanzas should collapse: got %+v", got)
	}
	// The origin field ("o:") is not the package name.
	if got := ParseApkInstalled([]byte("P:libcrypto3\nV:3.3.2-r0\no:openssl\n"), []string{"openssl"}); got != nil {
		t.Errorf("origin must not match: got %+v", got)
	}
}

const sampleStatusD = `Package: ca-certificates
Version: 20250419~deb12u1
Architecture: all
Maintainer: Julien Cristau <jcristau@debian.org>
Installed-Size: 384
Depends: openssl (>= 1.1.1), debconf (>= 0.5) | debconf-2.0
Section: misc
Priority: standard
Multi-Arch: foreign
Description: Common CA certificates
 Contains the certificate authorities shipped with Mozilla's browser to allow
 SSL-based applications to check for the authenticity of SSL connections.
`

func TestParseDpkgStatusD(t *testing.T) {
	want := []Package{{Name: "ca-certificates", Version: "20250419~deb12u1", Manager: "dpkg"}}
	if got := ParseDpkgStatusD([]byte(sampleStatusD), TrustPackages); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDpkgStatusD =\n  %+v\nwant\n  %+v", got, want)
	}
	// The name filter still applies.
	if got := ParseDpkgStatusD([]byte(sampleStatusD), []string{"openssl"}); got != nil {
		t.Errorf("filtered: got %+v", got)
	}
	// The status file parser keeps requiring a Status field.
	if got := ParseDpkgStatus([]byte(sampleStatusD), TrustPackages); got != nil {
		t.Errorf("ParseDpkgStatus must not count a stanza without Status: got %+v", got)
	}
	// Several stanzas in one file, with and without Status.
	multi := "Package: libssl3\nVersion: 3.0.17-1~deb12u2\nArchitecture: amd64\n\nPackage: openssl\nStatus: deinstall ok config-files\nVersion: 3.0.17-1~deb12u2\n\nPackage: ca-certificates\nStatus: install ok installed\nVersion: 20230311\n"
	if got := ParseDpkgStatusD([]byte(multi), TrustPackages); !reflect.DeepEqual(got, []Package{
		{Name: "libssl3", Version: "3.0.17-1~deb12u2", Manager: "dpkg"},
		{Name: "ca-certificates", Version: "20230311", Manager: "dpkg"},
	}) {
		t.Errorf("multi-stanza status.d: got %+v", got)
	}
	if got := ParseDpkgStatusD(nil, TrustPackages); got != nil {
		t.Errorf("no data: got %+v", got)
	}
	// An md5sums file fed by mistake yields nothing.
	if got := ParseDpkgStatusD([]byte("d41d8cd98f00b204e9800998ecf8427e  usr/share/doc/ca-certificates/copyright\n"), TrustPackages); got != nil {
		t.Errorf("md5sums: got %+v", got)
	}
	// Wolfi's apk database is the same format at another path.
	wolfi := "C:Q1abc=\nP:ca-certificates-bundle\nV:20261013-r0\nA:x86_64\no:ca-certificates\n\nC:Q1def=\nP:wolfi-baselayout\nV:20230201-r25\n"
	if got := ParseApkInstalled([]byte(wolfi), TrustPackages); !reflect.DeepEqual(got, []Package{{Name: "ca-certificates-bundle", Version: "20261013-r0", Manager: "apk"}}) {
		t.Errorf("wolfi apk db: got %+v", got)
	}
}
