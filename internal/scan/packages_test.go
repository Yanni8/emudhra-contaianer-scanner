package scan

import (
	"strings"
	"testing"

	"emudhra-container-scanner/internal/stores"
)

func TestDistrolessStatusD(t *testing.T) {
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	b := newTar()
	b.file("etc/ssl/certs/ca-certificates.crt", pemOf(g3))
	b.file("usr/lib/os-release", []byte("PRETTY_NAME=\"Distroless\"\nNAME=\"Debian GNU/Linux\"\nID=\"debian\"\nVERSION_ID=\"12\"\nVERSION=\"Debian GNU/Linux 12 (bookworm)\"\n"))
	b.file("var/lib/dpkg/status.d/ca-certificates", []byte("Package: ca-certificates\nVersion: 20250419~deb12u1\nArchitecture: all\nMaintainer: x\nDescription: Common CA certificates\n"))
	b.file("var/lib/dpkg/status.d/ca-certificates.md5sums", []byte("Package: ca-certificates\nVersion: 99\n"))
	b.file("var/lib/dpkg/status.d/base-files", []byte("Package: base-files\nVersion: 12.4+deb12u15\n"))
	res := scanTar(t, b.bytes(), Options{Env: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}})

	pkgs := packagesByKey(res)
	if len(res.Packages) != 1 {
		t.Errorf("packages = %+v", res.Packages)
	}
	if p := pkgs["dpkg:ca-certificates"]; p.Version != "20250419~deb12u1" || p.FixedVersion != "20250419~deb12u2" || p.Outdated == nil || !*p.Outdated {
		t.Errorf("ca-certificates = %+v", p)
	}
	if res.Summary.PackageDatabase != "dpkg (status.d)" {
		t.Errorf("package database = %q", res.Summary.PackageDatabase)
	}
	f, ok := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3")
	if !ok || !strings.Contains(f.Remediation, "Rebuild on a base image published after 2026-10-20 that ships ca-certificates 20250419~deb12u2 or later") || strings.Contains(f.Remediation, "apt-get") {
		t.Errorf("distroless remediation = %q (ok %v)", f.Remediation, ok)
	}
	if !strings.Contains(f.Trust.Detail, "explicitly selected by SSL_CERT_FILE") || !strings.Contains(f.Trust.Detail, "which is the default system bundle") {
		t.Errorf("trust detail = %q", f.Trust.Detail)
	}
}

func TestApkDatabases(t *testing.T) {
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	t.Run("wolfi", func(t *testing.T) {
		b := newTar()
		b.file("etc/ssl/certs/ca-certificates.crt", pemOf(g3))
		b.file("etc/os-release", []byte("ID=wolfi\nNAME=\"Wolfi\"\nVERSION_ID=\"20230201\"\n"))
		b.file("usr/lib/apk/db/installed", []byte("P:ca-certificates-bundle\nV:20260413-r0\no:ca-certificates\n\nP:wolfi-baselayout\nV:20230201-r23\n"))
		b.file("usr/bin/apk", append([]byte(nil), elfHeader...))
		res := scanTar(t, b.bytes(), Options{})
		if p := packagesByKey(res)["apk:ca-certificates-bundle"]; p.Version != "20260413-r0" || p.Outdated != nil || !strings.Contains(p.Note, "no fixed version known") {
			t.Errorf("wolfi bundle = %+v", p)
		}
		if res.Summary.PackageDatabase != "apk" {
			t.Errorf("package database = %q", res.Summary.PackageDatabase)
		}
		if f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3"); !strings.Contains(f.Remediation, "Wolfi/Chainguard") {
			t.Errorf("wolfi remediation = %q", f.Remediation)
		}
	})
	t.Run("alpine-bundle-only", func(t *testing.T) {
		b := newTar()
		b.file("etc/ssl/certs/ca-certificates.crt", pemOf(g3))
		b.file("etc/os-release", []byte("ID=alpine\nVERSION_ID=3.20.10\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"))
		b.file("lib/apk/db/installed", []byte("P:ca-certificates-bundle\nV:20260413-r0\no:ca-certificates\n\nP:libssl3\nV:3.3.7-r0\n"))
		b.file("sbin/apk", append([]byte(nil), elfHeader...))
		res := scanTar(t, b.bytes(), Options{})
		if p := packagesByKey(res)["apk:ca-certificates-bundle"]; p.FixedVersion != "20261020-r0" || p.Outdated == nil || !*p.Outdated {
			t.Errorf("alpine bundle = %+v", p)
		}
		f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3")
		if !strings.Contains(f.Remediation, "apk upgrade ca-certificates-bundle") || strings.Contains(f.Remediation, "deselect") {
			t.Errorf("alpine remediation = %q", f.Remediation)
		}
	})
}

func TestDistroStatus(t *testing.T) {
	fedora := stores.OSInfo{ID: "fedora", VersionID: "43"}
	fedoraFix, fedoraOK := stores.CACertificatesFix(fedora)
	debianFix, debianOK := stores.CACertificatesFix(stores.OSInfo{ID: "debian", VersionID: "12"})
	rhelFix, rhelOK := stores.CACertificatesFix(stores.OSInfo{ID: "rhel", VersionID: "9.4"})
	cases := []struct {
		pkg      stores.Package
		fix      stores.Fix
		ok       bool
		outdated *bool
		fixed    string
	}{
		{stores.Package{Name: "ca-certificates", Version: "2026.2.92_v9.0.319-1.fc43", Manager: "rpm"}, fedoraFix, fedoraOK, boolPtr(true), "2026.2.92_v9.0.319-2"},
		{stores.Package{Name: "ca-certificates", Version: "2026.2.92_v9.0.319-2.fc43", Manager: "rpm"}, fedoraFix, fedoraOK, boolPtr(false), "2026.2.92_v9.0.319-2"},
		{stores.Package{Name: "ca-certificates", Version: "2025.2.80_v9.0.305-91.el9", Manager: "rpm"}, rhelFix, rhelOK, nil, ""},
		{stores.Package{Name: "ca-certificates", Version: "20230311", Manager: "dpkg"}, debianFix, debianOK, boolPtr(true), "20250419~deb12u2"},
		{stores.Package{Name: "ca-certificates", Version: "20250419~deb12u2", Manager: "dpkg"}, debianFix, debianOK, boolPtr(false), "20250419~deb12u2"},
		{stores.Package{Name: "openssl", Version: "3.0.15-1~deb12u1", Manager: "dpkg"}, debianFix, debianOK, nil, ""},
		{stores.Package{Name: "openjdk-17-jre-headless", Version: "17.0.20+8-1~deb12u1", Manager: "dpkg"}, debianFix, debianOK, boolPtr(true), "17.0.21.0.2"},
		{stores.Package{Name: "openjdk-17-jre-headless", Version: "17.0.21.0.2+9-1~deb12u1", Manager: "dpkg"}, debianFix, debianOK, boolPtr(false), "17.0.21.0.2"},
		{stores.Package{Name: "java-17-openjdk-headless", Version: "1:17.0.21.0.2-1.el9", Manager: "rpm"}, rhelFix, rhelOK, boolPtr(false), "17.0.21.0.2"},
		{stores.Package{Name: "java-21-openjdk", Version: "1:21.0.12.0.1-1.el9", Manager: "rpm"}, rhelFix, rhelOK, boolPtr(true), "21.0.13.0.2"},
		{stores.Package{Name: "java-1.8.0-openjdk-headless", Version: "1:1.8.0.462.b08-2.el9", Manager: "rpm"}, rhelFix, rhelOK, boolPtr(true), ""},
	}
	for i, tc := range cases {
		ps := distroStatus(tc.pkg, tc.fix, tc.ok)
		switch {
		case tc.outdated == nil && ps.Outdated != nil, tc.outdated != nil && (ps.Outdated == nil || *ps.Outdated != *tc.outdated), ps.FixedVersion != tc.fixed:
			t.Errorf("case %d %s %s: %+v", i, tc.pkg.Name, tc.pkg.Version, ps)
		}
	}
	if ps := distroStatus(stores.Package{Name: "ca-certificates", Version: "2025.2.80_v9.0.305-91.el9", Manager: "rpm"}, rhelFix, rhelOK); !strings.Contains(ps.Note, "pending") || ps.Reference == "" {
		t.Errorf("rhel pending = %+v", ps)
	}
}

func TestRPMTrustPackage(t *testing.T) {
	for name, want := range map[string]bool{
		"ca-certificates": true, "ca-certificates-mozilla": true, "openssl-libs": true, "openssl": true, "p11-kit-trust": true, "nss": true,
		"java-17-openjdk-headless": true, "java-21-openjdk": true, "java-1.8.0-openjdk": true,
		"gpg-pubkey": false, "zlib": false, "java-17-openjdk-devel": false, "nss-util": false, "openssl-devel": false,
	} {
		if got := rpmTrustPackage(name); got != want {
			t.Errorf("rpmTrustPackage(%s) = %v", name, got)
		}
	}
}

func TestVersionStatuses(t *testing.T) {
	type tc struct {
		ps       PackageStatus
		outdated *bool
		fixed    string
		note     string // substring, "" for none
	}
	check := func(name string, cases []tc) {
		t.Helper()
		for i, c := range cases {
			ps := c.ps
			switch {
			case c.outdated == nil && ps.Outdated != nil, c.outdated != nil && (ps.Outdated == nil || *ps.Outdated != *c.outdated), ps.FixedVersion != c.fixed, !strings.Contains(ps.Note, c.note):
				t.Errorf("%s case %d (%s %s): %+v", name, i, ps.Name, ps.Version, ps)
			}
		}
	}
	check("java", []tc{
		{javaStatus("Eclipse Adoptium", "17.0.12", "jdk", "/x"), boolPtr(true), "17.0.21.0.2", ""},
		{javaStatus("Eclipse Adoptium", "17.0.21.0.2+9", "jre", "/x"), boolPtr(false), "17.0.21.0.2", ""},
		{javaStatus("Oracle", "1.8.0_462", "jdk", "/x"), boolPtr(true), "", "8u512"},
		{javaStatus("Temurin", "11.0.33.0.2", "jdk", "/x"), boolPtr(false), "11.0.33.0.2", "expected"},
		{javaStatus("Temurin", "11.0.32+7", "jdk", "/x"), boolPtr(true), "11.0.33.0.2", "expected"},
		{javaStatus("Temurin", "21.0.12.1+1-LTS", "jdk", "/x"), boolPtr(true), "21.0.13.0.2", ""},
		{javaStatus("Temurin", "25-ea", "jdk", "/x"), boolPtr(true), "25.0.5.0.2", ""},
		{javaStatus("Temurin", "23.0.1", "jdk", "/x"), nil, "", "no fix data"},
		{javaStatus("Temurin", "garbage", "jdk", "/x"), nil, "", ""},
	})
	check("node", []tc{
		{nodeStatus("22.23.4", "/x"), boolPtr(false), "22.23.4", ""},
		{nodeStatus("22.23.3", "/x"), boolPtr(true), "22.23.4", ""},
		{nodeStatus("24.22.1", "/x"), boolPtr(false), "24.22.1", ""},
		{nodeStatus("26.12.1", "/x"), boolPtr(false), "26.12.1", ""},
		{nodeStatus("20.18.0", "/x"), boolPtr(true), "", "end-of-life"},
		{nodeStatus("23.11.1", "/x"), boolPtr(true), "", "end-of-life"},
		{nodeStatus("28.0.0", "/x"), boolPtr(true), "", "no Node.js 28 release"},
		{nodeStatus("v20.18.0", "/x"), boolPtr(true), "", "end-of-life"},
		{nodeStatus("x.y.z", "/x"), nil, "", ""},
	})
	if ps := nodeStatus("24.0.0", "/x"); ps.Reference != "https://nodejs.org/en/blog/release/v24.22.1" {
		t.Errorf("node reference = %q", ps.Reference)
	}
	check("go", []tc{
		{goStatus("1.27.3", "/x"), boolPtr(false), "1.27.3", ""},
		{goStatus("1.27.2", "/x"), boolPtr(true), "1.27.3", ""},
		{goStatus("1.26.10", "/x"), boolPtr(false), "1.26.10", ""},
		{goStatus("1.25.14", "/x"), boolPtr(true), "", "no fixed release in this line"},
		{goStatus("1.28.0", "/x"), nil, "", "newer than the fix data"},
		{goStatus("go1.26.10", "/x"), boolPtr(false), "1.26.10", ""},
		{goStatus("x", "/x"), nil, "", ""},
	})
	check("python", []tc{
		{pythonPackage("certifi", "2024.08.30", "/x"), boolPtr(true), "2026.10.18", "2026.10.19"},
		{pythonPackage("certifi", "2026.10.18", "/x"), boolPtr(false), "2026.10.18", "2026.10.19"},
		{pythonPackage("certifi", "2026.10.19", "/x"), boolPtr(false), "2026.10.18", ""},
		{pythonPackage("certifi", "2026.12.1", "/x"), boolPtr(false), "2026.10.18", ""},
		{pythonPackage("pip", "24.0", "/x"), boolPtr(true), "26.2.2", ""},
		{pythonPackage("pip", "26.2.2", "/x"), boolPtr(false), "26.2.2", ""},
		{pythonPackage("other", "1.0", "/x"), nil, "", ""},
	})
	check("runtime", []tc{
		{runtimeStatus("deno", "2.9.7", "/x"), boolPtr(true), "2.9.8", ""},
		{runtimeStatus("deno", "2.9.8", "/x"), boolPtr(false), "2.9.8", ""},
		{runtimeStatus("bun", "1.4.4", "/x"), boolPtr(false), "1.4.4", ""},
		{runtimeStatus("bun", "1.3.9", "/x"), boolPtr(true), "1.4.4", ""},
		{runtimeStatus("uv", "0.13.5", "/x"), boolPtr(false), "0.13.4", "0.13.5"},
		{runtimeStatus("node", "22.23.4", "/x"), boolPtr(false), "22.23.4", ""},
		{runtimeStatus("go", "1.27.3", "/x"), boolPtr(false), "1.27.3", ""},
		{runtimeStatus("other", "1.0.0", "/x"), nil, "", ""},
	})
}

func TestEnvVersions(t *testing.T) {
	w := newWalker(nil, Options{Env: []string{"NODE_VERSION=20.18.0", "DENO_VERSION=v2.9.8", "GOLANG_VERSION=1.27.3", "JAVA_VERSION=jre-17.0.12+7", "BUN_VERSION=", "UV_VERSION=0.13.5"}})
	existing := []PackageStatus{{Name: "node", Version: "22.23.4", Manager: "node"}, {Name: "java (x)", Version: "21.0.1", Manager: "jre"}}
	rows := w.envVersions(existing)
	got := map[string]PackageStatus{}
	for _, r := range rows {
		got[r.Manager] = r
	}
	if len(rows) != 3 || got["deno"].Version != "2.9.8" || got["go"].Version != "1.27.3" || got["uv"].Version != "0.13.5" {
		t.Errorf("env rows = %+v", rows)
	}
	if _, ok := got["node"]; ok {
		t.Error("NODE_VERSION must not add a row when a node version was found on disk")
	}
	if _, ok := got["jdk"]; ok {
		t.Error("JAVA_VERSION must not add a row when a JRE release file was found")
	}
	if got["deno"].Path != "DENO_VERSION (image environment)" || got["deno"].Outdated == nil || *got["deno"].Outdated {
		t.Errorf("deno env row = %+v", got["deno"])
	}
}

func TestIsStatusDFile(t *testing.T) {
	for name, want := range map[string]bool{
		"/var/lib/dpkg/status.d/ca-certificates": true, "/var/lib/dpkg/status.d/libssl3": true,
		"/var/lib/dpkg/status.d/ca-certificates.md5sums": false, "/var/lib/dpkg/status.d/": false,
		"/var/lib/dpkg/status.d/sub/x": false, "/var/lib/dpkg/status": false,
	} {
		if got := isStatusDFile(name); got != want {
			t.Errorf("isStatusDFile(%s) = %v", name, got)
		}
	}
	for name, want := range map[string]bool{"/usr/local/go/VERSION": true, "/usr/lib/go-1.25/VERSION": true, "/opt/app/VERSION": false, "/usr/local/go/README": false} {
		if got := isGoVersionFile(name); got != want {
			t.Errorf("isGoVersionFile(%s) = %v", name, got)
		}
	}
}
