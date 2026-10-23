package scan

import (
	"context"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/stores"
)

func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"Example"}}
}

func TestAliasPromotion(t *testing.T) {
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	aaa := blocklistCert(t, "aaa-certificate-services")
	inter := blocklistCert(t, "em-dv-tls-ca-g3b")
	b := newTar()
	b.file("opt/custom/bundle.pem", append(pemOf(g3), pemOf(inter)...))
	b.symlink("etc/ssl/certs/ca-certificates.crt", "/opt/custom/bundle.pem")
	b.hardlink("etc/ssl/cert.pem", "opt/custom/bundle.pem")
	b.file("opt/custom/extra.pem", pemOf(aaa))
	b.symlink("etc/ssl/certs/d7a7a0fb.0", "../../../opt/custom/extra.pem")
	b.file("etc/os-release", []byte("ID=debian\nVERSION_ID=\"13\"\n"))
	b.file("usr/bin/dpkg", append([]byte(nil), elfHeader...))
	res := scanTar(t, b.bytes(), Options{})

	f, ok := findingFor(res, "/opt/custom/bundle.pem", "emsign-ecc-root-ca-g3")
	if !ok {
		t.Fatal("finding in the linked bundle missing")
	}
	if f.Store.Class != stores.ClassSystemBundle || f.Store.Name != "Debian/Ubuntu/Alpine OpenSSL CA bundle" || f.Trust.State != TrustTrusted || f.Severity != blocklist.SeverityHigh || !strings.Contains(f.Trust.Detail, "identified by the link name /etc/ssl/certs/ca-certificates.crt") {
		t.Errorf("linked bundle finding: store %+v trust %+v severity %s", f.Store, f.Trust, f.Severity)
	}
	if !equalStrings(f.Aliases, []string{"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"}) || !strings.Contains(f.Remediation, "apt-get install --only-upgrade ca-certificates") {
		t.Errorf("linked bundle: aliases %v remediation %q", f.Aliases, f.Remediation)
	}
	if f, _ := findingFor(res, "/opt/custom/bundle.pem", "em-dv-tls-ca-g3b"); f.Severity != blocklist.SeverityCritical || f.Trust.State != TrustTrusted {
		t.Errorf("intermediate in the linked bundle: %s %s", f.Severity, f.Trust.State)
	}
	if f, _ := findingFor(res, "/opt/custom/extra.pem", "aaa-certificate-services"); f.Store.Class != stores.ClassSystemAnchorDir || f.Trust.State != TrustTrusted || f.Severity != blocklist.SeverityHigh {
		t.Errorf("hashed-link file: store %s trust %s severity %s", f.Store.Class, f.Trust.State, f.Severity)
	}
	if s, _ := storeFor(res, "/opt/custom/bundle.pem"); s.Class != stores.ClassSystemBundle || s.ClassifiedBy != "/etc/ssl/certs/ca-certificates.crt" || s.Certificates != 2 {
		t.Errorf("store summary = %+v", s)
	}
	if !res.Summary.SystemBundleFound {
		t.Error("the linked bundle counts as the system bundle")
	}
}

func TestClassRank(t *testing.T) {
	order := []stores.Store{
		stores.Classify("/etc/ssl/certs/ca-certificates.crt", nil),
		stores.Classify("/usr/local/share/ca-certificates/x.crt", nil),
		stores.Classify("/usr/local/bin/node", elfHeader),
		stores.Classify("/usr/share/ca-certificates/mozilla/x.crt", nil),
		stores.Classify("/opt/app/keystore.jks", nil),
		stores.Classify("/opt/app/bin/server", elfHeader),
		stores.Classify("/opt/app/x.pem", nil),
	}
	for i := 1; i < len(order); i++ {
		if classRank(order[i-1]) >= classRank(order[i]) {
			t.Errorf("%s (%d) must outrank %s (%d)", order[i-1].Class, classRank(order[i-1]), order[i].Class, classRank(order[i]))
		}
	}
	if classRank(stores.Classify("/opt/java/lib/security/cacerts", nil)) != classRank(stores.Classify("/usr/local/share/ca-certificates/x.crt", nil)) {
		t.Error("a trusted keystore ranks with anchor directories")
	}
	if classRank(stores.Classify("/etc/pki/ca-trust/source/blocklist/x.pem", nil)) != 0 {
		t.Error("blocklist directories rank with system bundles")
	}
}

func TestDirectorySymlinkAliases(t *testing.T) {
	w := newWalker(context.Background(), Options{})
	for _, p := range []string{
		"/etc/pki/ca-trust/extracted/pem/directory-hash/emSign.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/usr/lib/jvm/java-17/lib/security/cacerts",
		"/opt/data/c/x.pem",
	} {
		w.storeFor(p, stores.Store{}, nil)
	}
	w.symlinks["/etc/ssl/certs"] = "/etc/pki/ca-trust/extracted/pem/directory-hash"
	w.symlinks["/etc/pki/ca-trust/extracted/pem/directory-hash/14bc7599.0"] = "/etc/pki/ca-trust/extracted/pem/directory-hash/emSign.pem"
	w.symlinks["/etc/pki/ca-trust/extracted/pem/directory-hash/ca-bundle.crt"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	w.symlinks["/lib"] = "/usr/lib"
	w.symlinks["/etc/alternatives/jre"] = "/lib/jvm/java-17"
	w.symlinks["/opt/a"] = "/opt/b"
	w.symlinks["/opt/b"] = "/opt/data/c"
	w.symlinks["/dangling"] = "/nowhere"
	idx := w.aliasIndex()
	cases := map[string][]string{
		"/etc/pki/ca-trust/extracted/pem/directory-hash/emSign.pem": {"/etc/pki/ca-trust/extracted/pem/directory-hash/14bc7599.0", "/etc/ssl/certs/14bc7599.0", "/etc/ssl/certs/emSign.pem"},
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem":         {"/etc/pki/ca-trust/extracted/pem/directory-hash/ca-bundle.crt", "/etc/ssl/certs/ca-bundle.crt"},
		"/usr/lib/jvm/java-17/lib/security/cacerts":                 {"/etc/alternatives/jre/lib/security/cacerts", "/lib/jvm/java-17/lib/security/cacerts"},
		"/opt/data/c/x.pem": {"/opt/a/x.pem", "/opt/b/x.pem"},
	}
	for target, want := range cases {
		if !equalStrings(idx[target], want) {
			t.Errorf("aliases of %s = %v, want %v", target, idx[target], want)
		}
	}
	if _, ok := idx["/nowhere/x.pem"]; ok {
		t.Error("names below a dangling directory link must not be invented")
	}
}

func TestEnvSelects(t *testing.T) {
	w := newWalker(context.Background(), Options{})
	w.symlinks["/etc/ssl/certs"] = "/etc/pki/ca-trust/extracted/pem/directory-hash"
	w.symlinks["/etc/pki/ca-trust/extracted/pem/directory-hash/ca-bundle.crt"] = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	w.symlinks["/etc/ssl/certs/java"] = "/etc/pki/ca-trust/extracted/java"
	w.symlinks["/loop"] = "/loop"
	w.hints = stores.EnvHints([]string{"SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt", "SSL_CERT_DIR=/etc/ssl/certs", "GIT_SSL_CAPATH=/opt/capath", "REQUESTS_CA_BUNDLE=/opt/app/ca.pem", "NODE_TLS_REJECT_UNAUTHORIZED=0", "PIP_CERT=/loop/x.pem"})
	bundle := stores.Classify("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", nil)
	hashed := stores.Classify("/etc/pki/ca-trust/extracted/pem/directory-hash/x.pem", nil)
	cacerts := stores.Classify("/etc/pki/ca-trust/extracted/java/cacerts", nil)
	loose := stores.Classify("/opt/capath/x.pem", nil)
	cases := []struct {
		path    string
		aliases []string
		store   stores.Store
		want    string // variable, "" for none
	}{
		{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", nil, bundle, "SSL_CERT_FILE"},
		{"/etc/pki/ca-trust/extracted/pem/directory-hash/x.pem", nil, hashed, "SSL_CERT_DIR"},
		{"/etc/pki/ca-trust/extracted/java/cacerts", []string{"/etc/ssl/certs/java/cacerts"}, cacerts, ""},
		{"/opt/capath/x.pem", nil, loose, "GIT_SSL_CAPATH"},
		{"/opt/real/ca.pem", []string{"/opt/app/ca.pem"}, loose, "REQUESTS_CA_BUNDLE"},
		{"/opt/other/ca.pem", nil, loose, ""},
		{"/loop/x.pem", nil, loose, "PIP_CERT"},
		{"/usr/local/bin/node", []string{"/etc/ssl/certs/node"}, stores.Classify("/usr/local/bin/node", elfHeader), ""},
	}
	for i, tc := range cases {
		h, ok := w.envSelects(tc.path, tc.aliases, tc.store)
		if ok != (tc.want != "") || h.Variable != tc.want {
			t.Errorf("case %d %s: got %q (%v), want %q", i, tc.path, h.Variable, ok, tc.want)
		}
	}
}

func TestP11KitFamilyAndBlocklistNames(t *testing.T) {
	for name, want := range map[string]bool{
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem": true, "/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit": true,
		"/etc/pki/tls/certs/ca-bundle.crt": true, "/etc/pki/java/cacerts": true, "/var/lib/ca-certificates/java-cacerts": true,
		"/etc/ssl/ca-bundle.pem": true, "/etc/ca-certificates/extracted/tls-ca-bundle.pem": true, "/etc/pki/trust/anchors/x.pem": true,
		"/etc/ssl/certs/ca-certificates.crt": false, "/usr/share/ca-certificates/mozilla/x.crt": false, "/opt/x.pem": false,
	} {
		if got := p11KitFamily(name, nil); got != want {
			t.Errorf("p11KitFamily(%s) = %v", name, got)
		}
	}
	if !p11KitFamily("/opt/x.pem", []string{"/etc/pki/ca-trust/source/anchors/x.pem"}) {
		t.Error("an alias in the tree puts the file in the family")
	}
	if name, ok := blocklistName("/etc/pki/ca-trust/source/anchors/x.pem", []string{"/opt/y", "/etc/pki/ca-trust/source/blocklist/x.pem"}); !ok || name != "/etc/pki/ca-trust/source/blocklist/x.pem" {
		t.Errorf("blocklistName = %q, %v", name, ok)
	}
	if _, ok := blocklistName("/opt/x.pem", []string{"/etc/ssl/certs/x.pem"}); ok {
		t.Error("blocklistName without a blocklist path")
	}
	var d distrustIndex
	d.add(certID{sha256: "aa", spki: "bb"}, "/first")
	d.add(certID{sha256: "cc", spki: "bb"}, "/second")
	if p, ok := d.lookup(CertInfo{SHA256: "cc", SPKISHA256: "zz"}); !ok || p != "/second" {
		t.Errorf("lookup by fingerprint = %q, %v", p, ok)
	}
	if p, ok := d.lookup(CertInfo{SHA256: "dd", SPKISHA256: "bb"}); !ok || p != "/first" {
		t.Errorf("lookup by key = %q, %v", p, ok)
	}
	if _, ok := d.lookup(CertInfo{SPKISHA256: "ee"}); ok {
		t.Error("lookup of an unknown key")
	}
}
