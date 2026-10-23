package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Yanni8/emudhra-container-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-container-scanner/internal/certs"
	"github.com/Yanni8/emudhra-container-scanner/internal/stores"
)

// --- fixtures ---------------------------------------------------------------

type tarBuilder struct {
	buf bytes.Buffer
	tw  *tar.Writer
}

func newTar() *tarBuilder {
	b := &tarBuilder{}
	b.tw = tar.NewWriter(&b.buf)
	return b
}

func (b *tarBuilder) file(name string, content []byte) {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
	if err := b.tw.WriteHeader(hdr); err != nil {
		panic(err)
	}
	if _, err := b.tw.Write(content); err != nil {
		panic(err)
	}
}

func (b *tarBuilder) dir(name string) {
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		panic(err)
	}
}

func (b *tarBuilder) symlink(name, target string) {
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: target}); err != nil {
		panic(err)
	}
}

func (b *tarBuilder) hardlink(name, target string) {
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeLink, Linkname: target}); err != nil {
		panic(err)
	}
}

func (b *tarBuilder) bytes() []byte {
	if err := b.tw.Close(); err != nil {
		panic(err)
	}
	return b.buf.Bytes()
}

func blocklistCert(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	e := blocklist.Default().ByID(id)
	if e == nil || e.Certificate == nil {
		t.Fatalf("blocklist entry %q missing", id)
	}
	return e.Certificate
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newRoot returns a self-signed CA with the given subject.
func newRoot(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(mathrand.Int63n(1<<62) + 1),
		Subject:               subject,
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeIssued returns a certificate whose issuer name (and AKI) claim issuer
// but which is signed by an unrelated key.
func fakeIssued(t *testing.T, cn string, issuer pkix.Name, issuerSKI []byte) *x509.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(mathrand.Int63n(1<<62) + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn},
	}
	parent := &x509.Certificate{Subject: issuer, SubjectKeyId: issuerSKI}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// writeJKS serialises trusted-certificate entries as a version-2 JKS.
func writeJKS(entries map[string]*x509.Certificate, order []string) []byte {
	var b []byte
	u32 := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	utf := func(s string) { b = binary.BigEndian.AppendUint16(b, uint16(len(s))); b = append(b, s...) }
	u32(0xFEEDFEED)
	u32(2)
	u32(uint32(len(order)))
	for _, alias := range order {
		c := entries[alias]
		u32(2)
		utf(alias)
		b = binary.BigEndian.AppendUint64(b, 1700000000000)
		utf("X.509")
		u32(uint32(len(c.Raw)))
		b = append(b, c.Raw...)
	}
	h := sha1.New()
	for _, r := range "changeit" {
		h.Write([]byte{byte(r >> 8), byte(r)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(b)
	return append(b, h.Sum(nil)...)
}

type certAux struct {
	Trust  []asn1.ObjectIdentifier `asn1:"optional"`
	Reject []asn1.ObjectIdentifier `asn1:"optional,tag:0"`
	Alias  string                  `asn1:"optional,utf8"`
}

func trustedPEM(t *testing.T, c *x509.Certificate, aux certAux) []byte {
	t.Helper()
	der, err := asn1.Marshal(aux)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: append(append([]byte(nil), c.Raw...), der...)})
}

func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	mathrand.New(mathrand.NewSource(seed)).Read(b)
	return b
}

var elfHeader = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0}

func certifiBundle(cs map[string]*x509.Certificate, order []string) []byte {
	var b bytes.Buffer
	b.WriteString("\n## Bundle of CA Root Certificates\n\n")
	for _, label := range order {
		c := cs[label]
		fmt.Fprintf(&b, "# Issuer: %s\n# Subject: %s\n# Label: \"%s\"\n# Serial: %s\n", c.Issuer, c.Subject, label, c.SerialNumber)
		b.Write(pemOf(c))
		b.WriteString("\n")
	}
	return b.Bytes()
}

var (
	anyEKU          = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidCodeSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidEmailProtect = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
)

const (
	osRelease  = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n"
	dpkgStatus = "Package: ca-certificates\nStatus: install ok installed\nPriority: standard\nSection: misc\nVersion: 20230311\nDescription: Common CA certificates\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.15-1~deb12u1\n\nPackage: libssl3\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.15-1~deb12u1\n\nPackage: removed-thing\nStatus: deinstall ok config-files\nVersion: 1\n"
	caConf     = "# Automatically generated by update-ca-certificates\n# Do not edit.\nmozilla/Comodo_AAA_Services_root.crt\nmozilla/emSign_Root_CA_-_G1.crt\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\n!mozilla/emSign_ECC_Root_CA_-_C3.crt\n"
	jdkRelease = "IMPLEMENTOR=\"Eclipse Adoptium\"\nIMPLEMENTOR_VERSION=\"Temurin-17.0.12+7\"\nJAVA_RUNTIME_VERSION=\"17.0.12+7\"\nJAVA_VERSION=\"17.0.12\"\nJAVA_VERSION_DATE=\"2024-07-16\"\nOS_ARCH=\"x86_64\"\n"
	nodeHeader = "#ifndef SRC_NODE_VERSION_H_\n#define SRC_NODE_VERSION_H_\n\n#define NODE_MAJOR_VERSION 20\n#define NODE_MINOR_VERSION 18\n#define NODE_PATCH_VERSION 0\n\n#define NODE_VERSION_IS_LTS 1\n"
	// brokenPEM decodes to 75 bytes, enough for the strict-parser warning.
	brokenPEM = "-----BEGIN CERTIFICATE-----\n" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "\n-----END CERTIFICATE-----\n"
)

// fixture is the synthetic Debian root filesystem used by the tests.
type fixture struct {
	tar      []byte
	g3, aaa  *x509.Certificate
	g1, c1   *x509.Certificate
	c3       *x509.Certificate
	inter    *x509.Certificate
	fakeLeaf *x509.Certificate
}

func buildFixture(t *testing.T) fixture {
	t.Helper()
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	aaa := blocklistCert(t, "aaa-certificate-services")
	g1 := blocklistCert(t, "emsign-root-ca-g1")
	c1 := blocklistCert(t, "emsign-root-ca-c1")
	c3 := blocklistCert(t, "emsign-ecc-root-ca-c3")
	inter := blocklistCert(t, "em-dv-tls-ca-g3b")
	root1 := newRoot(t, pkix.Name{CommonName: "Example Root CA 1", Organization: []string{"Example"}})
	root2 := newRoot(t, pkix.Name{CommonName: "Example Root CA 2", Organization: []string{"Example"}})
	root3 := newRoot(t, pkix.Name{CommonName: "Example ECC Root", Organization: []string{"Example"}})
	emudhraNamed := newRoot(t, pkix.Name{CommonName: "emSign Test Root", Organization: []string{"eMudhra Technologies Limited"}, Country: []string{"IN"}})
	fakeLeaf := fakeIssued(t, "fake.example", inter.Subject, inter.SubjectKeyId)
	fakeIssuedByCustom := fakeIssued(t, "custom.example", pkix.Name{CommonName: "Fake Issuer CA", Organization: []string{"Fake Org"}}, nil)

	b := newTar()
	b.dir("etc/")
	b.dir("etc/ssl/certs/")
	var bundle bytes.Buffer
	for _, c := range []*x509.Certificate{root1, g3, root2, aaa, g1, root3, g1} { // G1 twice: concatenated bundles repeat roots
		bundle.Write(pemOf(c))
	}
	b.file("./etc/ssl/certs/ca-certificates.crt", bundle.Bytes())
	b.hardlink("etc/ssl/cert.pem", "etc/ssl/certs/ca-certificates.crt")
	b.file("etc/ca-certificates.conf", []byte(caConf))
	b.file("usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", pemOf(g3))
	b.file("usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_C3.crt", pemOf(c3))
	b.file("usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt", pemOf(aaa))
	b.file("usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt", pemOf(g1))
	b.file("usr/share/ca-certificates/mozilla/Example_Root_CA_1.crt", pemOf(root1))
	b.file("usr/share/ca-certificates/extra/emSign_Root_CA_-_C1.crt", pemOf(c1))
	b.symlink("etc/ssl/certs/emSign_Root_CA_-_G1.pem", "../../../usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt")
	b.symlink("etc/ssl/certs/5a4d6896.0", "emSign_Root_CA_-_G1.pem")
	b.symlink("etc/ssl/certs/emSign_Root_CA_-_C1.pem", "/usr/share/ca-certificates/extra/emSign_Root_CA_-_C1.crt")
	b.symlink("etc/ssl/certs/dangling.pem", "../../usr/share/ca-certificates/mozilla/Missing.crt")
	b.symlink("etc/ssl/certs/loop-a.pem", "loop-b.pem")
	b.symlink("etc/ssl/certs/loop-b.pem", "loop-a.pem")
	b.file("usr/bin/apt-get", []byte("#!/bin/sh\n"))
	b.file("usr/sbin/update-ca-certificates", []byte("#!/bin/sh\n"))

	b.dir("usr/local/lib/python3.12/site-packages/certifi-2024.8.30.dist-info/")
	b.file("usr/local/lib/python3.12/site-packages/certifi-2024.8.30.dist-info/METADATA", []byte("Metadata-Version: 2.1\nName: certifi\nVersion: 2024.8.30\n"))
	b.file("usr/local/lib/python3.12/site-packages/certifi/cacert.pem", certifiBundle(map[string]*x509.Certificate{"Example Root CA 1": root1, "emSign ECC Root CA - G3": g3}, []string{"Example Root CA 1", "emSign ECC Root CA - G3"}))
	b.file("usr/local/lib/python3.12/site-packages/pip/_vendor/vendor.txt", []byte("CacheControl==0.14.0\nrequests==2.32.3\n    certifi==2024.7.4\n    idna==3.7\ndistlib==0.3.8\n"))
	b.file("usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", certifiBundle(map[string]*x509.Certificate{"Example Root CA 2": root2}, []string{"Example Root CA 2"}))

	b.file("usr/local/share/ca-certificates/em.crt", pemOf(inter))
	b.file("etc/pki/ca-trust/source/blocklist/em.pem", pemOf(inter))
	trustBundle := trustedPEM(t, root3, certAux{Trust: []asn1.ObjectIdentifier{oidServerAuth}, Alias: "Example ECC Root"})
	trustBundle = append(trustBundle, trustedPEM(t, aaa, certAux{Reject: []asn1.ObjectIdentifier{anyEKU}, Alias: "AAA Certificate Services"})...)
	trustBundle = append(trustBundle, trustedPEM(t, g3, certAux{Trust: []asn1.ObjectIdentifier{oidEmailProtect}, Alias: "emSign ECC Root CA - G3"})...)
	b.file("etc/pki/tls/certs/ca-bundle.trust.crt", trustBundle)

	b.file("opt/java/openjdk/lib/security/cacerts", writeJKS(map[string]*x509.Certificate{"emsigneccrootcag3": g3, "examplerootca1": root1}, []string{"examplerootca1", "emsigneccrootcag3"}))
	b.file("opt/java/openjdk/release", []byte(jdkRelease))
	b.symlink("usr/lib/jvm/default", "/opt/java/openjdk")
	b.symlink("etc/alternatives/jre-cacerts", "/usr/lib/jvm/default/lib/security/cacerts")
	b.symlink("etc/ssl/certs/java/cacerts", "../../../../opt/java/openjdk/lib/security/cacerts")

	node := append(append([]byte(nil), elfHeader...), randomBytes(1, 20000)...)
	node = append(node, []byte("\"")...)
	node = append(node, bytes.TrimSuffix(pemOf(g3), []byte("\n"))...)
	node = append(node, []byte("\"\x00")...)
	node = append(node, randomBytes(2, 5000)...)
	b.file("usr/local/bin/node", node)
	b.file("usr/local/include/node/node_version.h", []byte(nodeHeader))

	server := append(append([]byte(nil), elfHeader...), randomBytes(3, 8000)...)
	server = append(server, aaa.RawSubjectPublicKeyInfo[4:]...)
	server = append(server, randomBytes(4, 3000)...)
	b.file("opt/app/bin/server", server)

	b.file("opt/app/certs/fake-leaf.pem", pemOf(fakeLeaf))
	b.file("opt/app/certs/custom-issued.pem", pemOf(fakeIssuedByCustom))
	b.file("opt/app/certs/emudhra-test.pem", pemOf(emudhraNamed))
	b.file("opt/app/certs/broken.pem", []byte(brokenPEM))
	b.file("etc/os-release", []byte(osRelease))
	b.file("var/lib/dpkg/status", []byte(dpkgStatus))
	b.file("etc/hostname", []byte("test\n"))
	b.file("dev/null", nil)
	return fixture{tar: b.bytes(), g3: g3, aaa: aaa, g1: g1, c1: c1, c3: c3, inter: inter, fakeLeaf: fakeLeaf}
}

func findingFor(r *Result, path, entryID string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.Path == path && f.EntryID == entryID {
			return f, true
		}
	}
	return Finding{}, false
}

func storeFor(r *Result, path string) (StoreSummary, bool) {
	for _, s := range r.Stores {
		if s.Path == path {
			return s, true
		}
	}
	return StoreSummary{}, false
}

func packagesByKey(r *Result) map[string]PackageStatus {
	pkgs := map[string]PackageStatus{}
	for _, p := range r.Packages {
		pkgs[p.Manager+":"+p.Name] = p
	}
	return pkgs
}

func scanTar(t *testing.T, data []byte, opts Options) *Result {
	t.Helper()
	res, err := Tar(context.Background(), bytes.NewReader(data), opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// --- tests ------------------------------------------------------------------

func TestTarSyntheticRootfs(t *testing.T) {
	fx := buildFixture(t)
	var progress []string
	res, err := Tar(context.Background(), bytes.NewReader(fx.tar), Options{
		IncludeOperatorHeuristic: true,
		Env:                      []string{"PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", "NODE_TLS_REJECT_UNAUTHORIZED=0"},
		Progress:                 func(m string) { progress = append(progress, m) },
		Version:                  "1.2.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(progress) == 0 {
		t.Error("no progress messages")
	}

	type want struct {
		path, entry string
		severity    blocklist.Severity
		trust       string
		match       blocklist.MatchKind
		kind        certs.Kind
		class       stores.Class
	}
	wants := []want{
		{"/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemBundle},
		{"/etc/ssl/certs/ca-certificates.crt", "aaa-certificate-services", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemBundle},
		{"/etc/ssl/certs/ca-certificates.crt", "emsign-root-ca-g1", blocklist.SeverityLow, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemBundle},
		// Deselected in the configuration, but update-ca-certificates was not run: the bundle still carries it.
		{"/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", "emsign-ecc-root-ca-g3", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemSource},
		{"/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_C3.crt", "emsign-ecc-root-ca-c3", blocklist.SeverityInfo, TrustDisabled, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemSource},
		{"/usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt", "aaa-certificate-services", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemSource},
		{"/usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt", "emsign-root-ca-g1", blocklist.SeverityLow, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemSource},
		{"/usr/share/ca-certificates/extra/emSign_Root_CA_-_C1.crt", "emsign-root-ca-c1", blocklist.SeverityLow, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemSource},
		{"/usr/local/lib/python3.12/site-packages/certifi/cacert.pem", "emsign-ecc-root-ca-g3", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassAppBundle},
		{"/usr/local/share/ca-certificates/em.crt", "em-dv-tls-ca-g3b", blocklist.SeverityCritical, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemAnchorDir},
		{"/etc/pki/ca-trust/source/blocklist/em.pem", "em-dv-tls-ca-g3b", blocklist.SeverityInfo, TrustDistrusted, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassSystemBlocklist},
		{"/etc/pki/tls/certs/ca-bundle.trust.crt", "aaa-certificate-services", blocklist.SeverityInfo, TrustDistrusted, blocklist.MatchFingerprint, certs.KindPEMTrusted, stores.ClassSystemBundle},
		// Trusted for e-mail only: no exposure to the TLS and code-signing intermediates.
		{"/etc/pki/tls/certs/ca-bundle.trust.crt", "emsign-ecc-root-ca-g3", blocklist.SeverityLow, TrustTrusted, blocklist.MatchFingerprint, certs.KindPEMTrusted, stores.ClassSystemBundle},
		{"/opt/java/openjdk/lib/security/cacerts", "emsign-ecc-root-ca-g3", blocklist.SeverityHigh, TrustTrusted, blocklist.MatchFingerprint, certs.KindJKS, stores.ClassJavaKeystore},
		{"/usr/local/bin/node", "emsign-ecc-root-ca-g3", blocklist.SeverityHigh, TrustEmbedded, blocklist.MatchFingerprint, certs.KindPEM, stores.ClassEmbeddedRuntime},
		// A bare anchor key in an unknown executable is a trust-anchor table.
		{"/opt/app/bin/server", "aaa-certificate-services", blocklist.SeverityHigh, TrustEmbedded, blocklist.MatchSPKI, certs.KindSPKI, stores.ClassEmbeddedBinary},
		{"/opt/app/certs/emudhra-test.pem", "operator-heuristic", blocklist.SeverityInfo, TrustUnknown, blocklist.MatchOperator, certs.KindPEM, stores.ClassLooseFile},
	}
	for _, w := range wants {
		f, ok := findingFor(res, w.path, w.entry)
		if !ok {
			t.Errorf("missing finding %s in %s", w.entry, w.path)
			continue
		}
		if f.Severity != w.severity || f.Trust.State != w.trust || f.Match != w.match || f.Certificate.Kind != w.kind || f.Store.Class != w.class {
			t.Errorf("%s in %s: severity %s trust %s match %s kind %s class %s; want %s %s %s %s %s",
				w.entry, w.path, f.Severity, f.Trust.State, f.Match, f.Certificate.Kind, f.Store.Class, w.severity, w.trust, w.match, w.kind, w.class)
		}
		if f.Explanation == "" || f.Remediation == "" {
			t.Errorf("%s in %s: empty explanation or remediation", w.entry, w.path)
		}
		if f.EntryID != "operator-heuristic" && (len(f.References) == 0 || f.EntryName == "") {
			t.Errorf("%s in %s: references/name missing", w.entry, w.path)
		}
	}
	if n := len(res.Findings); n != len(wants) {
		var got []string
		for _, f := range res.Findings {
			got = append(got, fmt.Sprintf("%s:%s(%s)", f.Path, f.EntryID, f.Severity))
		}
		t.Errorf("got %d findings, want %d: %s", n, len(wants), strings.Join(got, "\n"))
	}

	// Details that the table does not cover.
	if f, _ := findingFor(res, "/usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt", "emsign-root-ca-g1"); !equalStrings(f.Aliases, []string{"/etc/ssl/certs/5a4d6896.0", "/etc/ssl/certs/emSign_Root_CA_-_G1.pem"}) || !strings.Contains(f.Trust.Detail, "ca-certificates.conf") {
		t.Errorf("G1 source: aliases %v detail %q", f.Aliases, f.Trust.Detail)
	}
	if f, _ := findingFor(res, "/usr/share/ca-certificates/extra/emSign_Root_CA_-_C1.crt", "emsign-root-ca-c1"); !strings.Contains(f.Trust.Detail, "linked from the OpenSSL certificate directory as /etc/ssl/certs/emSign_Root_CA_-_C1.pem") || f.Store.Class != stores.ClassSystemSource {
		t.Errorf("C1 source trust detail = %q class %s", f.Trust.Detail, f.Store.Class)
	}
	if f, _ := findingFor(res, "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", "emsign-ecc-root-ca-g3"); !strings.Contains(f.Trust.Detail, "deselected") || !strings.Contains(f.Trust.Detail, "stale") || !strings.Contains(f.Remediation, "Run update-ca-certificates") || !strings.Contains(f.Remediation, "apt-get install --only-upgrade ca-certificates") {
		t.Errorf("stale deselected G3 source: detail %q remediation %q", f.Trust.Detail, f.Remediation)
	}
	if f, _ := findingFor(res, "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_C3.crt", "emsign-ecc-root-ca-c3"); !strings.Contains(f.Trust.Detail, "deselected") || strings.Contains(f.Trust.Detail, "stale") || !strings.Contains(f.Remediation, "No action is required") {
		t.Errorf("disabled C3 source: detail %q remediation %q", f.Trust.Detail, f.Remediation)
	}
	if f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3"); !equalStrings(f.Aliases, []string{"/etc/ssl/cert.pem"}) || !strings.Contains(f.Trust.Detail, "explicitly selected by SSL_CERT_FILE") || f.Certificate.SHA256 != blocklist.Default().ByID("emsign-ecc-root-ca-g3").SHA256 || f.Category != blocklist.CategoryAnchor {
		t.Errorf("bundle G3: aliases %v detail %q sha %s category %s", f.Aliases, f.Trust.Detail, f.Certificate.SHA256, f.Category)
	}
	if f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3"); strings.Contains(f.Remediation, "Distrust this CA in every store") || !strings.Contains(f.Remediation, "apt-get install --only-upgrade ca-certificates") || !strings.Contains(f.Remediation, "prefix its line with '!'") {
		t.Errorf("bundle G3 remediation = %q", f.Remediation)
	}
	if f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-root-ca-g1"); !strings.Contains(f.Explanation, "appears again at offset") || f.Remediation != "No action is required for this certificate: it is an eMudhra root that is not known to be compromised." {
		t.Errorf("duplicated G1: explanation %q remediation %q", f.Explanation, f.Remediation)
	}
	if f, _ := findingFor(res, "/usr/local/lib/python3.12/site-packages/certifi/cacert.pem", "emsign-ecc-root-ca-g3"); f.Certificate.Label != "emSign ECC Root CA - G3" || !strings.Contains(f.Remediation, "2026.10.19") || strings.Contains(f.Remediation, "Fixed in Python certifi") {
		t.Errorf("certifi finding: label %q remediation %q", f.Certificate.Label, f.Remediation)
	}
	if f, _ := findingFor(res, "/usr/local/share/ca-certificates/em.crt", "em-dv-tls-ca-g3b"); !strings.Contains(f.Explanation, "issued-by emsign-root-tls-ca-g3") || f.Category != blocklist.CategoryCompromisedKey || !strings.Contains(f.Remediation, "apt-get install --only-upgrade ca-certificates") {
		t.Errorf("intermediate finding: explanation %q category %s remediation %q", f.Explanation, f.Category, f.Remediation)
	}
	if f, _ := findingFor(res, "/opt/java/openjdk/lib/security/cacerts", "emsign-ecc-root-ca-g3"); f.Certificate.Label != "emsigneccrootcag3" || !equalStrings(f.Aliases, []string{"/etc/alternatives/jre-cacerts", "/etc/ssl/certs/java/cacerts", "/usr/lib/jvm/default/lib/security/cacerts"}) || !strings.Contains(f.Remediation, "Fixed in Java/OpenJDK") {
		t.Errorf("cacerts finding: label %q aliases %v remediation %q", f.Certificate.Label, f.Aliases, f.Remediation)
	}
	if f, _ := findingFor(res, "/usr/local/bin/node", "emsign-ecc-root-ca-g3"); !strings.Contains(f.Store.Name, "Node.js") || !strings.Contains(f.Remediation, "22.23.4") || strings.Contains(f.Remediation, "already at a fixed release") {
		t.Errorf("node finding: store %q remediation %q", f.Store.Name, f.Remediation)
	}
	if f, _ := findingFor(res, "/opt/app/bin/server", "aaa-certificate-services"); f.Certificate.SHA256 != "" || f.Certificate.SPKISHA256 != blocklist.Default().ByID("aaa-certificate-services").SPKISHA256 || !strings.Contains(f.Explanation, "bare public key") || !strings.Contains(f.Trust.Detail, "trust-anchor table") || f.Certificate.Subject != fx.aaa.Subject.String() || !f.Certificate.NotAfter.IsZero() {
		t.Errorf("server finding: %+v trust %+v", f.Certificate, f.Trust)
	}
	if f, _ := findingFor(res, "/etc/pki/tls/certs/ca-bundle.trust.crt", "aaa-certificate-services"); !strings.Contains(f.Trust.Detail, "anyExtendedKeyUsage") || f.Certificate.Label != "AAA Certificate Services" {
		t.Errorf("trust bundle finding: detail %q label %q", f.Trust.Detail, f.Certificate.Label)
	}
	if f, _ := findingFor(res, "/etc/pki/tls/certs/ca-bundle.trust.crt", "emsign-ecc-root-ca-g3"); !equalStrings(f.Trust.Purposes, []string{"emailProtection"}) || !strings.Contains(f.Trust.Detail, "trusted for emailProtection only: no exposure") {
		t.Errorf("email-only trust bundle finding: %+v", f.Trust)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Certificate.Subject, "fake.example") || strings.Contains(f.Certificate.Subject, "custom.example") {
			t.Errorf("unexpected finding for %s (issued-by must verify the signature)", f.Certificate.Subject)
		}
		if strings.Contains(f.Certificate.Subject, "Example") {
			t.Errorf("unexpected finding for generated root %s", f.Certificate.Subject)
		}
		if f.Category != blocklist.CategoryRelated && f.Category != blocklist.CategoryIssuedBy && f.Trust.State != TrustDistrusted && f.Trust.State != TrustDisabled && f.EntryID != "operator-heuristic" && strings.Contains(f.Remediation, "Distrust this CA in every store") {
			t.Errorf("%s in %s: the entry's generic paragraph is appended: %q", f.EntryID, f.Path, f.Remediation)
		}
	}

	// Sorted by severity (desc), then path.
	for i := 1; i < len(res.Findings); i++ {
		a, b := res.Findings[i-1], res.Findings[i]
		if a.Severity < b.Severity || a.Severity == b.Severity && a.Path > b.Path {
			t.Errorf("findings not sorted at %d: %s/%s before %s/%s", i, a.Severity, a.Path, b.Severity, b.Path)
		}
	}
	if res.MaxSeverity() != blocklist.SeverityCritical || res.Summary.MaxSeverity != "critical" {
		t.Errorf("max severity %s / %s", res.MaxSeverity(), res.Summary.MaxSeverity)
	}
	wantCounts := map[string]int{"critical": 1, "high": 8, "medium": 0, "low": 4, "info": 4}
	if len(res.Summary.FindingsBySeverity) != 5 {
		t.Errorf("findings_by_severity must carry all five keys: %v", res.Summary.FindingsBySeverity)
	}
	for k, v := range wantCounts {
		if res.Summary.FindingsBySeverity[k] != v {
			t.Errorf("count %s = %d, want %d", k, res.Summary.FindingsBySeverity[k], v)
		}
	}
	// G3, AAA, G1, C1, C3, the intermediate: six distinct certificates (the heuristic one is a seventh).
	if res.Summary.AffectedCertificates != 7 || !res.Summary.SystemBundleFound || res.Summary.PackageDatabase != "dpkg" {
		t.Errorf("summary = %+v", res.Summary)
	}

	// Stores.
	if s, ok := storeFor(res, "/etc/ssl/certs/ca-certificates.crt"); !ok || s.Certificates != 6 || s.Duplicates != 1 || s.Findings != 3 || s.Class != stores.ClassSystemBundle || !equalStrings(s.Aliases, []string{"/etc/ssl/cert.pem"}) {
		t.Errorf("bundle store = %+v (ok %v)", s, ok)
	}
	if s, ok := storeFor(res, "/opt/java/openjdk/lib/security/cacerts"); !ok || s.Certificates != 2 || s.Findings != 1 {
		t.Errorf("cacerts store = %+v (ok %v)", s, ok)
	}
	if s, ok := storeFor(res, "/opt/app/bin/server"); !ok || s.Certificates != 0 || s.Findings != 1 {
		t.Errorf("server store = %+v (ok %v)", s, ok)
	}
	if _, ok := storeFor(res, "/etc/hostname"); ok {
		t.Error("files without certificates must not be listed as stores")
	}

	// Packages.
	pkgs := packagesByKey(res)
	if p := pkgs["dpkg:ca-certificates"]; p.Version != "20230311" || p.FixedVersion != "20250419~deb12u2" || p.Outdated == nil || !*p.Outdated {
		t.Errorf("ca-certificates = %+v", p)
	}
	if p := pkgs["dpkg:openssl"]; p.Version != "3.0.15-1~deb12u1" || p.Outdated != nil {
		t.Errorf("openssl = %+v", p)
	}
	if _, ok := pkgs["dpkg:removed-thing"]; ok {
		t.Error("removed package listed")
	}
	if p := pkgs["pip:certifi"]; p.Version != "2024.8.30" || p.FixedVersion != "2026.10.18" || p.Outdated == nil || !*p.Outdated || p.Path != "/usr/local/lib/python3.12/site-packages/certifi-2024.8.30.dist-info" || !strings.Contains(p.Note, "2026.10.19") {
		t.Errorf("certifi = %+v", p)
	}
	if p := pkgs["pip:certifi (vendored in pip)"]; p.Version != "2024.7.4" || p.Outdated == nil || !*p.Outdated {
		t.Errorf("vendored certifi = %+v", p)
	}
	if p := pkgs["jdk:java (Eclipse Adoptium)"]; p.Version != "17.0.12" || p.FixedVersion != "17.0.21.0.2" || p.Outdated == nil || !*p.Outdated || p.Path != "/opt/java/openjdk" {
		t.Errorf("jdk = %+v", p)
	}
	if p := pkgs["node:node"]; p.Version != "20.18.0" || p.Outdated == nil || !*p.Outdated || p.FixedVersion != "" || !strings.Contains(p.Note, "end-of-life") || p.Reference != "https://nodejs.org/en/about/previous-releases" {
		t.Errorf("node = %+v", p)
	}

	// OS, env hints, warnings, summary.
	if res.OS.ID != "debian" || res.OS.VersionID != "12" || !strings.Contains(res.OS.PrettyName, "bookworm") {
		t.Errorf("os = %+v", res.OS)
	}
	if len(res.EnvHints) != 2 || res.EnvHints[0].Variable != "SSL_CERT_FILE" || !res.EnvHints[0].Default || !res.EnvHints[1].Warning {
		t.Errorf("env hints = %+v", res.EnvHints)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "/opt/app/certs/broken.pem") || !strings.Contains(res.Warnings[0], "rejected by the strict X.509 parser") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if res.Summary.FilesScanned < 25 || res.Summary.BytesScanned < 30000 || res.Summary.CertificatesFound < 20 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if res.Scanner.Name != Name || res.Scanner.Version != "1.2.3" || res.Scanner.BlocklistVersion != blocklist.Default().Version {
		t.Errorf("scanner = %+v", res.Scanner)
	}

	// JSON round trip.
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != len(res.Findings) || back.Findings[0].Severity != res.Findings[0].Severity || back.Findings[0].Store.Class != res.Findings[0].Store.Class {
		t.Errorf("JSON round trip differs")
	}
	if !bytes.Contains(data, []byte(`"severity":"critical"`)) {
		t.Errorf("severity not serialised by name")
	}
	if bytes.Contains(data, []byte(`0001-01-01`)) || bytes.Contains(data, []byte(`"exit"`)) {
		t.Errorf("zero validity or empty exit block serialised: %s", data)
	}
	if !bytes.Contains(data, []byte(`"system_bundle_found":true`)) || !bytes.Contains(data, []byte(`"package_database":"dpkg"`)) {
		t.Errorf("summary fields missing from JSON")
	}
}

func TestOperatorHeuristicOff(t *testing.T) {
	fx := buildFixture(t)
	res := scanTar(t, fx.tar, Options{})
	if _, ok := findingFor(res, "/opt/app/certs/emudhra-test.pem", "operator-heuristic"); ok {
		t.Error("operator heuristic reported although disabled")
	}
	if len(res.EnvHints) != 0 {
		t.Errorf("env hints without env: %v", res.EnvHints)
	}
	if f, _ := findingFor(res, "/etc/ssl/certs/ca-certificates.crt", "emsign-ecc-root-ca-g3"); strings.Contains(f.Trust.Detail, "SSL_CERT_FILE") || f.Trust.State != TrustTrusted {
		t.Errorf("bundle trust without env = %+v", f.Trust)
	}
	if res.Scanner.Version != Version {
		t.Errorf("scanner version = %q, want the package default %q", res.Scanner.Version, Version)
	}
}

func TestIssuedByEntryWithoutCertificate(t *testing.T) {
	fx := buildFixture(t)
	custom, err := blocklist.Load(strings.NewReader(`{"version":"test","entries":[{"id":"custom-fake-ca","name":"Fake Issuer CA","category":"compromised-key","severity":"critical","subject":"CN=Fake Issuer CA,O=Fake Org","sha256":"` + strings.Repeat("ab", 32) + `","notes":"test entry without a certificate","references":["https://example.invalid"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := scanTar(t, fx.tar, Options{Blocklist: blocklist.Default().Merge(custom)})
	f, ok := findingFor(res, "/opt/app/certs/custom-issued.pem", "custom-fake-ca")
	if !ok {
		t.Fatal("issued-by match against an entry without certificate missing")
	}
	if f.Match != blocklist.MatchIssuedBy || f.Severity != blocklist.SeverityMedium || f.Trust.State != TrustUnknown || !strings.Contains(f.Explanation, "issuer name only") || !strings.Contains(f.Remediation, "leaked key") {
		t.Errorf("finding = severity %s match %s trust %s explanation %q", f.Severity, f.Match, f.Trust.State, f.Explanation)
	}
	if f.Category != blocklist.CategoryIssuedBy || f.EntryName != "custom.example" || f.IssuerEntryID != "custom-fake-ca" || f.IssuerEntryName != "Fake Issuer CA" {
		t.Errorf("issued-by finding: category %s entry %q issuer %q/%q", f.Category, f.EntryName, f.IssuerEntryID, f.IssuerEntryName)
	}
	if _, ok := findingFor(res, "/opt/app/certs/fake-leaf.pem", "em-dv-tls-ca-g3b"); ok {
		t.Error("fake leaf matched issued-by although its signature does not verify")
	}
	for _, f := range res.Findings {
		if f.Match != blocklist.MatchIssuedBy && (f.IssuerEntryID != "" || f.Category == blocklist.CategoryIssuedBy) {
			t.Errorf("%s in %s: issuer fields set on a %s match", f.EntryID, f.Path, f.Match)
		}
	}
}

func TestTarEmptyAndMalformed(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		res := scanTar(t, newTar().bytes(), Options{})
		if len(res.Findings) != 0 || res.MaxSeverity() != blocklist.SeverityInfo || res.Summary.MaxSeverity != "" || res.Summary.FilesScanned != 0 {
			t.Errorf("empty result = %+v", res.Summary)
		}
		if res.Findings == nil || res.Stores == nil || res.Packages == nil || res.Warnings == nil || res.EnvHints == nil {
			t.Error("slices must be non-nil for JSON output")
		}
		if res.Summary.SystemBundleFound || res.Summary.PackageDatabase != "none" || len(res.Summary.FindingsBySeverity) != 5 || res.Summary.AffectedCertificates != 0 {
			t.Errorf("empty summary = %+v", res.Summary)
		}
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("max_severity")) || !bytes.Contains(data, []byte(`"critical":0`)) {
			t.Errorf("empty summary JSON = %s", data)
		}
	})
	t.Run("malformed-certificate", func(t *testing.T) {
		b := newTar()
		b.file("etc/ssl/certs/ca-certificates.crt", []byte("-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----\n"+brokenPEM))
		b.file("usr/lib/jvm/lib/security/cacerts", append([]byte{0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 9}, randomBytes(9, 50)...))
		res := scanTar(t, b.bytes(), Options{})
		if len(res.Findings) != 0 {
			t.Errorf("findings = %+v", res.Findings)
		}
		if len(res.Warnings) != 2 {
			t.Errorf("warnings = %v", res.Warnings)
		}
		if s, ok := storeFor(res, "/etc/ssl/certs/ca-certificates.crt"); !ok || s.Certificates != 0 {
			t.Errorf("empty bundle store = %+v (ok %v)", s, ok)
		}
		if res.Summary.SystemBundleFound {
			t.Error("an empty bundle does not count as a system bundle")
		}
	})
	t.Run("truncated-stream", func(t *testing.T) {
		fx := buildFixture(t)
		_, err := Tar(context.Background(), bytes.NewReader(fx.tar[:len(fx.tar)/2]), Options{})
		if err == nil {
			t.Error("truncated stream must fail")
		}
	})
	t.Run("garbage-stream", func(t *testing.T) {
		_, err := Tar(context.Background(), bytes.NewReader(randomBytes(3, 4096)), Options{})
		if err == nil {
			t.Error("garbage stream must fail")
		}
	})
}

// gnuSparseEntry writes an old-GNU sparse entry (typeflag 'S') by hand,
// since archive/tar's writer does not produce them: a hole of hole bytes
// followed by data, with the sparse map in the header.
func gnuSparseEntry(name string, hole int, data []byte) []byte {
	hdr := make([]byte, 512)
	octal := func(off, width, v int) { copy(hdr[off:], fmt.Sprintf("%0*o\x00", width-1, v)) }
	copy(hdr, name)
	copy(hdr[100:], "0000644\x00")
	copy(hdr[108:], "0000000\x00")
	copy(hdr[116:], "0000000\x00")
	octal(124, 12, len(data)) // bytes stored in the archive
	octal(136, 12, 0)
	hdr[156] = 'S'
	copy(hdr[257:], "ustar  \x00")
	octal(386, 12, hole)      // sparse[0].offset
	octal(398, 12, len(data)) // sparse[0].numbytes
	octal(483, 12, hole+len(data))
	copy(hdr[148:], "        ")
	sum := 0
	for _, b := range hdr {
		sum += int(b)
	}
	copy(hdr[148:], fmt.Sprintf("%06o\x00 ", sum))
	out := append(hdr, data...)
	if pad := len(out) % 512; pad != 0 {
		out = append(out, make([]byte, 512-pad)...)
	}
	return append(out, make([]byte, 1024)...)
}

func TestTarSparseEntries(t *testing.T) {
	// A GNU sparse entry reads like a regular file; the certificate after the
	// hole must be found at its logical offset.
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	res := scanTar(t, gnuSparseEntry("opt/sparse/ca.pem", 8192, pemOf(g3)), Options{})
	if f, ok := findingFor(res, "/opt/sparse/ca.pem", "emsign-ecc-root-ca-g3"); !ok || f.Certificate.Offset != 8192 {
		t.Errorf("sparse entry: finding %+v (ok %v)", f.Certificate, ok)
	}
	if res.Summary.FilesScanned != 1 || res.Summary.BytesScanned != int64(8192+len(pemOf(g3))) {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestTarCancellation(t *testing.T) {
	fx := buildFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Tar(ctx, bytes.NewReader(fx.tar), Options{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestResolveLinks(t *testing.T) {
	w := newWalker(context.Background(), Options{})
	w.symlinks["/lib"] = "/usr/lib"
	w.symlinks["/etc/alternatives/cacerts"] = "/lib/jvm/java/lib/security/cacerts"
	w.symlinks["/a"] = "/b"
	w.symlinks["/b"] = "/a"
	w.hardlinks["/etc/ssl/cert.pem"] = "/etc/ssl/certs/ca-certificates.crt"
	w.symlinks["/etc/ssl/certs/x.pem"] = "/etc/ssl/cert.pem"
	cases := map[string]string{
		"/etc/alternatives/cacerts": "/usr/lib/jvm/java/lib/security/cacerts",
		"/lib/x/y":                  "/usr/lib/x/y",
		"/a":                        "",
		"/etc/ssl/certs/x.pem":      "/etc/ssl/certs/ca-certificates.crt",
		"/plain":                    "/plain",
	}
	for in, want := range cases {
		if got := w.resolveLink(in, 0); got != want {
			t.Errorf("resolveLink(%s) = %q, want %q", in, got, want)
		}
	}
	idx := w.aliasIndex()
	if !equalStrings(idx["/etc/ssl/certs/ca-certificates.crt"], []string{"/etc/ssl/cert.pem", "/etc/ssl/certs/x.pem"}) {
		t.Errorf("aliases = %v", idx["/etc/ssl/certs/ca-certificates.crt"])
	}
}

func TestSeverityTable(t *testing.T) {
	bl := blocklist.Default()
	comp := blocklist.Match{Entry: bl.ByID("em-dv-tls-ca-g3b"), Kind: blocklist.MatchFingerprint}
	anchor := blocklist.Match{Entry: bl.ByID("emsign-ecc-root-ca-g3"), Kind: blocklist.MatchFingerprint}
	anchorKey := blocklist.Match{Entry: bl.ByID("emsign-ecc-root-ca-g3"), Kind: blocklist.MatchSPKI}
	related := blocklist.Match{Entry: bl.ByID("emsign-root-ca-g1"), Kind: blocklist.MatchSPKI}
	issuedComp := blocklist.Match{Entry: bl.ByID("em-dv-tls-ca-g3b"), Kind: blocklist.MatchIssuedBy}
	issuedAnchor := blocklist.Match{Entry: bl.ByID("emsign-ecc-root-ca-g3"), Kind: blocklist.MatchIssuedBy}
	issuedRelated := blocklist.Match{Entry: bl.ByID("emsign-root-ca-g1"), Kind: blocklist.MatchIssuedBy}
	operator := blocklist.Match{Kind: blocklist.MatchOperator}
	cases := []struct {
		m        blocklist.Match
		state    string
		purposes []string
		class    stores.Class
		kind     certs.Kind
		want     blocklist.Severity
	}{
		{comp, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityCritical},
		{comp, TrustUnknown, nil, stores.ClassLooseFile, certs.KindPEM, blocklist.SeverityCritical},
		{comp, TrustTrusted, []string{"emailProtection"}, stores.ClassSystemBundle, certs.KindPEMTrusted, blocklist.SeverityCritical},
		{comp, TrustDistrusted, nil, stores.ClassSystemBlocklist, certs.KindPEM, blocklist.SeverityInfo},
		{comp, TrustDistrusted, nil, stores.ClassEmbeddedRuntime, certs.KindSPKI, blocklist.SeverityInfo},
		{comp, TrustDisabled, nil, stores.ClassSystemSource, certs.KindPEM, blocklist.SeverityInfo},
		{anchor, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityHigh},
		{anchor, TrustTrusted, []string{"serverAuth", "clientAuth"}, stores.ClassSystemSource, certs.KindP11Kit, blocklist.SeverityHigh},
		{anchor, TrustTrusted, []string{"codeSigning", "emailProtection"}, stores.ClassSystemBundle, certs.KindPEMTrusted, blocklist.SeverityMedium},
		{anchor, TrustTrusted, []string{"codeSigning"}, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityMedium},
		{anchor, TrustTrusted, []string{"emailProtection"}, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityLow},
		{anchor, TrustTrusted, []string{"clientAuth", "emailProtection"}, stores.ClassSystemSource, certs.KindCertdata, blocklist.SeverityLow},
		{anchor, TrustTrusted, []string{}, stores.ClassSystemBundle, certs.KindPEMTrusted, blocklist.SeverityLow},
		{anchor, TrustEmbedded, nil, stores.ClassEmbeddedRuntime, certs.KindDER, blocklist.SeverityHigh},
		{anchor, TrustEmbedded, nil, stores.ClassEmbeddedBinary, certs.KindDER, blocklist.SeverityMedium},
		{anchorKey, TrustEmbedded, nil, stores.ClassEmbeddedBinary, certs.KindSPKI, blocklist.SeverityHigh},
		{anchor, TrustUnknown, nil, stores.ClassLooseFile, certs.KindPEM, blocklist.SeverityMedium},
		{anchor, TrustUnknown, nil, stores.ClassJavaKeystore, certs.KindJKS, blocklist.SeverityMedium},
		{anchor, TrustUnknown, nil, stores.ClassNSSDB, certs.KindDER, blocklist.SeverityMedium},
		{anchor, TrustDistrusted, nil, stores.ClassSystemBlocklist, certs.KindPEM, blocklist.SeverityInfo},
		{related, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityLow},
		{related, TrustTrusted, []string{"emailProtection"}, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityLow},
		{related, TrustTrusted, []string{}, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityInfo},
		{related, TrustEmbedded, nil, stores.ClassEmbeddedRuntime, certs.KindDER, blocklist.SeverityLow},
		{related, TrustEmbedded, nil, stores.ClassEmbeddedBinary, certs.KindSPKI, blocklist.SeverityLow},
		{related, TrustEmbedded, nil, stores.ClassEmbeddedBinary, certs.KindDER, blocklist.SeverityInfo},
		{related, TrustUnknown, nil, stores.ClassLooseFile, certs.KindPEM, blocklist.SeverityInfo},
		{issuedComp, TrustUnknown, nil, stores.ClassLooseFile, certs.KindPEM, blocklist.SeverityMedium},
		{issuedComp, TrustDistrusted, nil, stores.ClassSystemBlocklist, certs.KindPEM, blocklist.SeverityInfo},
		{issuedAnchor, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityLow},
		{issuedRelated, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityInfo},
		{operator, TrustTrusted, nil, stores.ClassSystemBundle, certs.KindPEM, blocklist.SeverityInfo},
	}
	for i, tc := range cases {
		if got := severityOf(tc.m, TrustInfo{State: tc.state, Purposes: tc.purposes}, tc.class, tc.kind); got != tc.want {
			t.Errorf("case %d (%s %s %v %s %s %s): got %s, want %s", i, tc.m.Kind, tc.state, tc.purposes, tc.class, tc.kind, entryID(tc.m), got, tc.want)
		}
	}
}

func entryID(m blocklist.Match) string {
	if m.Entry == nil {
		return "-"
	}
	return m.Entry.ID
}

func TestPurposeQualifier(t *testing.T) {
	cases := []struct {
		category blocklist.Category
		trust    TrustInfo
		want     string
	}{
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted}, ""},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted, Purposes: []string{"serverAuth", "clientAuth"}}, ""},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted, Purposes: []string{"codeSigning"}}, "trusted for codeSigning only, not for TLS server authentication"},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted, Purposes: []string{"codeSigning", "emailProtection"}}, "trusted for codeSigning, emailProtection only, not for TLS server authentication"},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted, Purposes: []string{"clientAuth", "emailProtection"}}, "trusted for clientAuth, emailProtection only: no exposure to the compromised intermediates"},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustTrusted, Purposes: []string{}}, "trusted for none of the standard purposes"},
		{blocklist.CategoryAnchor, TrustInfo{State: TrustDistrusted, Purposes: []string{"emailProtection"}}, ""},
		{blocklist.CategoryRelated, TrustInfo{State: TrustTrusted, Purposes: []string{"emailProtection"}}, ""},
		{blocklist.CategoryCompromisedKey, TrustInfo{State: TrustTrusted, Purposes: []string{"emailProtection"}}, ""},
	}
	for i, tc := range cases {
		if got := purposeQualifier(tc.category, tc.trust); got != tc.want {
			t.Errorf("case %d: got %q, want %q", i, got, tc.want)
		}
	}
}

func TestCommonName(t *testing.T) {
	cases := map[string]string{
		"CN=fake.example":                            "fake.example",
		"CN=EM DV TLS CA - G3B,O=eMudhra Inc,C=US":   "EM DV TLS CA - G3B",
		"O=Example,CN=Example Root CA 1":             "Example Root CA 1",
		"O=Example\\, Inc,CN=Comma\\, Inc Root,C=US": "Comma, Inc Root",
		"O=No Common Name,C=US":                      "O=No Common Name,C=US",
		"":                                           "",
		"CN=":                                        "",
	}
	for in, want := range cases {
		if got := commonName(in); got != want {
			t.Errorf("commonName(%q) = %q, want %q", in, got, want)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
