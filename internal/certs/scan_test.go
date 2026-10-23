package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestScanPEMBundleWithLabels(t *testing.T) {
	ca1, _ := newCA(t, "Alpha Root")
	ca2, _ := newCA(t, "Beta Root")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	var buf bytes.Buffer
	buf.WriteString("## Bundle of CA Root Certificates\n\n")
	buf.WriteString("# Issuer: CN=Alpha Root\n# Subject: CN=Alpha Root\n# Label: \"Alpha Root\"\n# Serial: 1\n")
	off1 := buf.Len()
	buf.Write(pemOf(ca1))
	buf.WriteString("\nBeta Root\n=========\n")
	off2 := buf.Len()
	buf.Write(pemOf(ca2))
	buf.WriteString("\n")
	off3 := buf.Len()
	buf.Write(pemOf(g3))
	buf.WriteString("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")

	found := ScanBytes(buf.Bytes(), "/etc/ssl/certs/ca-certificates.crt", Options{})
	if len(found) != 3 {
		t.Fatalf("found %d objects, want 3: %v", len(found), subjects(found))
	}
	want := []struct {
		offset int64
		label  string
		cn     string
	}{
		{int64(off1), "Alpha Root", "Alpha Root"},
		{int64(off2), "Beta Root", "Beta Root"},
		{int64(off3), "", "emSign ECC Root CA - G3"},
	}
	for i, w := range want {
		f := found[i]
		if f.Kind != KindPEM || f.Offset != w.offset || f.Label != w.label || f.Certificate.Subject.CommonName != w.cn || f.Trust != TrustUnknown {
			t.Errorf("found[%d] = kind %s offset %d label %q cn %q trust %s; want pem %d %q %q unknown", i, f.Kind, f.Offset, f.Label, f.Certificate.Subject.CommonName, f.Trust, w.offset, w.label, w.cn)
		}
		if !bytes.Equal(f.Raw, f.Certificate.Raw) {
			t.Errorf("found[%d]: Raw differs from Certificate.Raw", i)
		}
	}
	// Raw must not alias the scanned buffer.
	data := buf.Bytes()
	for i := range data {
		data[i] = 0
	}
	if _, err := x509.ParseCertificate(found[0].Raw); err != nil {
		t.Errorf("Raw aliases the input buffer: %v", err)
	}
	if got := ScanPEM(buf.Bytes(), 100); len(got) != 0 {
		t.Errorf("ScanPEM on zeroed data found %d", len(got))
	}
}

func TestScanPEMOffsetsRelativeToBase(t *testing.T) {
	ca, _ := newCA(t, "Base Test")
	data := append([]byte("xx\n"), pemOf(ca)...)
	got := ScanPEM(data, 1000)
	if len(got) != 1 || got[0].Offset != 1003 {
		t.Fatalf("ScanPEM = %+v", got)
	}
}

type certAux struct {
	Trust  []asn1.ObjectIdentifier `asn1:"optional"`
	Reject []asn1.ObjectIdentifier `asn1:"optional,tag:0"`
	Alias  string                  `asn1:"optional,utf8"`
}

func trustedBlock(t *testing.T, c *x509.Certificate, aux *certAux) []byte {
	t.Helper()
	body := append([]byte(nil), c.Raw...)
	if aux != nil {
		der, err := asn1.Marshal(*aux)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, der...)
	}
	return pemEncode("TRUSTED CERTIFICATE", body)
}

func TestTrustedCertificates(t *testing.T) {
	serverAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	email := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	anyEKU := asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	ca, _ := newCA(t, "Trusted One")
	cases := []struct {
		name   string
		aux    *certAux
		trust  TrustState
		detail string
		label  string
	}{
		{"anchor", &certAux{Trust: []asn1.ObjectIdentifier{serverAuth, email}, Alias: "Trusted One alias"}, TrustAnchor, "trust: emailProtection, serverAuth", "Trusted One alias"},
		{"distrusted", &certAux{Reject: []asn1.ObjectIdentifier{anyEKU}}, TrustDistrusted, "reject: anyExtendedKeyUsage", ""},
		{"both", &certAux{Trust: []asn1.ObjectIdentifier{serverAuth}, Reject: []asn1.ObjectIdentifier{email}}, TrustAnchor, "trust: serverAuth; reject: emailProtection", ""},
		{"reject-some", &certAux{Reject: []asn1.ObjectIdentifier{serverAuth}}, TrustNeutral, "reject: serverAuth", ""},
		{"empty-aux", &certAux{}, TrustUnknown, "no trust settings (treated like a plain certificate)", ""},
		{"no-aux", nil, TrustUnknown, "no CertAux trailer", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := trustedBlock(t, ca, tc.aux)
			found := ScanBytes(data, "/etc/pki/tls/certs/ca-bundle.trust.crt", Options{})
			if len(found) != 1 {
				t.Fatalf("found %d, want 1", len(found))
			}
			f := found[0]
			if f.Kind != KindPEMTrusted || f.Trust != tc.trust || f.TrustDetail != tc.detail || f.Label != tc.label {
				t.Errorf("got kind %s trust %s detail %q label %q; want pem-trusted %s %q %q", f.Kind, f.Trust, f.TrustDetail, f.Label, tc.trust, tc.detail, tc.label)
			}
			if !bytes.Equal(f.Raw, ca.Raw) {
				t.Errorf("Raw should be the bare certificate")
			}
		})
	}
	// Garbage trailer: still reported, flagged.
	data := pemEncode("TRUSTED CERTIFICATE", append(append([]byte(nil), ca.Raw...), 0x31, 0x03, 0x01, 0x01, 0xff))
	found := ScanBytes(data, "x", Options{})
	if len(found) != 1 || found[0].TrustDetail != "unparsable CertAux trailer" {
		t.Errorf("garbage trailer: %+v", found)
	}
}

func TestParseCertAuxRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30}, {0x04, 0x01, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x05}, {0x30, 0x80}} {
		if _, _, _, ok := ParseCertAux(b); ok {
			t.Errorf("ParseCertAux(%x) ok", b)
		}
	}
}

func TestPKCS7(t *testing.T) {
	ca, key := newCA(t, "P7 Root")
	leaf := newLeaf(t, "p7.example", ca, key)
	bundle := pkcs7Bundle(ca, leaf)

	t.Run("pem", func(t *testing.T) {
		data := append([]byte("prefix\n"), pemEncode("PKCS7", bundle)...)
		found := ScanBytes(data, "/x/chain.p7b", Options{})
		if got := subjects(found); !reflect.DeepEqual(got, []string{"P7 Root", "p7.example"}) {
			t.Fatalf("subjects = %v", got)
		}
		for _, f := range found {
			if f.Kind != KindPKCS7 || f.Offset != 7 {
				t.Errorf("kind %s offset %d", f.Kind, f.Offset)
			}
		}
	})
	t.Run("der", func(t *testing.T) {
		found := ScanBytes(bundle, "/x/chain.p7b", Options{})
		if got := subjects(found); !reflect.DeepEqual(got, []string{"P7 Root", "p7.example"}) {
			t.Fatalf("subjects = %v", got)
		}
		if found[0].Kind != KindPKCS7 || found[0].Offset <= 0 {
			t.Errorf("found[0] = kind %s offset %d", found[0].Kind, found[0].Offset)
		}
	})
}

func TestCarveDER(t *testing.T) {
	ca, key := newCA(t, "Carved Root")
	leaf := newLeaf(t, "carved.example", ca, key)
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	data := randomBytes(1, 5000)
	data = append(data, ca.Raw...)
	data = append(data, randomBytes(2, 333)...)
	off2 := len(data)
	data = append(data, leaf.Raw...)
	// A corrupted copy must be ignored.
	bad := append([]byte(nil), g3.Raw...)
	bad[6] ^= 0x01 // TBSCertificate length no longer matches: the parse fails
	data = append(data, bad...)
	data = append(data, randomBytes(3, 10)...)
	off3 := len(data)
	data = append(data, g3.Raw...)
	data = append(data, randomBytes(4, 100)...)

	found := CarveDER(data, 10)
	if got := subjects(found); !reflect.DeepEqual(got, []string{"Carved Root", "carved.example", "emSign ECC Root CA - G3"}) {
		t.Fatalf("subjects = %v", got)
	}
	if found[0].Offset != 5010 || found[1].Offset != int64(off2)+10 || found[2].Offset != int64(off3)+10 {
		t.Errorf("offsets = %d %d %d", found[0].Offset, found[1].Offset, found[2].Offset)
	}
	for _, f := range found {
		if f.Kind != KindDER {
			t.Errorf("kind %s", f.Kind)
		}
	}
	// Scan over the same data agrees (ELF header makes it a binary).
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, data...)
	scanned := ScanBytes(elf, "/usr/bin/thing", Options{})
	if got := subjects(scanned); !reflect.DeepEqual(got, []string{"Carved Root", "carved.example", "emSign ECC Root CA - G3"}) {
		t.Fatalf("scan subjects = %v", got)
	}
	if scanned[0].Offset != 5008 {
		t.Errorf("scan offset = %d", scanned[0].Offset)
	}
}

func TestCertCandidateShapes(t *testing.T) {
	ca, _ := newCA(t, "Shape")
	if n, complete, ok := certCandidate(ca.Raw); !ok || !complete || n != len(ca.Raw) {
		t.Errorf("real certificate: %d %v %v", n, complete, ok)
	}
	for _, b := range [][]byte{
		{0x30, 0x82, 0x00, 0x10, 0x30, 0x82},
		append([]byte{0x30, 0x82, 0x01, 0x00, 0x04, 0x82, 0x00, 0x80, 0xa0}, make([]byte, 300)...),
		append([]byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0x80, 0x04}, make([]byte, 300)...),
		append([]byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xff, 0xa0, 0x03, 0x02, 0x01, 0x02}, make([]byte, 300)...), // TBSCertificate fills the whole SEQUENCE: no signature
	} {
		if _, _, ok := certCandidate(b); ok {
			t.Errorf("accepted %x...", b[:min(len(b), 9)])
		}
	}
	// A certificate cut off at the end keeps its shape but is not complete.
	if n, complete, ok := certCandidate(ca.Raw[:len(ca.Raw)-1]); !ok || complete || n != len(ca.Raw) {
		t.Errorf("truncated certificate: %d %v %v", n, complete, ok)
	}
	if n, complete, ok := certCandidate(ca.Raw[:16]); !ok || complete || n != len(ca.Raw) {
		t.Errorf("certificate head: %d %v %v", n, complete, ok)
	}
}

func TestSPKIPatterns(t *testing.T) {
	aaa := blocklistCert(t, "aaa-certificate-services")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	inner := aaa.RawSubjectPublicKeyInfo[4:] // strip SEQUENCE header (two-byte length)
	if aaa.RawSubjectPublicKeyInfo[1] != 0x82 {
		t.Fatal("unexpected SPKI length form")
	}
	data := append([]byte{0x7f, 'E', 'L', 'F'}, randomBytes(7, 3000)...)
	patOff := len(data)
	data = append(data, inner...) // webpki-roots style: bare SPKI
	data = append(data, randomBytes(8, 500)...)
	certOff := len(data)
	data = append(data, g3.Raw...) // a full certificate: its key must be reported once, as the certificate
	data = append(data, randomBytes(9, 200)...)

	found := ScanBytes(data, "/opt/app/bin/server", Options{SPKIPatterns: blocklistPatterns()})
	if len(found) != 2 {
		t.Fatalf("found %d: %v", len(found), subjects(found))
	}
	if f := found[0]; f.Kind != KindSPKI || f.PatternID != "aaa-certificate-services" || f.Offset != int64(patOff) || f.Certificate != nil || !bytes.Equal(f.Raw, inner) {
		t.Errorf("pattern hit = %+v", f)
	}
	if f := found[1]; f.Kind != KindDER || f.Offset != int64(certOff) || f.Certificate.Subject.CommonName != "emSign ECC Root CA - G3" {
		t.Errorf("certificate = kind %s offset %d", f.Kind, f.Offset)
	}
	// Without patterns only the certificate is found.
	if got := ScanBytes(data, "x", Options{}); len(got) != 1 {
		t.Errorf("without patterns: %d", len(got))
	}
	// PEM PUBLIC KEY blocks are decoded and matched too.
	pemData := append(randomText(1, 200), pemEncode("PUBLIC KEY", aaa.RawSubjectPublicKeyInfo)...)
	got := ScanBytes(pemData, "/x/key.pem", Options{SPKIPatterns: blocklistPatterns()})
	if len(got) != 1 || got[0].Kind != KindSPKI || got[0].PatternID != "aaa-certificate-services" || got[0].Offset != 200 {
		t.Errorf("public key block: %+v", got)
	}
}

func TestPatternSetGrouping(t *testing.T) {
	ps := newPatternSet([]SPKIPattern{{ID: "a", Pattern: []byte("0123456789abcdefXXXX")}, {ID: "b", Pattern: []byte("0123456789abcdefYYYY")}, {ID: "c", Pattern: []byte("short")}, {ID: "", Pattern: nil}})
	if len(ps.groups) != 2 {
		t.Fatalf("groups = %d", len(ps.groups))
	}
	data := []byte("..0123456789abcdefYYYY..short..0123456789abcdefXXXX..0123456789abcdefZZZZ")
	var hits []string
	ps.find(data, 0, len(data), func(off int, p SPKIPattern) { hits = append(hits, fmt.Sprintf("%s@%d", p.ID, off)) })
	if want := []string{"b@2", "a@31", "c@24"}; !reflect.DeepEqual(hits, want) {
		t.Errorf("hits = %v, want %v", hits, want)
	}
	hits = nil
	ps.find(data, 3, 31, func(off int, p SPKIPattern) { hits = append(hits, p.ID) })
	if !reflect.DeepEqual(hits, []string{"c"}) {
		t.Errorf("ranged hits = %v", hits)
	}
	if newPatternSet(nil) != nil {
		t.Error("empty set should be nil")
	}
}

// TestWindowBoundaries scans a large file with small windows and checks that
// every object is reported exactly once, with the same offsets as a
// single-window scan.
func TestWindowBoundaries(t *testing.T) {
	ca, key := newCA(t, "Window Root")
	leaf := newLeaf(t, "window.example", ca, key)
	aaa := blocklistCert(t, "aaa-certificate-services")
	inner := aaa.RawSubjectPublicKeyInfo[4:]
	pemCA := pemOf(ca)

	var data []byte
	r := randomBytes(11, 0)
	_ = r
	// Objects every ~1.5 KiB so that every window boundary is straddled by
	// something: PEM text, DER certificates and bare keys in turn.
	for i := 0; i < 400; i++ {
		data = append(data, randomText(int64(i), 700+(i*37)%900)...)
		data = append(data, '\n')
		switch i % 4 {
		case 0:
			data = append(data, "# Label: \"L"+fmt.Sprint(i)+"\"\n"...)
			data = append(data, pemCA...)
		case 1:
			data = append(data, leaf.Raw...)
		case 2:
			data = append(data, inner...)
		case 3:
			data = append(data, randomBytes(int64(i), 300)...)
		}
	}
	opts := Options{SPKIPatterns: blocklistPatterns()}
	want := ScanBytes(data, "/big", opts)
	if n := len(want); n != 300 {
		t.Fatalf("single window found %d objects, want 300", n)
	}
	setWindow(t, 32<<10, 8<<10)
	got, err := Scan(bytes.NewReader(data), "/big", -1, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("windowed scan found %d objects, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Offset != want[i].Offset || got[i].Kind != want[i].Kind || !bytes.Equal(got[i].Raw, want[i].Raw) || got[i].Label != want[i].Label || got[i].PatternID != want[i].PatternID {
			t.Errorf("object %d differs: got %s@%d %q, want %s@%d %q", i, got[i].Kind, got[i].Offset, got[i].Label, want[i].Kind, want[i].Offset, want[i].Label)
		}
	}
	// A declared size that is too small must not lose anything either.
	got, err = Scan(bytes.NewReader(data), "/big", 10, opts)
	if err != nil || len(got) != len(want) {
		t.Errorf("size lie: %d objects, err %v", len(got), err)
	}
	// Nor must a declared size that is too large.
	got, err = Scan(bytes.NewReader(data), "/big", int64(len(data))*2, opts)
	if err != nil || len(got) != len(want) {
		t.Errorf("size overstatement: %d objects, err %v", len(got), err)
	}
}

func TestPEMStraddlingWindowWithLabelContext(t *testing.T) {
	setWindow(t, 8192, 4096)
	ca, _ := newCA(t, "Straddle")
	block := append([]byte("# Label: \"Straddle Label\"\n"), pemOf(ca)...)
	for _, pad := range []int{0, 100, 2000, 4000, 4096 - 30, 4100, 6000, 7000, 8000, 8191, 8192, 8193, 12000, 12280, 12290} {
		data := append(randomText(int64(pad), pad), block...)
		if pad > 0 {
			data[pad-1] = '\n'
		}
		data = append(data, randomText(99, 500)...)
		found, err := Scan(bytes.NewReader(data), "/x", -1, Options{})
		if err != nil || len(found) != 1 || found[0].Offset != int64(pad+len(block)-len(pemOf(ca))) || found[0].Label != "Straddle Label" {
			t.Errorf("pad %d: found %d err %v (%+v)", pad, len(found), err, found)
		}
	}
}

func TestJKS(t *testing.T) {
	ca, key := newCA(t, "JKS Root")
	leaf := newLeaf(t, "jks.example", ca, key)
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	data := writeJKS([]jksEntry{
		{alias: "jks root", cert: ca},
		{alias: "emsign ecc root ca - g3", cert: g3},
		{alias: "server", chain: []*x509.Certificate{leaf, ca}},
	})
	var warnings []string
	found := ScanBytes(data, "/opt/java/openjdk/lib/security/cacerts", Options{Warn: func(m string) { warnings = append(warnings, m) }})
	if got := subjects(found); !reflect.DeepEqual(got, []string{"JKS Root", "emSign ECC Root CA - G3", "jks.example", "JKS Root"}) {
		t.Fatalf("subjects = %v", got)
	}
	for i, f := range found {
		if f.Kind != KindJKS || f.Offset <= 0 {
			t.Errorf("found[%d]: kind %s offset %d", i, f.Kind, f.Offset)
		}
	}
	if found[1].Label != "emsign ecc root ca - g3" || found[2].Label != "server" || found[2].Note == "" || found[0].Note != "" {
		t.Errorf("labels/notes: %q %q %q %q", found[1].Label, found[2].Label, found[2].Note, found[0].Note)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}

	t.Run("truncated", func(t *testing.T) {
		var warnings []string
		found := ScanBytes(data[:len(data)-300], "cacerts", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) < 2 || len(warnings) != 1 || !strings.Contains(warnings[0], "truncated") {
			t.Errorf("found %d warnings %v", len(found), warnings)
		}
		for _, f := range found {
			if f.Certificate.Subject.CommonName == "" {
				t.Error("entry without subject")
			}
		}
	})
	t.Run("too-large", func(t *testing.T) {
		var warnings []string
		found := ScanBytes(data, "cacerts", Options{MaxBuffer: 100, Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 4 || len(warnings) != 1 {
			t.Fatalf("found %d warnings %v", len(found), warnings)
		}
		for _, f := range found {
			if f.Kind != KindDER {
				t.Errorf("kind %s, want carved DER", f.Kind)
			}
		}
	})
}

func TestPKCS12(t *testing.T) {
	ca, _ := newCA(t, "P12 Root")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	certs := []*x509.Certificate{ca, g3}

	cases := []struct {
		name      string
		password  string
		encoder   *pkcs12.Encoder
		passwords []string
		wantNote  string
		wantWarn  bool
		wantN     int
	}{
		{"modern-default-passwords", "changeit", pkcs12.Modern2023, nil, `pkcs12 opened with password "changeit"`, false, 2},
		{"modern-empty-password", "", pkcs12.Modern2023, nil, "pkcs12 opened with an empty password", false, 2},
		{"passwordless", "", pkcs12.Passwordless, nil, "stored unencrypted", false, 2},
		{"legacy", "changeit", pkcs12.Legacy, []string{"nope", "changeit"}, `pkcs12 opened with password "changeit"`, false, 2},
		{"wrong-password", "secret", pkcs12.Modern2023, []string{"", "changeit"}, "", true, 0},
		{"passwordless-any-list", "", pkcs12.Passwordless, []string{"x"}, "stored unencrypted", false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.encoder.EncodeTrustStore(certs, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			var warnings []string
			found := ScanBytes(data, "/etc/pki/java/cacerts", Options{KeystorePasswords: tc.passwords, Warn: func(m string) { warnings = append(warnings, m) }})
			if len(found) != tc.wantN {
				t.Fatalf("found %d (%v), want %d; warnings %v", len(found), subjects(found), tc.wantN, warnings)
			}
			if (len(warnings) > 0) != tc.wantWarn {
				t.Errorf("warnings = %v, wantWarn %v", warnings, tc.wantWarn)
			}
			for _, f := range found {
				if f.Kind != KindPKCS12 || !strings.Contains(f.Note, tc.wantNote) {
					t.Errorf("kind %s note %q", f.Kind, f.Note)
				}
			}
			for _, w := range warnings {
				if strings.Contains(w, "secret") || strings.Contains(w, "changeit") {
					t.Errorf("warning echoes a password: %s", w)
				}
			}
		})
	}
}

func TestCertdata(t *testing.T) {
	ca, _ := newCA(t, "Certdata Root")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	other, _ := newCA(t, "Neutral Root")
	none, _ := newCA(t, "No Trust Object")
	var sb strings.Builder
	sb.WriteString("# This Source Code Form is subject to the terms of the Mozilla Public\n# License\n\nCVS_ID \"@(#) $RCSfile: certdata.txt,v $\"\n\nBEGINDATA\n\n")
	sb.WriteString("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST\nCKA_TOKEN CK_BBOOL CK_TRUE\nCKA_LABEL UTF8 \"Mozilla Builtin Roots\"\n\n")
	sb.WriteString(certdataText(ca, "Certdata Root", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST"))
	g3Off := sb.Len() + len("#\n# Certificate \"emSign ECC Root CA - G3\"\n#\n")
	sb.WriteString(certdataText(g3, "emSign ECC Root CA - G3", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED"))
	sb.WriteString(certdataText(other, "Neutral Root", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST"))
	sb.WriteString(certdataText(none, "No Trust Object", "", "", ""))
	data := []byte(sb.String())

	found := ScanBytes(data, "/usr/share/ca-certificates/mozilla/certdata.txt", Options{SPKIPatterns: blocklistPatterns()})
	if got := subjects(found); !reflect.DeepEqual(got, []string{"Certdata Root", "emSign ECC Root CA - G3", "Neutral Root", "No Trust Object"}) {
		t.Fatalf("subjects = %v", got)
	}
	want := []struct {
		trust  TrustState
		detail string
	}{
		{TrustAnchor, "CKA_TRUST_SERVER_AUTH=CKT_NSS_TRUSTED_DELEGATOR, CKA_TRUST_EMAIL_PROTECTION=CKT_NSS_TRUSTED_DELEGATOR, CKA_TRUST_CODE_SIGNING=CKT_NSS_MUST_VERIFY_TRUST"},
		{TrustDistrusted, "CKA_TRUST_SERVER_AUTH=CKT_NSS_NOT_TRUSTED, CKA_TRUST_EMAIL_PROTECTION=CKT_NSS_NOT_TRUSTED, CKA_TRUST_CODE_SIGNING=CKT_NSS_NOT_TRUSTED"},
		{TrustNeutral, "CKA_TRUST_SERVER_AUTH=CKT_NSS_MUST_VERIFY_TRUST, CKA_TRUST_EMAIL_PROTECTION=CKT_NSS_MUST_VERIFY_TRUST, CKA_TRUST_CODE_SIGNING=CKT_NSS_MUST_VERIFY_TRUST"},
		{TrustNeutral, "no CKO_NSS_TRUST object"},
	}
	for i, w := range want {
		f := found[i]
		if f.Kind != KindCertdata || f.Trust != w.trust || f.TrustDetail != w.detail {
			t.Errorf("found[%d]: kind %s trust %s detail %q", i, f.Kind, f.Trust, f.TrustDetail)
		}
	}
	if found[1].Label != "emSign ECC Root CA - G3" || found[1].Offset != int64(g3Off) || !bytes.Equal(found[1].Raw, g3.Raw) {
		t.Errorf("g3 entry: label %q offset %d (want %d)", found[1].Label, found[1].Offset, g3Off)
	}
	if got := ParseCertdata(data); len(got) != 4 {
		t.Errorf("ParseCertdata = %d", len(got))
	}
}

func TestCertdataAttributeFields(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE", []string{"CKA_CLASS", "CK_OBJECT_CLASS", "CKO_CERTIFICATE"}},
		{"CKA_CLASS\tCK_OBJECT_CLASS\tCKO_CERTIFICATE", []string{"CKA_CLASS", "CK_OBJECT_CLASS", "CKO_CERTIFICATE"}},
		{"CKA_LABEL UTF8 \"Label with  spaces\"", []string{"CKA_LABEL", "UTF8", "\"Label with  spaces\""}},
		{"CKA_VALUE  \t MULTILINE_OCTAL", []string{"CKA_VALUE", "MULTILINE_OCTAL"}},
		{"CKA_X", []string{"CKA_X"}},
	}
	for _, tc := range cases {
		if got := attributeFields(tc.line); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("attributeFields(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestDecodeOctal(t *testing.T) {
	got := decodeOctal([]byte("\\060\\202\\001\n\\377\\0x\\12"))
	if !bytes.Equal(got, []byte{0x30, 0x82, 0x01, 0xff}) {
		t.Errorf("decodeOctal = %x", got)
	}
}

func TestP11Kit(t *testing.T) {
	ca, _ := newCA(t, "P11 Root")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	aaa := blocklistCert(t, "aaa-certificate-services")
	neutral, _ := newCA(t, "Neutral")
	var sb strings.Builder
	sb.WriteString("# This file has been auto-generated\n\n")
	sb.WriteString(p11Object(ca, "P11 Root", "trusted: true", "nss-mozilla-ca-policy: true"))
	sb.WriteString(p11Extension(ca, "P11 Root"))
	sb.WriteString(p11Object(g3, "emSign ECC Root CA - G3", "x-distrusted: true"))
	sb.WriteString(p11Extension(g3, "emSign ECC Root CA - G3")) // key of a certificate in the file: not a separate hit
	sb.WriteString(p11Object(neutral, "Neutral%20Root", "trusted: false"))
	sb.WriteString(p11Extension(aaa, "AAA extension"))
	// The layout p11-kit's own tools write (RHEL ca-bundle.trust.p11-kit):
	// no class attribute, an openssl text dump as comments, distrust-after
	// attributes with escaped values.
	g1 := blocklistCert(t, "emsign-root-ca-g1")
	sb.WriteString("[p11-kit-object-v1]\nlabel: \"emSign Root CA - G1\"\ntrusted: true\nnss-mozilla-ca-policy: true\nmodifiable: false\nnss-server-distrust-after: \"%00\"\nnss-email-distrust-after: \"%00\"\n#Certificate:\n#    Data:\n#        Version: 3 (0x2)\n#        Serial Number: 1 (0x1)\n#        Issuer: C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign Root CA - G1\n")
	sb.Write(pemOf(g1))
	sb.WriteString("\n")
	data := []byte(sb.String())

	found := ScanBytes(data, "/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", Options{SPKIPatterns: blocklistPatterns()})
	if got := subjects(found); !reflect.DeepEqual(got, []string{"P11 Root", "emSign ECC Root CA - G3", "Neutral", "spki:aaa-certificate-services", "emSign Root CA - G1"}) {
		t.Fatalf("subjects = %v", got)
	}
	if f := found[4]; f.Kind != KindP11Kit || f.Trust != TrustAnchor || f.Label != "emSign Root CA - G1" {
		t.Errorf("class-less section: %+v", f)
	}
	// The extension object limits the anchor to the purposes it lists.
	if f := found[0]; f.Kind != KindP11Kit || f.Trust != TrustAnchor || f.TrustDetail != "trusted: true; extended key usage: serverAuth" || f.Label != "P11 Root" ||
		f.Purposes[PurposeServerAuth] != TrustAnchor || f.Purposes[PurposeEmailProtection] != TrustNeutral {
		t.Errorf("found[0] = %+v", f)
	}
	if f := found[4]; f.TrustDetail != "trusted: true" || len(f.Purposes) != 4 || f.Purposes[PurposeEmailProtection] != TrustAnchor {
		t.Errorf("unrestricted anchor: detail %q purposes %v", f.TrustDetail, f.Purposes)
	}
	if f := found[1]; f.Trust != TrustDistrusted || f.TrustDetail != "x-distrusted: true" {
		t.Errorf("found[1] trust %s %q", f.Trust, f.TrustDetail)
	}
	if f := found[2]; f.Trust != TrustNeutral || f.TrustDetail != "trusted: false" || f.Label != "Neutral Root" {
		t.Errorf("found[2] trust %s %q label %q", f.Trust, f.TrustDetail, f.Label)
	}
	if f := found[3]; f.Kind != KindSPKI || f.Label != "AAA extension" || f.PatternID != "aaa-certificate-services" {
		t.Errorf("found[3] = %+v", f)
	}
	if got := ParseP11Kit(data); len(got) != 4 {
		t.Errorf("ParseP11Kit = %d", len(got))
	}
	// Offsets must point at the section's PEM block.
	if !bytes.HasPrefix(data[found[1].Offset:], []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("offset %d does not point at a PEM block", found[1].Offset)
	}
}

func TestLabelBefore(t *testing.T) {
	cases := []struct {
		before string
		want   string
	}{
		{"# Label: \"Foo Bar\"\n# Serial: 1\n", "Foo Bar"},
		{"Foo Bar\n=======\n", "Foo Bar"},
		{"# Comodo AAA Services root\n", "Comodo AAA Services root"},
		{"# Issuer: X\n# Subject: Y\n# Serial: 1\n", ""},
		{"# Serial:\n", ""},
		{"#\n", ""},
		{"-----END CERTIFICATE-----\n\n# emSign ECC Root CA - G3\n", "emSign ECC Root CA - G3"},
		{"Foo Bar\n=======\n\n", "Foo Bar"},
		{"-----END CERTIFICATE-----\n\nFoo Bar\n=======\n", "Foo Bar"},
		{"Foo Bar\n=======\n-----END CERTIFICATE-----\n", ""},
		{"just text\n", ""},
		{"", ""},
		{"# Label: \"Old\"\n-----END CERTIFICATE-----\n", ""},
		// curl's mk-ca-bundle.pl 1.35 writes a fingerprint comment under the underline.
		{"COMODO ECC Certification Authority\n==================================\n# Fingerprint (SHA-256): 17:93:92:7A:06:14\n", "COMODO ECC Certification Authority"},
		{"-----END CERTIFICATE-----\n\nName\n====\n# Fingerprint (SHA-256): 17:93\n\n", "Name"},
		{"# Issuer: X\n# Comodo AAA Services root\n# Serial: 1\n", "Comodo AAA Services root"},
		{"Name\n====\n# Fingerprint (SHA-256): 17:93\nstray text\n", ""},
	}
	for _, tc := range cases {
		data := []byte(tc.before + "-----BEGIN CERTIFICATE-----\n")
		if got := labelBefore(data, len(tc.before)); got != tc.want {
			t.Errorf("labelBefore(%q) = %q, want %q", tc.before, got, tc.want)
		}
	}
}

func TestScanEdgeCases(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		found, err := Scan(bytes.NewReader(nil), "/empty", 0, Options{})
		if err != nil || len(found) != 0 {
			t.Errorf("empty: %v %v", found, err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if found := ScanBytes(randomBytes(5, 200000), "/dev/urandom", Options{SPKIPatterns: blocklistPatterns()}); len(found) != 0 {
			t.Errorf("garbage: %v", found)
		}
	})
	t.Run("read-error", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := Scan(&errReader{data: randomBytes(6, 10), err: boom}, "/x", -1, Options{})
		if !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
		setWindow(t, 8192, 4096)
		_, err = Scan(&errReader{data: randomBytes(6, 20000), err: boom}, "/x", -1, Options{})
		if !errors.Is(err, boom) {
			t.Errorf("err after first window = %v", err)
		}
	})
	t.Run("malformed-pem", func(t *testing.T) {
		// A block that decodes to a sizeable body but not to a certificate is
		// reported; one that does not decode at all, and a truncated one,
		// are not. (A body shorter than 64 bytes is a template, see the
		// "tiny-pem-body" case.)
		var warnings []string
		data := []byte("-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 100) + "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB\n")
		found := ScanBytes(data, "/x.pem", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser") {
			t.Errorf("found %v warnings %v", found, warnings)
		}
	})
	t.Run("tiny-pem-body", func(t *testing.T) {
		// Templates and placeholders in program text are not damaged
		// certificates: no warning for bodies shorter than 64 bytes.
		var warnings []string
		data := []byte("const tpl = \"-----BEGIN CERTIFICATE-----\\n-----END CERTIFICATE-----\\n\"\n-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n")
		found := ScanBytes(data, "/x.go", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 0 || len(warnings) != 0 {
			t.Errorf("found %v warnings %v", found, warnings)
		}
	})
	t.Run("pem-inside-binary-string", func(t *testing.T) {
		ca, _ := newCA(t, "Node Style")
		// Node.js embeds roots as C strings: the block is not at a line start
		// and is followed by a quote on the same line.
		data := append([]byte{0x7f, 'E', 'L', 'F'}, randomBytes(12, 1000)...)
		data = append(data, []byte("\"")...)
		data = append(data, bytes.TrimSuffix(pemOf(ca), []byte("\n"))...)
		data = append(data, []byte("\"\x00\x00")...)
		found := ScanBytes(data, "/usr/local/bin/node", Options{})
		if len(found) != 1 || found[0].Certificate.Subject.CommonName != "Node Style" {
			t.Errorf("found %v", subjects(found))
		}
	})
}

// --- per-purpose trust ------------------------------------------------------

func purposeMap(states ...TrustState) map[Purpose]TrustState {
	out := map[Purpose]TrustState{}
	for i, s := range states {
		out[standardPurposes[i]] = s
	}
	return out
}

func TestTrustFor(t *testing.T) {
	const (
		A = TrustAnchor
		D = TrustDistrusted
		N = TrustNeutral
	)
	cases := []struct {
		name     string
		found    Found
		ask      []Purpose
		want     TrustState
		wantText string
	}{
		{"no purpose information", Found{Trust: N, TrustDetail: "trusted: false"}, []Purpose{PurposeServerAuth}, N, "trusted: false"},
		{"nothing asked", Found{Trust: A, TrustDetail: "trusted: true", Purposes: purposeMap(A, A, A, A)}, nil, A, "trusted: true"},
		{"anchor for an asked purpose", Found{Trust: A, Purposes: purposeMap(A, A, N, N)}, []Purpose{PurposeServerAuth}, A, "trusted for serverAuth, clientAuth"},
		{"anchor for another purpose only", Found{Trust: A, Purposes: purposeMap(N, N, N, A)}, []Purpose{PurposeServerAuth}, N, "trusted for emailProtection only"},
		{"anchor elsewhere and rejected elsewhere", Found{Trust: A, Purposes: purposeMap(N, N, D, A)}, []Purpose{PurposeServerAuth}, N, "trusted for emailProtection only; rejected for codeSigning"},
		{"rejected for every asked purpose", Found{Trust: N, Purposes: purposeMap(D, N, D, N)}, []Purpose{PurposeServerAuth, PurposeCodeSigning}, D, "rejected for serverAuth, codeSigning"},
		{"rejected for one of the asked purposes", Found{Trust: N, Purposes: purposeMap(D, N, N, N)}, []Purpose{PurposeServerAuth, PurposeClientAuth}, N, "not trusted for serverAuth, clientAuth; rejected for serverAuth"},
		{"distrusted as a whole", Found{Trust: D, Purposes: purposeMap(D, D, D, D)}, []Purpose{PurposeEmailProtection}, D, "rejected for every purpose"},
		{"anchor wins over rejection", Found{Trust: A, Purposes: purposeMap(D, N, A, N)}, []Purpose{PurposeServerAuth, PurposeCodeSigning}, A, "trusted for codeSigning"},
		{"neutral everywhere", Found{Trust: N, Purposes: purposeMap(N, N, N, N)}, []Purpose{PurposeServerAuth}, N, "not trusted for serverAuth"},
		{"purpose missing from the map is neutral", Found{Trust: A, Purposes: map[Purpose]TrustState{PurposeEmailProtection: A}}, []Purpose{PurposeClientAuth}, N, "trusted for emailProtection only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, text := tc.found.TrustFor(tc.ask...)
			if got != tc.want || text != tc.wantText {
				t.Errorf("TrustFor(%v) = %s %q, want %s %q", tc.ask, got, text, tc.want, tc.wantText)
			}
		})
	}
}

var (
	oidServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidCodeSigning    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidEmail          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidIPSecEndSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidIPSecTunnel    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidIPSecUser      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidTimeStamping   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidAnyEKU         = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

func TestCertAuxPurposes(t *testing.T) {
	const (
		A = TrustAnchor
		D = TrustDistrusted
		N = TrustNeutral
	)
	ca, _ := newCA(t, "Aux Purposes")
	cases := []struct {
		name          string
		aux           certAux
		trust         TrustState
		purposes      map[Purpose]TrustState
		ask           Purpose
		askState      TrustState
		askText       string
		detailContain string
	}{
		{
			// What p11-kit's bundle writer emits for a blocklisted certificate
			// (the RHEL ca-bundle.trust.crt entry for DigiNotar): every
			// standard purpose rejected, no anyExtendedKeyUsage.
			name:          "p11-kit blocklist reject list",
			aux:           certAux{Reject: []asn1.ObjectIdentifier{oidEmail, oidServerAuth, oidCodeSigning, oidServerAuth, oidClientAuth, oidCodeSigning, oidEmail, oidIPSecEndSystem, oidIPSecTunnel, oidIPSecUser, oidTimeStamping}},
			trust:         D,
			purposes:      purposeMap(D, D, D, D),
			ask:           PurposeServerAuth,
			askState:      D,
			askText:       "rejected for every purpose",
			detailContain: "reject: clientAuth, codeSigning, codeSigning, emailProtection, emailProtection, ipsecEndSystem, ipsecTunnel, ipsecUser, serverAuth, serverAuth, timeStamping",
		},
		{
			// openssl x509 -addtrust emailProtection: OpenSSL rejects every
			// purpose absent from an explicit trust list.
			name:     "e-mail only",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidEmail}},
			trust:    A,
			purposes: purposeMap(D, D, D, A),
			ask:      PurposeServerAuth,
			askState: D,
			askText:  "rejected for serverAuth, clientAuth, codeSigning",
		},
		{
			name:     "e-mail only asked for e-mail",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidEmail}},
			trust:    A,
			purposes: purposeMap(D, D, D, A),
			ask:      PurposeEmailProtection,
			askState: A,
			askText:  "trusted for emailProtection",
		},
		{
			name:     "trust list with a reject list",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidServerAuth, oidClientAuth}, Reject: []asn1.ObjectIdentifier{oidEmail}},
			trust:    A,
			purposes: purposeMap(A, A, D, D),
			ask:      PurposeCodeSigning,
			askState: D,
			askText:  "rejected for codeSigning, emailProtection",
		},
		{
			name:     "reject list only",
			aux:      certAux{Reject: []asn1.ObjectIdentifier{oidServerAuth}},
			trust:    N,
			purposes: purposeMap(D, N, N, N),
			ask:      PurposeClientAuth,
			askState: N,
			askText:  "not trusted for clientAuth; rejected for serverAuth",
		},
		{
			name:     "anyExtendedKeyUsage trusted",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidAnyEKU}},
			trust:    A,
			purposes: purposeMap(A, A, A, A),
			ask:      PurposeCodeSigning,
			askState: A,
			askText:  "trusted for serverAuth, clientAuth, codeSigning, emailProtection",
		},
		{
			name:     "reject anyExtendedKeyUsage wins over trust",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidServerAuth}, Reject: []asn1.ObjectIdentifier{oidAnyEKU}},
			trust:    D,
			purposes: purposeMap(D, D, D, D),
			ask:      PurposeServerAuth,
			askState: D,
			askText:  "rejected for every purpose",
		},
		{
			// Trusted for nothing relevant: not an anchor, not distrusted as
			// a whole, but rejected for every standard purpose.
			name:     "time stamping only",
			aux:      certAux{Trust: []asn1.ObjectIdentifier{oidTimeStamping}},
			trust:    N,
			purposes: purposeMap(D, D, D, D),
			ask:      PurposeServerAuth,
			askState: D,
			askText:  "rejected for serverAuth, clientAuth, codeSigning, emailProtection",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := ScanBytes(trustedBlock(t, ca, &tc.aux), "/etc/pki/tls/certs/ca-bundle.trust.crt", Options{})
			if len(found) != 1 {
				t.Fatalf("found %d, want 1", len(found))
			}
			f := found[0]
			if f.Trust != tc.trust || !reflect.DeepEqual(f.Purposes, tc.purposes) {
				t.Errorf("trust %s purposes %v; want %s %v", f.Trust, f.Purposes, tc.trust, tc.purposes)
			}
			if got, text := f.TrustFor(tc.ask); got != tc.askState || text != tc.askText {
				t.Errorf("TrustFor(%s) = %s %q, want %s %q", tc.ask, got, text, tc.askState, tc.askText)
			}
			if !strings.Contains(f.TrustDetail, tc.detailContain) {
				t.Errorf("detail %q should contain %q", f.TrustDetail, tc.detailContain)
			}
			ca, ok := DecodeCertAux(trustedBlock(t, ca, &tc.aux)[0:0]) // not a CertAux
			if ok || ca.Purposes != nil {
				t.Errorf("DecodeCertAux(empty) = %+v %v", ca, ok)
			}
		})
	}
	// Without settings there is no purpose information at all.
	found := ScanBytes(trustedBlock(t, ca, &certAux{}), "x", Options{})
	if len(found) != 1 || found[0].Purposes != nil || found[0].Trust != TrustUnknown {
		t.Errorf("empty aux: %+v", found)
	}
}

func TestCertdataPurposes(t *testing.T) {
	ca, _ := newCA(t, "Certdata Purposes")
	cases := []struct {
		name                    string
		server, email, code     string
		trust                   TrustState
		purposes                map[Purpose]TrustState
		askServer, askServerTxt string
	}{
		{"not trusted for TLS, anchor for e-mail", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST", TrustAnchor,
			map[Purpose]TrustState{PurposeServerAuth: TrustDistrusted, PurposeEmailProtection: TrustAnchor, PurposeCodeSigning: TrustNeutral}, "distrusted", "rejected for serverAuth"},
		{"not trusted for TLS only", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST", TrustNeutral,
			map[Purpose]TrustState{PurposeServerAuth: TrustDistrusted, PurposeEmailProtection: TrustNeutral, PurposeCodeSigning: TrustNeutral}, "distrusted", "rejected for serverAuth"},
		{"code signing anchor only", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_TRUSTED_DELEGATOR", TrustAnchor,
			map[Purpose]TrustState{PurposeServerAuth: TrustNeutral, PurposeEmailProtection: TrustNeutral, PurposeCodeSigning: TrustAnchor}, "neutral", "trusted for codeSigning only"},
		{"unknown trust", "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_TRUST_UNKNOWN", TrustNeutral,
			map[Purpose]TrustState{PurposeServerAuth: TrustNeutral, PurposeEmailProtection: TrustNeutral, PurposeCodeSigning: TrustNeutral}, "neutral", "not trusted for serverAuth"},
		{"not trusted at all", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED", TrustDistrusted,
			map[Purpose]TrustState{PurposeServerAuth: TrustDistrusted, PurposeEmailProtection: TrustDistrusted, PurposeCodeSigning: TrustDistrusted}, "distrusted", "rejected for every purpose"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("BEGINDATA\n\n" + certdataText(ca, "Certdata Purposes", tc.server, tc.email, tc.code))
			found := ScanBytes(data, "/usr/share/ca-certificates/mozilla/certdata.txt", Options{})
			if len(found) != 1 || found[0].Kind != KindCertdata {
				t.Fatalf("found %+v", found)
			}
			f := found[0]
			if f.Trust != tc.trust || !reflect.DeepEqual(f.Purposes, tc.purposes) {
				t.Errorf("trust %s purposes %v; want %s %v", f.Trust, f.Purposes, tc.trust, tc.purposes)
			}
			if got, text := f.TrustFor(PurposeServerAuth); got.String() != tc.askServer || text != tc.askServerTxt {
				t.Errorf("TrustFor(serverAuth) = %s %q, want %s %q", got, text, tc.askServer, tc.askServerTxt)
			}
			want := "CKA_TRUST_SERVER_AUTH=" + tc.server + ", CKA_TRUST_EMAIL_PROTECTION=" + tc.email + ", CKA_TRUST_CODE_SIGNING=" + tc.code
			if f.TrustDetail != want {
				t.Errorf("detail %q, want %q", f.TrustDetail, want)
			}
		})
	}
	t.Run("no trust object", func(t *testing.T) {
		found := ScanBytes([]byte(certdataText(ca, "Lonely", "", "", "")), "certdata.txt", Options{})
		if len(found) != 1 || found[0].Purposes != nil {
			t.Fatalf("found %+v", found)
		}
		if got, text := found[0].TrustFor(PurposeServerAuth); got != TrustNeutral || text != "no CKO_NSS_TRUST object" {
			t.Errorf("TrustFor = %s %q", got, text)
		}
	})
}

// p11EKUExtension renders an x-certificate-extension section carrying an
// extended-key-usage extension with the given OIDs, keyed by c's public key,
// in the layout of RHEL's ca-bundle.trust.p11-kit.
func p11EKUExtension(t *testing.T, c *x509.Certificate, label string, oids ...asn1.ObjectIdentifier) string {
	t.Helper()
	var list []byte
	for _, oid := range oids {
		der, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, der...)
	}
	extOID, err := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 29, 37})
	if err != nil {
		t.Fatal(err)
	}
	ext := derTLV(0x30, extOID, []byte{0x01, 0x01, 0xff}, derTLV(0x04, derTLV(0x30, list)))
	var value strings.Builder
	for _, b := range ext {
		fmt.Fprintf(&value, "%%%02x", b)
	}
	var sb strings.Builder
	sb.WriteString("[p11-kit-object-v1]\nlabel: \"" + label + "\"\nclass: x-certificate-extension\nobject-id: 2.5.29.37\nvalue: \"" + value.String() + "\"\nmodifiable: false\n")
	sb.Write(pemEncode("PUBLIC KEY", c.RawSubjectPublicKeyInfo))
	sb.WriteString("\n")
	return sb.String()
}

func TestP11KitPurposes(t *testing.T) {
	const (
		A = TrustAnchor
		D = TrustDistrusted
		N = TrustNeutral
	)
	ca, _ := newCA(t, "P11 Purposes")
	other, _ := newCA(t, "Other Key")
	cases := []struct {
		name     string
		file     string
		trust    TrustState
		detail   string
		purposes map[Purpose]TrustState
		ask      Purpose
		askState TrustState
		askText  string
	}{
		{"code signing only, extension before the certificate", p11EKUExtension(t, ca, "P11 Purposes", oidCodeSigning) + p11Object(ca, "P11 Purposes", "trusted: true"),
			A, "trusted: true; extended key usage: codeSigning", purposeMap(N, N, A, N), PurposeServerAuth, N, "trusted for codeSigning only"},
		{"TLS and e-mail, extension after the certificate", p11Object(ca, "P11 Purposes", "trusted: true") + p11EKUExtension(t, ca, "P11 Purposes", oidServerAuth, oidClientAuth, oidEmail),
			A, "trusted: true; extended key usage: serverAuth, clientAuth, emailProtection", purposeMap(A, A, N, A), PurposeServerAuth, A, "trusted for serverAuth, clientAuth, emailProtection"},
		{"anyExtendedKeyUsage", p11Object(ca, "P11 Purposes", "trusted: true") + p11EKUExtension(t, ca, "P11 Purposes", oidAnyEKU),
			A, "trusted: true; extended key usage: serverAuth, clientAuth, codeSigning, emailProtection", purposeMap(A, A, A, A), PurposeCodeSigning, A, "trusted for serverAuth, clientAuth, codeSigning, emailProtection"},
		{"extension for nothing relevant", p11Object(ca, "P11 Purposes", "trusted: true") + p11EKUExtension(t, ca, "P11 Purposes", oidTimeStamping),
			N, "trusted: true; extended key usage: ", purposeMap(N, N, N, N), PurposeServerAuth, N, "not trusted for serverAuth"},
		{"extension of another key does not apply", p11Object(ca, "P11 Purposes", "trusted: true") + p11EKUExtension(t, other, "Other Key", oidCodeSigning),
			A, "trusted: true", purposeMap(A, A, A, A), PurposeServerAuth, A, "trusted for serverAuth, clientAuth, codeSigning, emailProtection"},
		{"distrusted despite an extension", p11Object(ca, "P11 Purposes", "x-distrusted: true") + p11EKUExtension(t, ca, "P11 Purposes", oidServerAuth),
			D, "x-distrusted: true", purposeMap(D, D, D, D), PurposeServerAuth, D, "rejected for every purpose"},
		{"not trusted", p11Object(ca, "P11 Purposes", "trusted: false"),
			N, "trusted: false", purposeMap(N, N, N, N), PurposeServerAuth, N, "not trusted for serverAuth"},
		{"no trust attribute", p11Object(ca, "P11 Purposes"),
			N, "no trusted/x-distrusted attribute", purposeMap(N, N, N, N), PurposeEmailProtection, N, "not trusted for emailProtection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := ScanBytes([]byte(tc.file), "/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", Options{})
			if len(found) != 1 || found[0].Kind != KindP11Kit {
				t.Fatalf("found %+v", found)
			}
			f := found[0]
			if f.Trust != tc.trust || f.TrustDetail != tc.detail || !reflect.DeepEqual(f.Purposes, tc.purposes) {
				t.Errorf("trust %s %q purposes %v; want %s %q %v", f.Trust, f.TrustDetail, f.Purposes, tc.trust, tc.detail, tc.purposes)
			}
			if got, text := f.TrustFor(tc.ask); got != tc.askState || text != tc.askText {
				t.Errorf("TrustFor(%s) = %s %q, want %s %q", tc.ask, got, text, tc.askState, tc.askText)
			}
		})
	}
	t.Run("extension value parsing", func(t *testing.T) {
		for _, bad := range [][]byte{nil, {0x30, 0x00}, derTLV(0x30, []byte{0x06, 0x03, 0x55, 0x1d, 0x1e}, derTLV(0x04, derTLV(0x30)))} {
			if p, ok := extKeyUsagePurposes(bad); ok {
				t.Errorf("accepted %x as %v", bad, p)
			}
		}
	})
}

// --- PEM decoding -----------------------------------------------------------

func TestPEMTrailingBytes(t *testing.T) {
	ca, key := newCA(t, "Trailing")
	leaf := newLeaf(t, "leaf.example", ca, key)
	aux, err := asn1.Marshal(certAux{Trust: []asn1.ObjectIdentifier{oidServerAuth}, Alias: "renamed alias"})
	if err != nil {
		t.Fatal(err)
	}
	withAux := append(append([]byte(nil), ca.Raw...), aux...)
	cases := []struct {
		name     string
		body     []byte
		typ      string
		kind     Kind
		trust    TrustState
		label    string
		note     string
		purposes map[Purpose]TrustState
	}{
		{"DER then an empty SEQUENCE", append(append([]byte(nil), ca.Raw...), 0x30, 0x00), "CERTIFICATE", KindPEM, TrustUnknown, "Trailing", "ignored 2 trailing bytes after the certificate", nil},
		{"DER then NUL padding", append(append([]byte(nil), ca.Raw...), 0, 0, 0), "CERTIFICATE", KindPEM, TrustUnknown, "Trailing", "ignored 3 trailing bytes after the certificate", nil},
		{"two concatenated certificates", append(append([]byte(nil), ca.Raw...), leaf.Raw...), "X509 CERTIFICATE", KindPEM, TrustUnknown, "Trailing", fmt.Sprintf("ignored %d trailing bytes after the certificate", len(leaf.Raw)), nil},
		{"renamed TRUSTED CERTIFICATE", withAux, "CERTIFICATE", KindPEM, TrustAnchor, "renamed alias", "CertAux trust trailer after the certificate (a renamed TRUSTED CERTIFICATE block)", purposeMap(TrustAnchor, TrustDistrusted, TrustDistrusted, TrustDistrusted)},
		{"TRUSTED CERTIFICATE", withAux, "TRUSTED CERTIFICATE", KindPEMTrusted, TrustAnchor, "renamed alias", "", purposeMap(TrustAnchor, TrustDistrusted, TrustDistrusted, TrustDistrusted)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			data := append([]byte("# Trailing\n"), pemEncode(tc.typ, tc.body)...)
			found := ScanBytes(data, "/etc/ssl/certs/x.pem", Options{Warn: func(m string) { warnings = append(warnings, m) }})
			if len(found) != 1 || len(warnings) != 0 {
				t.Fatalf("found %v warnings %v", subjects(found), warnings)
			}
			f := found[0]
			if f.Kind != tc.kind || f.Trust != tc.trust || f.Label != tc.label || f.Note != tc.note || !bytes.Equal(f.Raw, ca.Raw) || f.Offset != int64(len("# Trailing\n")) || !reflect.DeepEqual(f.Purposes, tc.purposes) {
				t.Errorf("got kind %s trust %s label %q note %q offset %d purposes %v", f.Kind, f.Trust, f.Label, f.Note, f.Offset, f.Purposes)
			}
		})
	}
	t.Run("sed-renamed trust bundle", func(t *testing.T) {
		// The common RHEL workaround for tools that cannot read TRUSTED
		// blocks: sed 's/TRUSTED CERTIFICATE/CERTIFICATE/' on ca-bundle.trust.crt.
		g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
		bundle := append(trustedBlock(t, ca, &certAux{Trust: []asn1.ObjectIdentifier{oidServerAuth, oidClientAuth, oidEmail}}),
			trustedBlock(t, g3, &certAux{Reject: []asn1.ObjectIdentifier{oidServerAuth, oidClientAuth, oidCodeSigning, oidEmail}})...)
		renamed := bytes.ReplaceAll(bundle, []byte("TRUSTED CERTIFICATE"), []byte("CERTIFICATE"))
		found := ScanBytes(renamed, "/etc/pki/tls/certs/ca-bundle.crt", Options{})
		if got := subjects(found); !reflect.DeepEqual(got, []string{"Trailing", "emSign ECC Root CA - G3"}) {
			t.Fatalf("subjects = %v", got)
		}
		if found[0].Trust != TrustAnchor || found[1].Trust != TrustDistrusted || found[0].Kind != KindPEM {
			t.Errorf("trust %s %s kind %s", found[0].Trust, found[1].Trust, found[0].Kind)
		}
		if got, _ := found[1].TrustFor(PurposeServerAuth); got != TrustDistrusted {
			t.Errorf("blocklisted certificate: TrustFor(serverAuth) = %s", got)
		}
	})
}

func indent(pem []byte, prefix string) []byte {
	var out []byte
	for _, line := range bytes.Split(bytes.TrimSuffix(pem, []byte("\n")), []byte("\n")) {
		out = append(out, prefix...)
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}

func TestPEMIndentedAndEscaped(t *testing.T) {
	ca, _ := newCA(t, "Indented")
	block := pemOf(ca)
	lines := bytes.Split(bytes.TrimSuffix(block, []byte("\n")), []byte("\n"))
	endOnly := append(bytes.Join(lines[:len(lines)-1], []byte("\n")), []byte("\n    -----END CERTIFICATE-----\n")...)
	cases := []struct {
		name string
		data []byte
	}{
		{"YAML block scalar", append([]byte("tls:\n  caBundle: |-\n"), indent(block, "    ")...)},
		{"tab indentation", indent(block, "\t")},
		{"END marker indented only", endOnly},
		{"Python triple-quoted string", append(append([]byte("def f():\n    CA = \"\"\"\n"), indent(block, "        ")...), []byte("        \"\"\"\n")...)},
		{"JSON string", []byte(`{"ca": "` + strings.ReplaceAll(string(block), "\n", `\n`) + `"}` + "\n")},
		{"JSON string with CRLF escapes", []byte(`{"ca": "` + strings.ReplaceAll(string(block), "\n", `\r\n`) + `"}`)},
		{"CRLF line endings", bytes.ReplaceAll(block, []byte("\n"), []byte("\r\n"))},
		{"single line with spaces", bytes.ReplaceAll(block, []byte("\n"), []byte(" "))},
		{"Go raw string", append(append([]byte("var ca = `\n"), indent(block, "\t\t")...), []byte("`\n")...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			found := ScanBytes(tc.data, "/app/config/values.yaml", Options{Warn: func(m string) { warnings = append(warnings, m) }})
			if len(found) != 1 || len(warnings) != 0 {
				t.Fatalf("found %v warnings %v", subjects(found), warnings)
			}
			f := found[0]
			if f.Kind != KindPEM || !bytes.Equal(f.Raw, ca.Raw) || f.Offset != int64(bytes.Index(tc.data, []byte("-----BEGIN"))) {
				t.Errorf("kind %s offset %d raw ok %v", f.Kind, f.Offset, bytes.Equal(f.Raw, ca.Raw))
			}
			if got := ScanPEM(tc.data, 0); len(got) != 1 {
				t.Errorf("ScanPEM found %d", len(got))
			}
		})
	}
	t.Run("escaped slash", func(t *testing.T) {
		if got, ok := base64Body([]byte("AB\\/CD \\n\\r\\tEF\r\n")); !ok || got != "AB/CDEF" {
			t.Errorf("base64Body = %q %v", got, ok)
		}
		if _, ok := base64Body([]byte("AB\\xCD")); ok {
			t.Error("accepted an unknown escape")
		}
	})
	t.Run("headers keep encoding/pem semantics", func(t *testing.T) {
		data := []byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,PLAIN\n\n" + strings.TrimSuffix(strings.TrimPrefix(string(block), "-----BEGIN CERTIFICATE-----\n"), "-----END CERTIFICATE-----\n") + "-----END CERTIFICATE-----\n")
		if found := ScanBytes(data, "x", Options{}); len(found) != 1 || !bytes.Equal(found[0].Raw, ca.Raw) {
			t.Errorf("found %v", subjects(found))
		}
	})
}

// --- DER shapes -------------------------------------------------------------

func TestNegativeSerialNumber(t *testing.T) {
	ca, _ := newCA(t, "Negative Serial")
	der := bytes.Clone(ca.Raw)
	// 30 82 ll ll | 30 82 ll ll | a0 03 02 01 02 | 02 len serial...
	if der[1] != 0x82 || der[5] != 0x82 || der[13] != 0x02 {
		t.Fatalf("unexpected certificate layout %x", der[:16])
	}
	der[15] |= 0x80 // the serial's first content byte: now a negative INTEGER
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("GODEBUG x509negativeserial=1 is not in effect: %v", err)
	}
	if cert.SerialNumber.Sign() >= 0 {
		t.Fatalf("serial %v is not negative", cert.SerialNumber)
	}
	t.Run("pem", func(t *testing.T) {
		var warnings []string
		found := ScanBytes(pemEncode("TRUSTED CERTIFICATE", der), "/etc/pki/tls/certs/ca-bundle.trust.crt", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 1 || len(warnings) != 0 || found[0].Certificate.SerialNumber.Sign() >= 0 {
			t.Errorf("found %v warnings %v", subjects(found), warnings)
		}
	})
	t.Run("der", func(t *testing.T) {
		data := append(append(randomBytes(21, 777), der...), randomBytes(22, 50)...)
		if found := CarveDER(data, 0); len(found) != 1 || found[0].Offset != 777 {
			t.Errorf("found %+v", found)
		}
	})
}

func TestSmallDERCertificate(t *testing.T) {
	// A minimal EC certificate: 256 to 400 bytes in total, whose
	// TBSCertificate has a one-byte length (30 81 xx).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "tiny"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if der[1] != 0x82 || der[5] != 0x81 {
		t.Fatalf("certificate is %d bytes with length forms %#x/%#x; the test needs a 256..400-byte certificate with a one-byte TBSCertificate length", len(der), der[1], der[5])
	}
	data := append(append(randomBytes(31, 4000), der...), randomBytes(32, 100)...)
	found := CarveDER(data, 0)
	if len(found) != 1 || found[0].Offset != 4000 || found[0].Certificate.Subject.CommonName != "tiny" {
		t.Fatalf("found %+v", found)
	}
	if found := ScanBytes(der, "/x/tiny.der", Options{}); len(found) != 1 {
		t.Errorf("standalone file: found %d", len(found))
	}
	// Version-1 shape too.
	v1 := bytes.Clone(der)
	if n, complete, ok := certCandidate(v1); !ok || !complete || n != len(der) {
		t.Errorf("certCandidate = %d %v %v", n, complete, ok)
	}
}

// --- windows ----------------------------------------------------------------

// bigCertificate returns a certificate carrying an extension of about n
// bytes, so that the DER is far longer than a scan overlap in tests.
func bigCertificate(t *testing.T, n int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(99),
		Subject:         pkix.Name{CommonName: "big extension"},
		NotBefore:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:        time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: randomBytes(41, n)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestLongObjectsAcrossWindows(t *testing.T) {
	setWindow(t, 8192, 4096)
	ca, key := newCA(t, "Long Root")
	var chain []*x509.Certificate
	for i := 0; i < 18; i++ {
		chain = append(chain, newLeaf(t, fmt.Sprintf("leaf%02d.example", i), ca, key))
	}
	p7 := pemEncode("PKCS7", pkcs7Bundle(chain...)) // ~8 KiB: longer than a whole window
	big := bigCertificate(t, 6000)                  // ~6.2 KiB of DER
	if len(p7) <= windowSize || len(big.Raw) <= overlap {
		t.Fatalf("fixtures too small: p7 %d, der %d", len(p7), len(big.Raw))
	}
	for _, pad := range []int{0, 1000, 2047, 2048, 3000, 4000, 4095, 4096, 4097, 6143, 6144, 6145, 7000, 8000, 8191, 8192, 8193, 10000, 12287, 12288, 13000, 20000} {
		t.Run(fmt.Sprintf("pem-pkcs7-at-%d", pad), func(t *testing.T) {
			data := append(randomText(int64(pad), pad), p7...)
			data = append(data, randomText(77, 300)...)
			var warnings []string
			found, err := Scan(bytes.NewReader(data), "/x/chain.p7b", -1, Options{Warn: func(m string) { warnings = append(warnings, m) }})
			if err != nil || len(found) != len(chain) || len(warnings) != 0 {
				t.Fatalf("found %d err %v warnings %v", len(found), err, warnings)
			}
			for i, f := range found {
				if f.Kind != KindPKCS7 || f.Offset != int64(pad) || f.Certificate.Subject.CommonName != chain[i].Subject.CommonName {
					t.Errorf("found[%d] = %s@%d %q", i, f.Kind, f.Offset, f.Certificate.Subject.CommonName)
				}
			}
		})
		t.Run(fmt.Sprintf("der-at-%d", pad), func(t *testing.T) {
			data := append(randomBytes(int64(pad), pad), big.Raw...)
			data = append(data, randomBytes(78, 300)...)
			found, err := Scan(bytes.NewReader(data), "/x/big.der", -1, Options{})
			if err != nil || len(found) != 1 || found[0].Offset != int64(pad) || found[0].Kind != KindDER {
				t.Fatalf("found %+v err %v", found, err)
			}
		})
	}
	t.Run("PEM object longer than MaxBuffer is skipped with a warning", func(t *testing.T) {
		data := append(randomText(5, 5000), p7...)
		data = append(data, randomText(6, 100)...)
		data = append(data, pemOf(ca)...)
		// The limit is sized from the fixture, so that the object never fits.
		limit := int64(len(p7)) - 1
		var warnings []string
		found, err := Scan(bytes.NewReader(data), "/x", -1, Options{MaxBuffer: limit, Warn: func(m string) { warnings = append(warnings, m) }})
		want := []string{fmt.Sprintf("PEM PKCS7 block at offset 5000 has no END marker within %s and was skipped", sizeString(limit))}
		if err != nil || !reflect.DeepEqual(warnings, want) {
			t.Fatalf("err %v warnings %q, want %q", err, warnings, want)
		}
		if got := subjects(found); !reflect.DeepEqual(got, []string{"Long Root"}) {
			t.Errorf("subjects = %v", got)
		}
	})
	t.Run("DER candidate longer than MaxBuffer is skipped with a warning", func(t *testing.T) {
		// With labelContext kept in front of it, the 6 KiB certificate does
		// not fit in a buffer of windowSize bytes.
		data := append(randomText(5, 5000), big.Raw...)
		data = append(data, randomText(6, 100)...)
		data = append(data, pemOf(ca)...)
		var warnings []string
		found, err := Scan(bytes.NewReader(data), "/x", -1, Options{MaxBuffer: int64(windowSize), Warn: func(m string) { warnings = append(warnings, m) }})
		want := []string{fmt.Sprintf("object at offset 5000 is longer than the buffer limit of %d bytes and was skipped", windowSize)}
		if err != nil || !reflect.DeepEqual(warnings, want) {
			t.Fatalf("err %v warnings %q, want %q", err, warnings, want)
		}
		if got := subjects(found); !reflect.DeepEqual(got, []string{"Long Root"}) {
			t.Errorf("subjects = %v", got)
		}
	})
	t.Run("random SEQUENCE headers near the window end", func(t *testing.T) {
		// Every window ends in "30 82 ff ff 30 82 ..." look-alikes: they are
		// retried, found not to be certificates and dropped.
		var data []byte
		for i := 0; i < 20; i++ {
			data = append(data, randomBytes(int64(100+i), 6000)...)
			data = append(data, 0x30, 0x82, 0xff, 0xff, 0x30, 0x82, 0x01, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x02)
			data = append(data, ca.Raw...)
		}
		found, err := Scan(bytes.NewReader(data), "/x", -1, Options{})
		if err != nil || len(found) != 20 {
			t.Fatalf("found %d err %v", len(found), err)
		}
	})
}

// TestPEMBlockPlausibility covers the two checks that decide whether a block
// without an END marker in the buffer is worth completing from a longer one.
func TestPEMBlockPlausibility(t *testing.T) {
	labels := []struct {
		label string
		ok    bool
	}{
		{"CERTIFICATE", true},
		{"TRUSTED CERTIFICATE", true},
		{"X509 CERTIFICATE", true},
		{"PKCS7", true},
		{"PUBLIC KEY", true},
		{"NEW CERTIFICATE REQUEST", true},
		{strings.Repeat("A", 64), true},
		{"", false},
		{"%s", false},
		{"certificate", false},
		{"Certificate", false},
		{" CERTIFICATE", false},
		{"CERTIFICATE\n", false},
		{"X.509 CERTIFICATE", false},
		{"\x00", false},
		{"\xc0\x06", false},
		{"\n\x00\xe4\x01\x01\x0c\x01\x02\x01\x03\x01\x00\nstartsWith", false},
		{strings.Repeat("A", 65), false},
	}
	for _, tc := range labels {
		if got := isPEMLabel([]byte(tc.label)); got != tc.ok {
			t.Errorf("isPEMLabel(%q) = %v, want %v", tc.label, got, tc.ok)
		}
	}
	b64 := strings.Repeat("MIIBfzCCASmgAwIBAgI", 4) // 76 base64 characters
	bodies := []struct {
		body string
		ok   bool
	}{
		{"\n" + b64, true},
		{"\r\n" + b64, true},
		{"  \n" + b64, true},                      // blanks at the end of the BEGIN line
		{"\n    " + b64, true},                    // indented, as in YAML
		{`\n` + b64[:64] + `\n` + b64[64:], true}, // JSON-escaped
		{`\r\n` + b64, true},
		{"\n" + b64[:16], true}, // a short buffer: the bytes present decide
		{"\n" + b64[:40] + "==\n", true},
		{b64, false}, // no line break
		{"", false},
		{"\n", false},
		{"\n" + b64[:15], false}, // too little base64
		{"\nMIIB" + strings.Repeat(" ", 60) + b64, false},
		{"\n\x00-----END CERTIFICATE-----\n", false}, // the next string constant
		{"\nconst header = require(\"fs\");\n", false},
		{"secp224r1secretPRIVATE KEYpkcs1", false},
		{"\n" + string(randomBytes(1, 64)), false},
	}
	for _, tc := range bodies {
		if got := looksLikePEMBody([]byte(tc.body)); got != tc.ok {
			t.Errorf("looksLikePEMBody(%q) = %v, want %v", tc.body, got, tc.ok)
		}
	}
}

// TestStrayPEMMarkers checks the "-----BEGIN " markers that binaries contain
// (the strings are those of deno, node and OpenJDK's lib/modules): printf
// format strings, class constants and neighbours of unrelated constants.
// Only a marker that begins like a real block is completed from a longer
// buffer, and skipped with a warning when the buffer limit is reached; any
// other marker is ignored without growing the window. A certificate later
// in the file is found either way.
func TestStrayPEMMarkers(t *testing.T) {
	setWindow(t, 8192, 4096)
	ca, _ := newCA(t, "After Stray")
	b64 := base64.StdEncoding.EncodeToString(randomBytes(31, 48<<10))
	lines := func(sep string) string { // 64-character lines
		var sb strings.Builder
		for i := 0; i < len(b64); i += 64 {
			sb.WriteString(b64[i:min(i+64, len(b64))])
			sb.WriteString(sep)
		}
		return sb.String()
	}
	const skipped = "PEM %s block at offset 1000 has no END marker within 32 KiB and was skipped"
	cases := []struct {
		name   string
		marker string
		warn   string // the expected warning; "" when the marker is ignored
	}{
		{"deno: neighbouring constants", "-----BEGIN -----BEGIN -----END ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", ""},
		{"node: pem_lib strings", "-----BEGIN \x00-----END \x00Expecting: \x00ANY PRIVATE KEY\x00PKCS #7 SIGNED DATA\x00", ""},
		{"node: printf format", "-----BEGIN %s-----\n\x00-----END %s-----\n\x00application/x-pkcs7-\x00", ""},
		{"lib/modules: class constant", "-----BEGIN \n\x00\xe4\x01\x01\x0c\x01\x02\x01\x03\x01\x00\nstartsWith\x01\x00\x15(Ljava/lang/String;)Z-----END \x08\x01\x0c\x01", ""},
		{"deno: label without line break", "-----BEGIN ENCRYPTED PRIVATE KEY-----secp224r1secretPRIVATE KEYpkcs1", ""},
		{"binary label", "-----BEGIN \xc0\x06-----\n\x00/home/runner/.cargo/registry/src/", ""},
		{"lower-case label", "-----BEGIN certificate-----\n" + lines("\n"), ""},
		{"empty label", "-----BEGIN -----\n" + lines("\n"), ""},
		{"well-formed header, program text", "-----BEGIN CERTIFICATE-----\nconst header = require(\"fs\"); // not a body\n", ""},
		{"well-formed header, binary body", "-----BEGIN CERTIFICATE-----\n" + string(randomBytes(3, 64)), ""},
		{"well-formed header, too little base64", "-----BEGIN CERTIFICATE-----\nMIIB" + strings.Repeat(" ", 80) + "\n", ""},
		{"block without END", "-----BEGIN PKCS7-----\n" + lines("\n"), fmt.Sprintf(skipped, "PKCS7")},
		{"CRLF block without END", "-----BEGIN CERTIFICATE-----\r\n" + lines("\r\n"), fmt.Sprintf(skipped, "CERTIFICATE")},
		{"indented block without END", "-----BEGIN TRUSTED CERTIFICATE-----\n    " + lines("\n    "), fmt.Sprintf(skipped, "TRUSTED CERTIFICATE")},
		{"JSON-escaped block without END", `-----BEGIN CERTIFICATE-----\n` + lines(`\n`), fmt.Sprintf(skipped, "CERTIFICATE")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := append(randomText(8, 1000), tc.marker...)
			data = append(data, randomText(9, 200000)...)
			certAt := len(data)
			data = append(data, pemOf(ca)...)
			data = append(data, randomText(10, 100)...)
			r := &maxReadReader{r: bytes.NewReader(data)}
			var warnings []string
			found, err := Scan(r, "/usr/bin/deno", -1, Options{MaxBuffer: 32 << 10, Warn: func(m string) { warnings = append(warnings, m) }})
			if err != nil || len(found) != 1 || found[0].Offset != int64(certAt) || found[0].Certificate.Subject.CommonName != "After Stray" {
				t.Fatalf("found %v at %v, err %v, warnings %q", subjects(found), offsets(found), err, warnings)
			}
			var want []string
			if tc.warn != "" {
				want = []string{tc.warn}
			}
			if !reflect.DeepEqual(warnings, want) {
				t.Errorf("warnings = %q, want %q", warnings, want)
			}
			if grew := r.max > windowSize; grew != (tc.warn != "") {
				t.Errorf("largest read %d with a window of %d: grew = %v, want %v", r.max, windowSize, grew, tc.warn != "")
			}
		})
	}
}

// TestStrayMarkerInLargeFile is the real-image regression at the default
// window geometry: a stray marker early in a 2 MiB binary must not grow the
// window beyond 1 MiB, and a certificate 1.5 MiB after it is found. The
// mirror case, a marker that begins like a real block, shows that the read
// sizes would reveal growth: there the window grows (to the end of the file,
// so without a warning) and the certificate is found all the same.
func TestStrayMarkerInLargeFile(t *testing.T) {
	if windowSize != 1<<20 || overlap != 64<<10 {
		t.Fatalf("default window geometry expected, have %d/%d", windowSize, overlap)
	}
	ca, _ := newCA(t, "Far Away")
	head, filler, tail := randomText(20, 100<<10), randomText(21, 1536<<10), randomText(22, 100<<10)
	for _, tc := range []struct {
		name   string
		marker string
		grows  bool
	}{
		{"garbage marker", "-----BEGIN \x00-----END \x00Expecting: \x00", false},
		{"marker that begins like a block", "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkG\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(append([]byte{}, head...), tc.marker...)
			data = append(data, filler...)
			certAt := len(data)
			data = append(append(data, pemOf(ca)...), tail...)
			r := &maxReadReader{r: bytes.NewReader(data)}
			var warnings []string
			found, err := Scan(r, "/usr/bin/deno", int64(len(data)), Options{Warn: func(m string) { warnings = append(warnings, m) }})
			if err != nil || len(warnings) != 0 || len(found) != 1 || found[0].Offset != int64(certAt) || found[0].Certificate.Subject.CommonName != "Far Away" {
				t.Fatalf("found %v at %v, err %v, warnings %q", subjects(found), offsets(found), err, warnings)
			}
			if grew := r.max > windowSize; grew != tc.grows {
				t.Errorf("largest read %d with a window of %d: grew = %v, want %v", r.max, windowSize, grew, tc.grows)
			}
		})
	}
}

// TestLargePEMObjectAtDefaultWindowBoundary is the PKCS7 regression at the
// default window geometry: a 172 KiB PEM PKCS7 bundle that starts before a
// window's limit but runs past the window (at offsets 900000 and 985087 of
// a file longer than one window, among others) is completed by moving and
// growing the window, without a warning.
func TestLargePEMObjectAtDefaultWindowBoundary(t *testing.T) {
	if windowSize != 1<<20 || overlap != 64<<10 {
		t.Fatalf("default window geometry expected, have %d/%d", windowSize, overlap)
	}
	ca, key := newCA(t, "Bundle Root")
	var leaves []*x509.Certificate
	for i := 0; i < 40; i++ {
		leaves = append(leaves, newLeaf(t, fmt.Sprintf("leaf%02d.example", i), ca, key))
	}
	var bundle []*x509.Certificate
	var p7 []byte
	for len(p7) < 172<<10 {
		bundle = append(bundle, leaves...)
		p7 = pemEncode("PKCS7", pkcs7Bundle(bundle...))
	}
	limit := windowSize - overlap + labelContext
	for _, pad := range []int{900000, limit - 1, limit, windowSize - len(p7), windowSize - 1} {
		t.Run(fmt.Sprint(pad), func(t *testing.T) {
			data := append(randomText(int64(pad), pad), p7...)
			data = append(data, randomText(7, 300<<10)...)
			var warnings []string
			found, err := Scan(bytes.NewReader(data), "/opt/p7/blob.pem", int64(len(data)), Options{Warn: func(m string) { warnings = append(warnings, m) }})
			if err != nil || len(warnings) != 0 || len(found) != len(bundle) {
				t.Fatalf("found %d of %d, err %v, warnings %q", len(found), len(bundle), err, warnings)
			}
			for i, f := range found {
				if f.Kind != KindPKCS7 || f.Offset != int64(pad) || f.Certificate.Subject.CommonName != bundle[i].Subject.CommonName {
					t.Errorf("found[%d] = %s@%d %q", i, f.Kind, f.Offset, f.Certificate.Subject.CommonName)
				}
			}
		})
	}
}

func TestSniffOnlyLooksAtTheHead(t *testing.T) {
	ca, _ := newCA(t, "Sniffed")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	cases := []struct {
		name string
		data []byte
		kind Kind
	}{
		{"p11-kit marker deep in a binary", append(append(append(append([]byte{0x7f, 'E', 'L', 'F'}, randomBytes(1, 100000)...), p11kitHeader...), randomBytes(2, 10000)...), g3.Raw...), KindDER},
		{"certdata marker deep in a text file", append(append(append(randomText(3, 100000), certdataMarkers[0]...), randomText(4, 10000)...), g3.Raw...), KindDER},
		{"certdata with tab-separated fields", []byte(strings.ReplaceAll(certdataText(g3, "emSign ECC Root CA - G3", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR"), "CKA_CLASS CK_OBJECT_CLASS", "CKA_CLASS\tCK_OBJECT_CLASS")), KindCertdata},
		{"p11-kit header without certificates", append(append([]byte("[p11-kit-object-v1]\nlabel: \"nothing here\"\nclass: data\n"), randomText(5, 1000)...), g3.Raw...), KindDER},
		{"certdata marker with no objects", append([]byte("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST\n"), g3.Raw...), KindDER},
		{"genuine p11-kit file", []byte(p11Object(g3, "emSign ECC Root CA - G3", "trusted: true")), KindP11Kit},
		{"genuine certdata file", []byte(certdataText(g3, "emSign ECC Root CA - G3", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR")), KindCertdata},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := ScanBytes(tc.data, "/x", Options{})
			if len(found) != 1 || found[0].Kind != tc.kind || found[0].Certificate.Subject.CommonName != "emSign ECC Root CA - G3" {
				t.Fatalf("found %+v", found)
			}
		})
	}
	_ = ca
}

func TestWholeFileLargerThanOneWindow(t *testing.T) {
	setWindow(t, 8192, 4096)
	var entries []jksEntry
	var want []string
	for i := 0; i < 40; i++ {
		c, _ := newCA(t, fmt.Sprintf("JKS Root %02d", i))
		entries = append(entries, jksEntry{alias: fmt.Sprintf("root-%02d", i), cert: c})
		want = append(want, c.Subject.CommonName)
	}
	data := writeJKS(entries)
	if len(data) <= 2*windowSize {
		t.Fatalf("keystore is only %d bytes", len(data))
	}
	for _, size := range []int64{int64(len(data)), -1, 100, int64(len(data)) * 3} {
		found, err := Scan(bytes.NewReader(data), "/opt/java/lib/security/cacerts", size, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := subjects(found); !reflect.DeepEqual(got, want) {
			t.Errorf("declared size %d: subjects = %v", size, got)
		}
		for _, f := range found {
			if f.Kind != KindJKS {
				t.Errorf("declared size %d: kind %s", size, f.Kind)
			}
		}
	}
}

// --- PKCS#12 warnings -------------------------------------------------------

func TestPKCS12Warnings(t *testing.T) {
	ca, _ := newCA(t, "P12 Warn")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	certs := []*x509.Certificate{ca, g3}
	const secret = "hunter2-user-password"
	t.Run("wrong passwords give one line without passwords", func(t *testing.T) {
		data, err := pkcs12.Modern2023.EncodeTrustStore(certs, "not-in-the-list")
		if err != nil {
			t.Fatal(err)
		}
		var warnings []string
		found := ScanBytes(data, "/opt/app/keystore.p12", Options{KeystorePasswords: []string{"", "changeit", secret, "x"}, Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 0 || len(warnings) != 1 {
			t.Fatalf("found %d warnings %v", len(found), warnings)
		}
		w := warnings[0]
		if !strings.HasPrefix(w, "pkcs12: none of the 4 supplied passwords opened the file: SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: incorrect password") || strings.Contains(w, "\n") || strings.Contains(w, "keystore:") {
			t.Errorf("warning = %q", w)
		}
		for _, pw := range []string{secret, "not-in-the-list", "changeit"} {
			if strings.Contains(w, pw) {
				t.Errorf("warning echoes %q: %s", pw, w)
			}
		}
	})
	t.Run("user password is referred to by position", func(t *testing.T) {
		data, err := pkcs12.Modern2023.EncodeTrustStore(certs, secret)
		if err != nil {
			t.Fatal(err)
		}
		var warnings []string
		found := ScanBytes(data, "/opt/app/keystore.p12", Options{KeystorePasswords: []string{"", "changeit", "", secret}, Warn: func(m string) { warnings = append(warnings, m) }})
		if len(found) != 2 || len(warnings) != 0 {
			t.Fatalf("found %d warnings %v", len(found), warnings)
		}
		for _, f := range found {
			if f.Note != "pkcs12 opened with supplied password #3" {
				t.Errorf("note = %q", f.Note)
			}
		}
	})
	t.Run("too expensive file is reported and carved", func(t *testing.T) {
		// A password-less store whose MacData asks for 50 million
		// iterations: the MAC is never verified and the certificates are
		// read from the unencrypted SafeContents.
		data, err := pkcs12.Passwordless.EncodeTrustStore(certs, "")
		if err != nil {
			t.Fatal(err)
		}
		type macData struct {
			Mac struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			MacSalt    []byte
			Iterations int
		}
		var pfx struct {
			Version  int
			AuthSafe asn1.RawValue
			MacData  macData `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(data, &pfx); err != nil {
			t.Fatal(err)
		}
		pfx.MacData.Mac.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Parameters: asn1.NullRawValue}
		pfx.MacData.Mac.Digest = make([]byte, 20)
		pfx.MacData.MacSalt = make([]byte, 8)
		pfx.MacData.Iterations = 50_000_000
		data, err = asn1.Marshal(pfx)
		if err != nil {
			t.Fatal(err)
		}
		var warnings []string
		start := time.Now()
		found := ScanBytes(data, "/ks/hang.p12", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if time.Since(start) > 2*time.Second {
			t.Fatal("the MAC was verified")
		}
		if got := subjects(found); !reflect.DeepEqual(got, []string{"P12 Warn", "emSign ECC Root CA - G3"}) || len(warnings) != 0 {
			t.Fatalf("subjects %v warnings %v", got, warnings)
		}
	})
	t.Run("structurally broken file is warned about and carved", func(t *testing.T) {
		data, err := pkcs12.Passwordless.EncodeTrustStore(certs, "")
		if err != nil {
			t.Fatal(err)
		}
		// Retag the authSafe's OCTET STRING as a SEQUENCE, the shape of the
		// fuzzer's hang input.
		oidData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
		p := bytes.Index(data, oidData) + len(oidData)
		if data[p] != 0xa0 {
			t.Fatalf("unexpected layout at %d: %x", p, data[p:p+4])
		}
		if data[p+1]&0x80 != 0 {
			p += 2 + int(data[p+1]&0x7f)
		} else {
			p += 2
		}
		if data[p] != 0x04 {
			t.Fatalf("expected the authSafe OCTET STRING at %d, got %#x", p, data[p])
		}
		data[p] = 0x30
		var warnings []string
		found := ScanBytes(data, "/ks/broken.p12", Options{Warn: func(m string) { warnings = append(warnings, m) }})
		if got := subjects(found); !reflect.DeepEqual(got, []string{"P12 Warn", "emSign ECC Root CA - G3"}) {
			t.Fatalf("subjects %v", got)
		}
		if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "pkcs12: decoding authSafe") {
			t.Errorf("warnings = %v", warnings)
		}
		for _, f := range found {
			if f.Kind != KindDER || f.Note != "carved from a region of the keystore that could not be parsed" {
				t.Errorf("found = kind %s note %q", f.Kind, f.Note)
			}
		}
	})
}
