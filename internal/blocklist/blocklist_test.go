package blocklist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// goDistrustedSPKIHashes is the list Go 1.27.3 / 1.26.10 hard-code in
// crypto/x509 (golang/go#82345, CVE-2026-111943). It is an independent oracle
// for the compromised keys in the embedded data.
var goDistrustedSPKIHashes = []string{
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
}

// Fingerprints published in Mozilla bug 2083449 comment 0 (eMudhra-issued) and
// comment 2 (Sectigo cross-signed).
var mozillaFingerprints = []string{
	"E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838",
	"98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B",
	"42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
	"432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3",
	"CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",
	"0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19",
	"9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4",
	"4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1",
	"579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512",
	"5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699",
	"45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE",
	"FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F",
	"7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489",
	"62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72",
	"A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8",
	"84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD",
}

func TestEmbeddedDataIntegrity(t *testing.T) {
	l := Default()
	if len(l.entries) < 16+4+3 {
		t.Fatalf("expected at least 23 entries, got %d", len(l.entries))
	}
	for _, e := range l.entries {
		if e.Certificate == nil {
			t.Errorf("%s: no certificate parsed", e.ID)
			continue
		}
		fp := sha256.Sum256(e.Certificate.Raw)
		if hex.EncodeToString(fp[:]) != e.SHA256 {
			t.Errorf("%s: sha256 mismatch", e.ID)
		}
		spki := sha256.Sum256(e.Certificate.RawSubjectPublicKeyInfo)
		if hex.EncodeToString(spki[:]) != e.SPKISHA256 {
			t.Errorf("%s: spki mismatch", e.ID)
		}
		if !e.Certificate.IsCA {
			t.Errorf("%s: expected a CA certificate", e.ID)
		}
		if e.Notes == "" || len(e.References) == 0 {
			t.Errorf("%s: notes/references missing", e.ID)
		}
		if e.Category == CategoryCompromisedKey {
			if e.Severity != SeverityCritical {
				t.Errorf("%s: compromised entry must be critical", e.ID)
			}
			if e.Certificate.PublicKeyAlgorithm != x509.ECDSA {
				t.Errorf("%s: compromised keys are P-384 ECDSA", e.ID)
			}
			if k, ok := e.Certificate.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P384() {
				t.Errorf("%s: expected a P-384 key", e.ID)
			}
			if !strings.Contains(e.Certificate.Subject.String(), "eMudhra") {
				t.Errorf("%s: subject %q is not eMudhra", e.ID, e.Certificate.Subject.String())
			}
		}
	}
}

func TestCompromisedKeysMatchGoBlocklist(t *testing.T) {
	l := Default()
	got := map[string]bool{}
	for _, h := range l.CompromisedSPKIHashes() {
		got[hex.EncodeToString(h[:])] = true
	}
	if len(got) != len(goDistrustedSPKIHashes) {
		t.Fatalf("expected %d distinct compromised keys, got %d", len(goDistrustedSPKIHashes), len(got))
	}
	for _, h := range goDistrustedSPKIHashes {
		if !got[h] {
			t.Errorf("Go-distrusted SPKI %s missing from the data set", h)
		}
	}
	n := 0
	for _, e := range l.entries {
		if e.Compromised() {
			n++
		}
	}
	if n != 16 {
		t.Errorf("expected 16 compromised certificates (8 eMudhra-issued + 8 cross-signed), got %d", n)
	}
}

func TestMozillaFingerprintsPresent(t *testing.T) {
	l := Default()
	for _, fp := range mozillaFingerprints {
		e := l.ByFingerprint(fp)
		if e == nil {
			t.Errorf("fingerprint %s from Mozilla bug 2083449 not in the data set", fp)
			continue
		}
		if !e.Compromised() {
			t.Errorf("%s: expected compromised-key, got %s", e.ID, e.Category)
		}
	}
}

func TestAnchorsPresent(t *testing.T) {
	l := Default()
	want := map[string]string{
		"86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
		"d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services",
		"7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d": "emSign Root TLS CA - G3",
		"f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5": "emSign Root CS CA - G3",
	}
	for fp, cn := range want {
		e := l.ByFingerprint(fp)
		if e == nil {
			t.Errorf("anchor %s (%s) missing", cn, fp)
			continue
		}
		if e.Category != CategoryAnchor || e.Severity != SeverityHigh {
			t.Errorf("%s: expected anchor/high, got %s/%s", e.ID, e.Category, e.Severity)
		}
		if e.Certificate.Subject.CommonName != cn {
			t.Errorf("%s: CN %q, want %q", e.ID, e.Certificate.Subject.CommonName, cn)
		}
	}
	for _, id := range []string{"emsign-root-ca-g1", "emsign-root-ca-c1", "emsign-ecc-root-ca-c3"} {
		e := l.ByID(id)
		if e == nil || e.Category != CategoryRelated || e.Severity != SeverityLow {
			t.Errorf("%s: expected related/low entry", id)
		}
	}
}

func TestMatchCertificate(t *testing.T) {
	l := Default()
	// Exact match of an eMudhra-issued compromised intermediate.
	icaDirect := l.ByFingerprint("42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493")
	ms := l.MatchCertificate(icaDirect.Certificate)
	if len(ms) == 0 || ms[0].Kind != MatchFingerprint || ms[0].Entry != icaDirect {
		t.Fatalf("direct ICA: got %+v", ms)
	}
	// It is issued by the anchor emSign Root TLS CA - G3: expect an issued-by relation too.
	var issuedBy []string
	for _, m := range ms[1:] {
		if m.Kind == MatchIssuedBy {
			issuedBy = append(issuedBy, m.Entry.ID)
		}
	}
	if len(issuedBy) != 1 || issuedBy[0] != "emsign-root-tls-ca-g3" {
		t.Errorf("direct ICA issued-by: got %v, want [emsign-root-tls-ca-g3]", issuedBy)
	}
	// Cross-signed variant: exact match to the cross entry; the Sectigo root is its issuer.
	cross := l.ByFingerprint("45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE")
	ms = l.MatchCertificate(cross.Certificate)
	if ms[0].Kind != MatchFingerprint || ms[0].Entry != cross {
		t.Fatalf("cross ICA: got %+v", ms[0])
	}
	foundAAA := false
	for _, m := range ms {
		if m.Kind == MatchIssuedBy && m.Entry.ID == "aaa-certificate-services" {
			foundAAA = true
		}
	}
	if !foundAAA {
		t.Errorf("cross ICA: expected issued-by aaa-certificate-services, got %+v", ms)
	}
}

func TestMatchBySPKIOnly(t *testing.T) {
	l := Default()
	ica := l.ByFingerprint("42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493")
	// Re-wrap the compromised public key in a fresh self-signed certificate: a
	// different fingerprint but the same SPKI must still be recognised.
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "re-issued"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ica.Certificate.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ms := l.MatchCertificate(cert)
	if len(ms) == 0 || ms[0].Kind != MatchSPKI || !ms[0].Entry.Compromised() {
		t.Fatalf("expected spki match to a compromised entry, got %+v", ms)
	}
	if ms[0].Entry.CrossSignedBy != "" {
		t.Errorf("spki match should prefer the eMudhra-issued entry, got %s", ms[0].Entry.ID)
	}
	var sum [32]byte = sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if es := l.MatchSPKIHash(sum); len(es) != 2 {
		t.Errorf("expected 2 entries sharing the key, got %d", len(es))
	}
}

func TestOperatorHeuristic(t *testing.T) {
	l := Default()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "EM Example CA", Organization: []string{"eMudhra Technologies Limited"}, Country: []string{"IN"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	ms := l.MatchCertificate(cert)
	if len(ms) != 1 || ms[0].Kind != MatchOperator || ms[0].Entry != nil {
		t.Fatalf("expected operator heuristic, got %+v", ms)
	}
	tmpl.Subject = pkix.Name{CommonName: "Unrelated", Organization: []string{"Example Corp"}}
	der, _ = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ = x509.ParseCertificate(der)
	if ms := l.MatchCertificate(cert); len(ms) != 0 {
		t.Fatalf("unrelated certificate matched: %+v", ms)
	}
}

func TestSPKIPatterns(t *testing.T) {
	l := Default()
	pats := l.SPKIPatterns()
	distinct := map[string]bool{}
	for _, e := range l.entries {
		distinct[e.SPKISHA256] = true
	}
	if len(pats) != len(distinct) {
		t.Fatalf("expected %d patterns (one per distinct key), got %d", len(distinct), len(pats))
	}
	for _, p := range pats {
		raw := p.Entry.Certificate.RawSubjectPublicKeyInfo
		if !bytes.Contains(raw, p.Pattern) || bytes.Equal(raw, p.Pattern) {
			t.Errorf("%s: pattern must be the SPKI contents without the outer header", p.Entry.ID)
		}
		if p.Pattern[0] != 0x30 {
			t.Errorf("%s: pattern should start with the AlgorithmIdentifier SEQUENCE", p.Entry.ID)
		}
		if !bytes.Contains(p.Entry.Certificate.Raw, p.Pattern) {
			t.Errorf("%s: pattern must also be found inside the full certificate", p.Entry.ID)
		}
	}
}

func TestLoadPEMAndJSON(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Custom Root"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	custom, err := Load(bytes.NewReader(pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(custom.Entries()) != 1 || custom.Entries()[0].Category != CategoryCustom || custom.Entries()[0].Name != "Custom Root" {
		t.Fatalf("unexpected custom list: %+v", custom.Entries())
	}
	merged := Default().Merge(custom)
	cert, _ := x509.ParseCertificate(der)
	if ms := merged.MatchCertificate(cert); len(ms) != 1 || ms[0].Kind != MatchFingerprint {
		t.Fatalf("merged list did not match custom cert: %+v", ms)
	}
	if len(merged.Entries()) != len(Default().Entries())+1 {
		t.Errorf("merge changed entry count unexpectedly")
	}

	jsonDoc := `{"version":"t","entries":[{"id":"x","name":"X","category":"anchor","severity":"medium","sha256":"` +
		strings.Repeat("ab", 32) + `"}]}`
	jl, err := Load(strings.NewReader(jsonDoc))
	if err != nil {
		t.Fatal(err)
	}
	if e := jl.ByFingerprint(strings.Repeat("AB", 32)); e == nil || e.Severity != SeverityMedium {
		t.Fatalf("json entry not indexed: %+v", e)
	}
	if _, err := Load(strings.NewReader(`{"entries":[{"id":"bad","category":"anchor","severity":"high","sha256":"12"}]}`)); err == nil {
		t.Error("expected error for short sha256")
	}
	if _, err := Load(strings.NewReader("garbage")); err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for s := SeverityInfo; s <= SeverityCritical; s++ {
		p, err := ParseSeverity(strings.ToUpper(s.String()))
		if err != nil || p != s {
			t.Errorf("round trip failed for %s", s)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("expected error")
	}
}

func TestIsEmudhraSubject(t *testing.T) {
	cases := []struct {
		n    pkix.Name
		want bool
	}{
		{pkix.Name{Organization: []string{"eMudhra Inc"}}, true},
		{pkix.Name{Organization: []string{"EMUDHRA BV"}}, true},
		{pkix.Name{OrganizationalUnit: []string{"emSign PKI"}}, true},
		{pkix.Name{CommonName: "emSign Root CA - G1"}, true},
		{pkix.Name{CommonName: "emsignature services"}, false},
		{pkix.Name{Organization: []string{"Example"}}, false},
	}
	for _, c := range cases {
		if got := IsEmudhraSubject(c.n); got != c.want {
			t.Errorf("%v: got %v want %v", c.n, got, c.want)
		}
	}
}
