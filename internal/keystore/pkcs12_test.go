package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"emudhra-container-scanner/internal/blocklist"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// --- PKCS#12 test helpers ---------------------------------------------------

// named pairs a certificate with the friendlyName it is stored under.
type named struct {
	alias string
	cert  *x509.Certificate
}

// mustTrustStore encodes a Java-style trust store with go-pkcs12.
func mustTrustStore(t *testing.T, enc *pkcs12.Encoder, password string, certs ...named) []byte {
	t.Helper()
	entries := make([]pkcs12.TrustStoreEntry, 0, len(certs))
	for _, c := range certs {
		entries = append(entries, pkcs12.TrustStoreEntry{Cert: c.cert, FriendlyName: c.alias})
	}
	data, err := enc.EncodeTrustStoreEntries(entries, password)
	if err != nil {
		t.Fatalf("encoding trust store: %v", err)
	}
	return data
}

// mustChain encodes a private key with its certificate chain with go-pkcs12.
func mustChain(t *testing.T, enc *pkcs12.Encoder, password string, key *ecdsa.PrivateKey, leaf *x509.Certificate, cas ...*x509.Certificate) []byte {
	t.Helper()
	data, err := enc.Encode(key, leaf, cas, password)
	if err != nil {
		t.Fatalf("encoding chain: %v", err)
	}
	return data
}

// makeCertBag builds a CertBag SafeBag with optional friendlyName and
// localKeyId attributes but without Java's trust attribute.
func makeCertBag(t *testing.T, der []byte, friendlyName string, localKeyID []byte) safeBag {
	t.Helper()
	return makeBag(t, oidCertBag, certBag{ID: oidCertTypeX509, Data: der}, friendlyName, localKeyID)
}

func makeBag(t *testing.T, bagType asn1.ObjectIdentifier, value any, friendlyName string, localKeyID []byte) safeBag {
	t.Helper()
	inner, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshaling bag value: %v", err)
	}
	bag := safeBag{ID: bagType, Value: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}}
	if friendlyName != "" {
		var bmp []byte
		for _, u := range utf16.Encode([]rune(friendlyName)) {
			bmp = append(bmp, byte(u>>8), byte(u))
		}
		v, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBMPString, Bytes: bmp})
		if err != nil {
			t.Fatal(err)
		}
		bag.Attributes = append(bag.Attributes, pkcs12Attribute{ID: oidFriendlyName,
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	}
	if localKeyID != nil {
		v, err := asn1.Marshal(localKeyID)
		if err != nil {
			t.Fatal(err)
		}
		bag.Attributes = append(bag.Attributes, pkcs12Attribute{ID: oidLocalKeyID,
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	}
	return bag
}

// plainContent wraps bags in an unencrypted (data) SafeContents.
func plainContent(t *testing.T, bags []safeBag) contentInfo {
	t.Helper()
	der, err := asn1.Marshal(bags)
	if err != nil {
		t.Fatalf("marshaling SafeContents: %v", err)
	}
	octets, err := asn1.Marshal(der)
	if err != nil {
		t.Fatal(err)
	}
	return contentInfo{ContentType: oidDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octets}}
}

// buildPFX assembles a PFX without MAC from a list of SafeContents.
func buildPFX(t *testing.T, contents []contentInfo) []byte {
	t.Helper()
	authSafe, err := asn1.Marshal(contents)
	if err != nil {
		t.Fatalf("marshaling AuthenticatedSafe: %v", err)
	}
	octets, err := asn1.Marshal(authSafe)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pfxPDU{Version: 3, AuthSafe: contentInfo{ContentType: oidDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octets}}})
	if err != nil {
		t.Fatalf("marshaling PFX: %v", err)
	}
	return der
}

// contentsOf returns the SafeContents list of an existing file so tests can
// splice files together.
func contentsOf(t *testing.T, data []byte) []contentInfo {
	t.Helper()
	p, err := parsePFX(data)
	if err != nil {
		t.Fatalf("parsePFX: %v", err)
	}
	return p.contents
}

// --- LooksLikePKCS12 --------------------------------------------------------

func TestLooksLikePKCS12(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	leaf, key := newTestCert(t, "leaf")
	var many []named
	for i := 0; i < 170; i++ {
		c, _ := newTestCert(t, fmt.Sprintf("filler certificate number %03d for the large store", i))
		many = append(many, named{alias: fmt.Sprintf("filler-%03d", i), cert: c})
	}
	large := mustTrustStore(t, pkcs12.Passwordless, "", many...)
	if len(large) <= 0xFFFF || large[1] != 0x83 {
		t.Fatalf("large store is %d bytes with length byte %#x; want > 65535 bytes and a 3-byte length", len(large), large[1])
	}
	jks := writeJKS(magicJKS, 2, []jksEntry{{tag: jksTagTrustedCert, alias: "a", certs: []jksCert{{der: root.Raw}}}})

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"Modern trust store", mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root}), true},
		{"Passwordless trust store", mustTrustStore(t, pkcs12.Passwordless, "", named{"root", root}), true},
		{"Legacy key chain", mustChain(t, pkcs12.Legacy, "changeit", key, leaf, root), true},
		{"large store with 3-byte length", large, true},
		{"synthetic 4-byte length", []byte{0x30, 0x84, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x03, 0x30, 0x84, 0x00, 0xff, 0xff, 0xf0}, true},
		{"indefinite BER length", []byte{0x30, 0x80, 0x02, 0x01, 0x03, 0x30, 0x80}, true},
		{"empty", nil, false},
		{"lone SEQUENCE tag", []byte{0x30}, false},
		{"declared length too short for a PFX", []byte{0x30, 0x03, 0x02, 0x01, 0x03}, false},
		{"version 2", []byte{0x30, 0x06, 0x02, 0x01, 0x02, 0x30, 0x01, 0x00}, false},
		{"INTEGER of wrong size", []byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x03, 0x30, 0x01, 0x00}, false},
		{"OCTET STRING instead of ContentInfo", []byte{0x30, 0x06, 0x02, 0x01, 0x03, 0x04, 0x01, 0x00}, false},
		{"five-byte length", []byte{0x30, 0x85, 0, 0, 0, 0, 1, 0x02, 0x01, 0x03, 0x30}, false},
		{"long-form length cut short", []byte{0x30, 0x82, 0x01}, false},
		{"PEM", pemOf(root), false},
		{"JKS", jks, false},
		{"ELF", elfHeader, false},
		{"DER certificate", root.Raw, false},
		{"DER private key", mustPKCS8(t, key), false},
		{"random", randomBytes(3, 1024), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikePKCS12(tc.data); got != tc.want {
				t.Errorf("LooksLikePKCS12 = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("large store parses", func(t *testing.T) {
		got, err := ParsePKCS12(large, []string{""})
		if err != nil {
			t.Fatalf("ParsePKCS12: %v", err)
		}
		if len(got) != len(many) {
			t.Fatalf("got %d entries, want %d", len(got), len(many))
		}
		for i, c := range many {
			checkEntry(t, got[i], c.alias, c.cert.Raw, false, false, 0)
		}
	})
}

func mustPKCS8(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// --- ParsePKCS12 ------------------------------------------------------------

var trustStoreEncoders = []struct {
	name      string
	enc       *pkcs12.Encoder
	password  string
	encrypted bool
}{
	{"Modern2023", pkcs12.Modern2023, "changeit", true},
	{"Modern2026", pkcs12.Modern2026, "changeit", true},
	{"LegacyDES", pkcs12.LegacyDES, "changeit", true},
	{"LegacyRC2", pkcs12.LegacyRC2, "changeit", true},
	{"Modern with empty password", pkcs12.Modern, "", true},
	{"Passwordless", pkcs12.Passwordless, "", false},
}

func TestParsePKCS12_TrustStores(t *testing.T) {
	self, _ := newTestCert(t, "self-signed test")
	certs := []named{
		{"emsign ecc root ca - g3", blocklistCert(t, "emsign-ecc-root-ca-g3")},
		{"aaa certificate services", blocklistCert(t, "aaa-certificate-services")},
		{"self", self},
	}
	for _, tc := range trustStoreEncoders {
		t.Run(tc.name, func(t *testing.T) {
			data := mustTrustStore(t, tc.enc, tc.password, certs...)
			got, err := ParsePKCS12(data, []string{"", "changeit"})
			if err != nil {
				t.Fatalf("ParsePKCS12: %v", err)
			}
			if len(got) != len(certs) {
				t.Fatalf("got %d entries, want %d", len(got), len(certs))
			}
			for i, c := range certs {
				checkEntry(t, got[i], c.alias, c.cert.Raw, false, tc.encrypted, 0)
			}
			expectBlocklistHit(t, got[0], "emsign-ecc-root-ca-g3")
			expectBlocklistHit(t, got[1], "aaa-certificate-services")

			// Duplicates and extra wrong passwords change nothing; the first
			// password that opens the file wins.
			again, err := ParsePKCS12(data, []string{"wrong", tc.password, "changeit", tc.password, ""})
			if err != nil {
				t.Fatalf("ParsePKCS12 with extra passwords: %v", err)
			}
			if len(again) != len(got) {
				t.Fatalf("got %d entries with extra passwords, want %d", len(again), len(got))
			}
			for i := range got {
				if again[i].Alias != got[i].Alias || !bytes.Equal(again[i].Raw, got[i].Raw) {
					t.Errorf("entry %d differs between password lists", i)
				}
			}
		})
	}
}

func TestParsePKCS12_KeyChains(t *testing.T) {
	leaf, key := newTestCert(t, "leaf.example")
	intermediate := blocklistCert(t, "em-dv-tls-ca-g3b")
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	spki := sha256.Sum256(intermediate.RawSubjectPublicKeyInfo)
	var pattern []byte
	for _, p := range blocklist.Default().SPKIPatterns() {
		if p.Entry.SPKISHA256 == hex.EncodeToString(spki[:]) {
			pattern = p.Pattern
		}
	}
	if pattern == nil {
		t.Fatal("blocklist has no SPKI pattern for em-dv-tls-ca-g3b")
	}

	encoders := []struct {
		name      string
		enc       *pkcs12.Encoder
		password  string
		encrypted bool
	}{
		{"Modern", pkcs12.Modern, "changeit", true},
		{"Legacy", pkcs12.Legacy, "changeit", true},
		{"LegacyRC2", pkcs12.LegacyRC2, "changeit", true},
		{"Passwordless", pkcs12.Passwordless, "", false},
	}
	for _, tc := range encoders {
		t.Run(tc.name, func(t *testing.T) {
			data := mustChain(t, tc.enc, tc.password, key, leaf, intermediate, root)
			got, err := ParsePKCS12(data, []string{"", "changeit"})
			if err != nil {
				t.Fatalf("ParsePKCS12: %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("got %d entries, want 3", len(got))
			}
			// Encoder.Encode writes no friendlyName, so aliases are empty.
			checkEntry(t, got[0], "", leaf.Raw, true, tc.encrypted, 0)
			checkEntry(t, got[1], "", intermediate.Raw, true, tc.encrypted, 0)
			checkEntry(t, got[2], "", root.Raw, true, tc.encrypted, 0)
			expectBlocklistHit(t, got[1], "em-dv-tls-ca-g3b")
			if !bytes.Contains(got[1].Raw, pattern) {
				t.Error("the compromised intermediate's DER should contain the blocklist SPKI pattern")
			}
		})
	}
}

func TestParsePKCS12_WrongPassword(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	leaf, key := newTestCert(t, "leaf")
	store := mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root})
	chain := mustChain(t, pkcs12.Legacy, "changeit", key, leaf, root)

	tests := []struct {
		name      string
		data      []byte
		passwords []string
		wantMsgs  []string
	}{
		{"no passwords", store, nil, []string{"no passwords were supplied", "SafeContents #0 (encrypted, PBES2 with AES-256-CBC)"}},
		{"wrong passwords", store, []string{"", "wrong"}, []string{"none of the 2 supplied passwords", "SafeContents #0 (encrypted, PBES2 with AES-256-CBC)", "incorrect password"}},
		{"wrong password for a key chain", chain, []string{"wrong"}, []string{"none of the 1 supplied passwords", "SafeContents #0 (encrypted, pbeWithSHA1And3-KeyTripleDES-CBC)"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePKCS12(tc.data, tc.passwords)
			if err == nil {
				t.Fatal("expected an error")
			}
			if len(got) != 0 {
				t.Errorf("got %d entries, want none", len(got))
			}
			if errors.Is(err, ErrFormat) {
				t.Errorf("a valid PFX with the wrong password must not be ErrFormat: %v", err)
			}
			for _, m := range tc.wantMsgs {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("error %q should mention %q", err, m)
				}
			}
		})
	}
}

func TestParsePKCS12_UnencryptedBagFallback(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	self, _ := newTestCert(t, "self")

	t.Run("certificates without Java trust attribute", func(t *testing.T) {
		// Neither DecodeTrustStore (no trust attribute) nor DecodeChain (no
		// key) accepts this file; the bags are still readable.
		data := buildPFX(t, []contentInfo{plainContent(t, []safeBag{
			makeCertBag(t, root.Raw, "emsign root", nil),
			makeCertBag(t, self.Raw, "self", nil),
		})})
		for _, passwords := range [][]string{nil, {""}, {"changeit"}, {"changeit", ""}} {
			got, err := ParsePKCS12(data, passwords)
			if err != nil {
				t.Fatalf("passwords %q: %v", passwords, err)
			}
			if len(got) != 2 {
				t.Fatalf("passwords %q: got %d entries, want 2", passwords, len(got))
			}
			checkEntry(t, got[0], "emsign root", root.Raw, false, false, 0)
			checkEntry(t, got[1], "self", self.Raw, false, false, 0)
			expectBlocklistHit(t, got[0], "emsign-ecc-root-ca-g3")
		}
	})

	t.Run("odd bags are skipped or reported", func(t *testing.T) {
		sdsi := makeBag(t, oidCertBag, certBag{ID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}, Data: []byte("sdsi")}, "sdsi", nil)
		garbage := makeCertBag(t, randomBytes(4, 120), "garbage", nil)
		secret := makeBag(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}, []byte("secret"), "secret", nil)
		nested := makeBag(t, oidSafeContentsBag, []safeBag{makeCertBag(t, self.Raw, "nested", nil)}, "", nil)
		data := buildPFX(t, []contentInfo{plainContent(t, []safeBag{
			makeCertBag(t, root.Raw, "root", nil), sdsi, garbage, secret, nested,
		})})
		got, err := ParsePKCS12(data, []string{""})
		if err == nil || !strings.Contains(err.Error(), "SafeContents #0: certificate bag 2") {
			t.Fatalf("err = %v, want a complaint about certificate bag 2", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
		checkEntry(t, got[0], "root", root.Raw, false, false, 0)
		checkEntry(t, got[1], "nested", self.Raw, false, false, 0)
	})

	t.Run("encrypted and unencrypted SafeContents side by side", func(t *testing.T) {
		encrypted := contentsOf(t, mustTrustStore(t, pkcs12.Modern, "secret", named{"encrypted root", root}))
		data := buildPFX(t, []contentInfo{encrypted[0], plainContent(t, []safeBag{makeCertBag(t, self.Raw, "plain self", nil)})})

		got, err := ParsePKCS12(data, []string{"", "changeit"})
		if err == nil {
			t.Fatal("expected an error for the undecryptable SafeContents")
		}
		for _, m := range []string{"SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read", "incorrect password", "none of the 2 supplied passwords"} {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("error %q should mention %q", err, m)
			}
		}
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1", len(got))
		}
		checkEntry(t, got[0], "plain self", self.Raw, false, false, 0)

		// With the right password the fallback decrypts the first part too;
		// go-pkcs12 itself rejects the file (two SafeContents, no MAC).
		got, err = ParsePKCS12(data, []string{"secret"})
		if err != nil {
			t.Fatalf("ParsePKCS12 with the right password: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
		checkEntry(t, got[0], "encrypted root", root.Raw, false, true, 0)
		checkEntry(t, got[1], "plain self", self.Raw, false, false, 0)
	})

	t.Run("keystore with two private keys", func(t *testing.T) {
		leaf1, key1 := newTestCert(t, "leaf-1")
		leaf2, key2 := newTestCert(t, "leaf-2")
		var contents []contentInfo
		contents = append(contents, contentsOf(t, mustChain(t, pkcs12.Modern, "changeit", key1, leaf1, root))...)
		contents = append(contents, contentsOf(t, mustChain(t, pkcs12.LegacyRC2, "changeit", key2, leaf2, root))...)
		data := buildPFX(t, contents)

		got, err := ParsePKCS12(data, []string{"changeit"})
		if err != nil {
			t.Fatalf("ParsePKCS12: %v", err)
		}
		if len(got) != 4 {
			t.Fatalf("got %d entries, want 4", len(got))
		}
		checkEntry(t, got[0], "", leaf1.Raw, true, true, 0)
		checkEntry(t, got[1], "", root.Raw, false, true, 0)
		checkEntry(t, got[2], "", leaf2.Raw, true, true, 0)
		checkEntry(t, got[3], "", root.Raw, false, true, 0)

		got, err = ParsePKCS12(data, []string{"wrong"})
		if err == nil || len(got) != 0 {
			t.Fatalf("wrong password: got %d entries, err = %v", len(got), err)
		}
	})

	t.Run("certificate duplicated in encrypted and plain parts", func(t *testing.T) {
		encrypted := contentsOf(t, mustTrustStore(t, pkcs12.Modern, "changeit", named{"encrypted copy", root}))
		data := buildPFX(t, []contentInfo{encrypted[0], plainContent(t, []safeBag{makeCertBag(t, root.Raw, "plain copy", nil)})})
		got, err := ParsePKCS12(data, []string{"changeit"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || !got[0].Encrypted || got[1].Encrypted {
			t.Fatalf("got %+v, want the encrypted copy first and the plain copy second", got)
		}
	})
}

func TestParsePKCS12_Errors(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	store := mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root})
	plain := mustTrustStore(t, pkcs12.Passwordless, "", named{"root", root})
	jks := writeJKS(magicJKS, 2, []jksEntry{{tag: jksTagTrustedCert, alias: "a", certs: []jksCert{{der: root.Raw}}}})

	notPKCS12 := map[string][]byte{
		"empty": nil, "PEM": pemOf(root), "JKS": jks, "ELF": elfHeader, "random": randomBytes(5, 500), "certificate": root.Raw,
	}
	for name, data := range notPKCS12 {
		t.Run(name, func(t *testing.T) {
			got, err := ParsePKCS12(data, []string{"", "changeit"})
			if !errors.Is(err, ErrFormat) {
				t.Errorf("err = %v, want ErrFormat", err)
			}
			if got != nil {
				t.Errorf("got %d entries, want none", len(got))
			}
		})
	}

	damaged := map[string][]byte{
		"truncated encrypted store": store[:len(store)/2],
		"truncated plain store":     plain[:len(plain)-10],
		"signedData integrity mode": buildSignedDataPFX(t),
	}
	for name, data := range damaged {
		t.Run(name, func(t *testing.T) {
			if !LooksLikePKCS12(data) {
				t.Fatal("test data should pass the sniff")
			}
			got, err := ParsePKCS12(data, []string{"", "changeit"})
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, ErrFormat) {
				t.Errorf("a damaged PFX is not an unrecognised format: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("got %d entries, want none", len(got))
			}
		})
	}
}

// buildSignedDataPFX builds a PFX using the (unsupported) public-key
// integrity mode.
func buildSignedDataPFX(t *testing.T) []byte {
	t.Helper()
	der, err := asn1.Marshal(pfxPDU{Version: 3, AuthSafe: contentInfo{ContentType: oidSignedDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0x00}}}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParsePKCS12_TruncationAndCorruptionNeverPanic(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	leaf, key := newTestCert(t, "leaf")
	files := map[string][]byte{
		"modern store": mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root}),
		"rc2 store":    mustTrustStore(t, pkcs12.LegacyRC2, "changeit", named{"root", root}),
		"plain store":  mustTrustStore(t, pkcs12.Passwordless, "", named{"root", root}),
		"chain":        mustChain(t, pkcs12.Legacy, "changeit", key, leaf, root),
	}
	passwords := []string{"", "changeit"}
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePKCS12(data, passwords); err != nil {
				t.Fatalf("intact file: %v", err)
			}
			for n := 0; n < len(data); n += 7 {
				got, err := ParsePKCS12(data[:n], passwords)
				if err == nil {
					t.Fatalf("prefix of %d/%d bytes parsed without error", n, len(data))
				}
				for _, e := range got {
					if _, perr := x509.ParseCertificate(e.Raw); perr != nil {
						t.Fatalf("prefix of %d bytes returned an unparsable certificate: %v", n, perr)
					}
				}
			}
			rng := newRand(99)
			for i := 0; i < 300; i++ {
				mutated := bytes.Clone(data)
				for k := 0; k < 1+rng.Intn(3); k++ {
					mutated[rng.Intn(len(mutated))] = byte(rng.Intn(256))
				}
				got, _ := ParsePKCS12(mutated, passwords)
				for _, e := range got {
					if _, perr := x509.ParseCertificate(e.Raw); perr != nil {
						t.Fatalf("mutation %d returned an unparsable certificate: %v", i, perr)
					}
				}
			}
		})
	}
}

func TestParsePKCS12_EntriesDoNotAliasInput(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	data := mustTrustStore(t, pkcs12.Passwordless, "", named{"root", root})
	got, err := ParsePKCS12(data, []string{""})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d entries, err = %v", len(got), err)
	}
	for i := range data {
		data[i] = 0
	}
	if !bytes.Equal(got[0].Raw, root.Raw) {
		t.Error("entry shares memory with the input buffer")
	}
}
