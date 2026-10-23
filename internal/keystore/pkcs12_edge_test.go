package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// encryptedContentOf wraps an EncryptedContentInfo in an encryptedData
// ContentInfo.
func encryptedContentOf(t *testing.T, version int, eci encryptedContentInfo) contentInfo {
	t.Helper()
	der, err := asn1.Marshal(encryptedData{Version: version, EncryptedContentInfo: eci})
	if err != nil {
		t.Fatal(err)
	}
	return contentInfo{ContentType: oidEncryptedDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}}
}

// encryptPBE is a test-side RFC 7292 PBE encryptor for the schemes go-pkcs12
// never writes.
func encryptPBE(t *testing.T, plain []byte, password string, oid asn1.ObjectIdentifier, keyLen int, newBlock func([]byte) (cipher.Block, error), iterations int) encryptedContentInfo {
	t.Helper()
	salt := randomBytes(21, 8)
	params, err := asn1.Marshal(pbeParams{Salt: salt, Iterations: iterations})
	if err != nil {
		t.Fatal(err)
	}
	pw := bmpStringZeroTerminated(password)
	block, err := newBlock(pkcs12KDF(1, salt, pw, iterations, keyLen))
	if err != nil {
		t.Fatal(err)
	}
	iv := pkcs12KDF(2, salt, pw, iterations, block.BlockSize())
	padLen := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return encryptedContentInfo{
		ContentType:                oidDataContentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedContent:           out,
	}
}

func TestPKCS12PBESchemesWithoutEncoder(t *testing.T) {
	self, _ := newTestCert(t, "self")
	bagsDER, err := asn1.Marshal([]safeBag{makeCertBag(t, self.Raw, "self", nil)})
	if err != nil {
		t.Fatal(err)
	}
	twoKeyDES := func(k []byte) (cipher.Block, error) { return des.NewTripleDESCipher(append(bytes.Clone(k), k[:8]...)) }
	rc2128 := func(k []byte) (cipher.Block, error) { return newRC2Cipher(k, 128) }
	tests := []struct {
		name string
		eci  encryptedContentInfo
	}{
		{"pbeWithSHA1And2-KeyTripleDES-CBC", encryptPBE(t, bagsDER, "pw", oidPBEWithSHAAnd2KeyTripleDESCBC, 16, twoKeyDES, 100)},
		{"pbeWithSHA1And128BitRC2-CBC", encryptPBE(t, bagsDER, "pw", oidPBEWithSHAAnd128BitRC2CBC, 16, rc2128, 100)},
		{"pbeWithSHA1And3-KeyTripleDES-CBC with empty password", encryptPBE(t, bagsDER, "", oidPBEWithSHAAnd3KeyTripleDESCBC, 24, des.NewTripleDESCipher, 100)},
		{"PBES2 with DES-EDE3-CBC", encryptPBES2(t, bagsDER, "pw", oidHMACWithSHA256, sha256.New, oidDESEDE3CBC, 24, des.NewTripleDESCipher, 100, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildPFX(t, []contentInfo{encryptedContentOf(t, 0, tc.eci)})
			got, err := ParsePKCS12(data, []string{"nope", "pw", ""})
			if err != nil {
				t.Fatalf("ParsePKCS12: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d entries, want 1", len(got))
			}
			checkEntry(t, got[0], "self", self.Raw, false, true, 0)
			if _, err := ParsePKCS12(data, []string{"nope"}); err == nil || !strings.Contains(err.Error(), "incorrect password") {
				t.Errorf("wrong password: err = %v", err)
			}
		})
	}
}

// withAttribute appends a raw attribute value (a DER element placed inside
// the attribute's SET) to a bag.
func withAttribute(bag safeBag, id asn1.ObjectIdentifier, valueDER []byte) safeBag {
	bag.Attributes = append(bag.Attributes, pkcs12Attribute{ID: id,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valueDER}})
	return bag
}

func TestPKCS12BagAttributes(t *testing.T) {
	self, _ := newTestCert(t, "self")
	marshalRaw := func(tag int, b []byte) []byte {
		der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: b})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	tests := []struct {
		name  string
		bag   safeBag
		alias string
	}{
		{"UTF8String friendlyName", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, marshalRaw(asn1.TagUTF8String, []byte("utf8 alias"))), "utf8 alias"},
		{"PrintableString friendlyName", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, marshalRaw(asn1.TagPrintableString, []byte("printable"))), "printable"},
		{"IA5String friendlyName", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, marshalRaw(asn1.TagIA5String, []byte("ia5"))), "ia5"},
		{"NumericString friendlyName is ignored", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, marshalRaw(asn1.TagNumericString, []byte("123"))), ""},
		{"context-specific friendlyName is ignored", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, []byte{0x80, 0x01, 'x'}), ""},
		{"garbage friendlyName is ignored", withAttribute(makeCertBag(t, self.Raw, "", nil), oidFriendlyName, []byte{0x1e}), ""},
		// DER sorts SET OF elements, so "aaa" precedes "zzz" in the file whatever the write order.
		{"first friendlyName in file order wins", withAttribute(makeCertBag(t, self.Raw, "zzz", nil), oidFriendlyName, marshalRaw(asn1.TagBMPString, []byte{0, 'a', 0, 'a', 0, 'a'})), "aaa"},
		{"garbage localKeyId is ignored", withAttribute(makeCertBag(t, self.Raw, "lk", nil), oidLocalKeyID, []byte{0x04}), "lk"},
		{"other attributes are ignored", withAttribute(makeCertBag(t, self.Raw, "other", nil), asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 17, 1}, marshalRaw(asn1.TagBMPString, []byte{0, 'x'})), "other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildPFX(t, []contentInfo{plainContent(t, []safeBag{tc.bag})})
			got, err := ParsePKCS12(data, nil)
			if err != nil {
				t.Fatalf("ParsePKCS12: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d entries, want 1", len(got))
			}
			checkEntry(t, got[0], tc.alias, self.Raw, false, false, 0)
		})
	}

	t.Run("localKeyId links certificates to key bags", func(t *testing.T) {
		keyBag := makeBag(t, oidKeyBag, []byte("not really a key"), "", []byte{1, 2, 3})
		data := buildPFX(t, []contentInfo{plainContent(t, []safeBag{
			makeCertBag(t, self.Raw, "with key", []byte{1, 2, 3}),
			makeCertBag(t, self.Raw, "other id", []byte{9, 9, 9}),
			makeCertBag(t, self.Raw, "no id", nil),
			keyBag,
		})})
		got, err := ParsePKCS12(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || !got[0].FromKeyEntry || got[1].FromKeyEntry || got[2].FromKeyEntry {
			t.Fatalf("got %+v, want only the first entry marked FromKeyEntry", got)
		}
	})
}

func TestParsePKCS12_UnsupportedParts(t *testing.T) {
	self, _ := newTestCert(t, "self")
	bagsDER, err := asn1.Marshal([]safeBag{makeCertBag(t, self.Raw, "self", nil)})
	if err != nil {
		t.Fatal(err)
	}
	plain := plainContent(t, []safeBag{makeCertBag(t, self.Raw, "plain", nil)})
	raw := func(contentType asn1.ObjectIdentifier, content []byte) contentInfo {
		return contentInfo{ContentType: contentType,
			Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: content}}
	}
	good := encryptPBES2(t, bagsDER, "pw", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, 10, 0)

	tests := []struct {
		name    string
		first   contentInfo
		wantMsg string
	}{
		{"envelopedData", raw(oidEnvelopedDataContentType, []byte{0x30, 0x00}), "SafeContents #0 (encrypted, envelopedData) could not be read: public-key privacy mode is not supported"},
		{"signedData inside the AuthenticatedSafe", raw(oidSignedDataContentType, []byte{0x30, 0x00}), "SafeContents #0 could not be read: unsupported content type 1.2.840.113549.1.7.2"},
		{"EncryptedData version 1", encryptedContentOf(t, 1, good), "unsupported EncryptedData version 1"},
		{"garbage encryptedData", raw(oidEncryptedDataContentType, []byte{0x04, 0x01, 0x00}), "decoding encryptedData"},
		{"garbage data content", raw(oidDataContentType, []byte{0x30, 0x00}), "decoding data content"},
		{"data content that is not a SafeContents", raw(oidDataContentType, []byte{0x04, 0x02, 0x05, 0x00}), "decoding SafeContents"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildPFX(t, []contentInfo{tc.first, plain})
			got, err := ParsePKCS12(data, []string{"pw"})
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			if errors.Is(err, ErrFormat) {
				t.Errorf("unsupported parts are not a format error: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d entries, want the one from the plain SafeContents", len(got))
			}
			checkEntry(t, got[0], "plain", self.Raw, false, false, 0)
		})
	}

	t.Run("authSafe with an unsupported content type", func(t *testing.T) {
		der, err := asn1.Marshal(pfxPDU{Version: 3, AuthSafe: raw(oidEncryptedDataContentType, []byte{0x30, 0x00})})
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePKCS12(der, []string{""})
		if err == nil || !strings.Contains(err.Error(), "unsupported authSafe content type") || errors.Is(err, ErrFormat) {
			t.Fatalf("err = %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %d entries", len(got))
		}
	})

	t.Run("deeply nested SafeContents bags stop at the limit", func(t *testing.T) {
		bag := makeCertBag(t, self.Raw, "deep", nil)
		for i := 0; i < maxSafeContentsNesting; i++ {
			bag = makeBag(t, oidSafeContentsBag, []safeBag{bag}, "", nil)
		}
		data := buildPFX(t, []contentInfo{plainContent(t, []safeBag{bag, makeCertBag(t, self.Raw, "top", nil)})})
		got, err := ParsePKCS12(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Alias != "top" {
			t.Fatalf("got %+v, want only the top-level certificate", got)
		}
	})
}

// pfxWithMAC exposes the MacData for tests that rewrite it.
type pfxWithMAC struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

func withMACIterations(t *testing.T, data []byte, iterations int) []byte {
	t.Helper()
	var pfx pfxWithMAC
	if _, err := asn1.Unmarshal(data, &pfx); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Iterations = iterations
	out, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParsePKCS12_MACIterations(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	want := map[string]struct {
		enc        *pkcs12.Encoder
		password   string
		iterations int
	}{
		"Modern2023":   {pkcs12.Modern2023, "changeit", 2048},
		"Modern2026":   {pkcs12.Modern2026, "changeit", 2048},
		"Legacy":       {pkcs12.Legacy, "changeit", 1},
		"Passwordless": {pkcs12.Passwordless, "", 0},
	}
	for name, tc := range want {
		p, err := parsePFX(mustTrustStore(t, tc.enc, tc.password, named{"root", root}))
		if err != nil {
			t.Fatal(err)
		}
		if p.macIterations != tc.iterations {
			t.Errorf("%s: macIterations = %d, want %d", name, p.macIterations, tc.iterations)
		}
		if p.hasMAC != (tc.iterations > 0) {
			t.Errorf("%s: hasMAC = %v", name, p.hasMAC)
		}
	}
}

func TestParsePKCS12_KDFLimitsGuard(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	self, _ := newTestCert(t, "self")

	t.Run("absurd MAC iteration count", func(t *testing.T) {
		// Without the guard go-pkcs12 would grind through 100 million
		// SHA-256 rounds for every password before reporting anything.
		data := withMACIterations(t, mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root}), 100_000_000)
		start := time.Now()
		got, err := ParsePKCS12(data, []string{"", "changeit"})
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Fatalf("took %v; the MAC iteration count was not guarded", elapsed)
		}
		if err != nil {
			t.Fatalf("the content itself is readable with the right password: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1", len(got))
		}
		checkEntry(t, got[0], "root", root.Raw, false, true, 0)

		// With the wrong password the content fails as usual; the MAC that
		// could not be verified does not make the file "too expensive".
		start = time.Now()
		_, err = ParsePKCS12(data, []string{"wrong"})
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Fatalf("took %v; the MAC iteration count was not guarded", elapsed)
		}
		if err == nil || !strings.Contains(err.Error(), "none of the 1 supplied passwords opened the file") || !strings.Contains(err.Error(), "incorrect password") {
			t.Fatalf("wrong password: err = %v", err)
		}
		if errors.Is(err, ErrTooExpensive) {
			t.Errorf("a cheap SafeContents behind an unverifiable MAC is not too expensive: %v", err)
		}
	})

	t.Run("absurd content iteration count", func(t *testing.T) {
		bagsDER, err := asn1.Marshal([]safeBag{makeCertBag(t, self.Raw, "self", nil)})
		if err != nil {
			t.Fatal(err)
		}
		eci := encryptPBES2(t, bagsDER, "", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, maxKDFIterations+1, 0)
		data := buildPFX(t, []contentInfo{encryptedContentOf(t, 0, eci), plainContent(t, []safeBag{makeCertBag(t, root.Raw, "plain", nil)})})
		got, err := ParsePKCS12(data, []string{""})
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrTooExpensive) {
			t.Errorf("err = %v, want it to wrap ErrTooExpensive", err)
		}
		for _, m := range []string{"too expensive to decrypt (5000001 iterations requested)", "SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: iteration count 5000001 exceeds the supported maximum of 5000000"} {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("error %q should mention %q", err, m)
			}
		}
		if len(got) != 1 || got[0].Alias != "plain" {
			t.Fatalf("got %+v, want only the plain certificate", got)
		}
	})
}

func TestParsePKCS12_ErrorsDoNotEchoPasswords(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	data := mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root})
	const secret = "hunter2-very-secret"
	_, err := ParsePKCS12(data, []string{secret, "also-" + secret})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message echoes a supplied password: %v", err)
	}
	if !strings.Contains(err.Error(), "none of the 2 supplied passwords") {
		t.Errorf("error should refer to passwords by count, not content: %v", err)
	}
}
