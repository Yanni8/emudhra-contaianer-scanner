package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"hash"
	mathrand "math/rand"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func newRand(seed int64) *mathrand.Rand { return mathrand.New(mathrand.NewSource(seed)) }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRC2_RFC2268Vectors checks the cipher against the test vectors of RFC
// 2268 section 5.
func TestRC2_RFC2268Vectors(t *testing.T) {
	tests := []struct {
		key, plain, cipher string
		effectiveBits      int
	}{
		{"0000000000000000", "0000000000000000", "ebb773f993278eff", 63},
		{"ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49", 64},
		{"3000000000000000", "1000000000000001", "30649edf9be7d2c2", 64},
		{"88", "0000000000000000", "61a8a244adacccf0", 64},
		{"88bca90e90875a", "0000000000000000", "6ccf4308974c267f", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "1a807d272bbe5db1", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6", 128},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", "0000000000000000", "5b78d3a43dfff1f1", 129},
	}
	for i, tc := range tests {
		c, err := newRC2Cipher(mustHex(t, tc.key), tc.effectiveBits)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		var out [8]byte
		c.Encrypt(out[:], mustHex(t, tc.plain))
		if got := hex.EncodeToString(out[:]); got != tc.cipher {
			t.Errorf("vector %d: encrypt = %s, want %s", i, got, tc.cipher)
		}
		c.Decrypt(out[:], mustHex(t, tc.cipher))
		if got := hex.EncodeToString(out[:]); got != tc.plain {
			t.Errorf("vector %d: decrypt = %s, want %s", i, got, tc.plain)
		}
	}
	for _, bad := range []struct{ keyLen, bits int }{{0, 64}, {129, 64}, {8, 0}, {8, 1025}} {
		if _, err := newRC2Cipher(make([]byte, bad.keyLen), bad.bits); err == nil {
			t.Errorf("key length %d with %d effective bits should be rejected", bad.keyLen, bad.bits)
		}
	}
}

// TestPKCS12KDF checks the RFC 7292 key derivation against the vectors used
// by go-pkcs12 (the second one exercises an intermediate value with a leading
// zero byte).
func TestPKCS12KDF(t *testing.T) {
	sesame := bmpStringZeroTerminated("sesame")
	if want := "0073006500730061006d00650000"; hex.EncodeToString(sesame) != want {
		t.Fatalf("bmpStringZeroTerminated = %x, want %s", sesame, want)
	}
	tests := []struct {
		name           string
		salt, password []byte
		iterations, n  int
		id             byte
		want           string
	}{
		{"sesame", bytes.Repeat([]byte{0xff}, 8), sesame, 2048, 24, 1, "7cd9fd3e2b3be7691a44e3bef0f9ea0fb9b897d4e325d9d1"},
		{"leading zero", mustHex(t, "f37e05b518324b4b"), []byte{0, 0}, 2048, 24, 1, "00f759ff47d14dd03665d5943cb3c4a39a2555c02aed66e1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pkcs12KDF(tc.id, tc.salt, tc.password, tc.iterations, tc.n)
			if hex.EncodeToString(got) != tc.want {
				t.Errorf("pkcs12KDF = %x, want %s", got, tc.want)
			}
		})
	}
	t.Run("edge cases", func(t *testing.T) {
		if got := pkcs12KDF(1, nil, nil, 1, 20); len(got) != 20 {
			t.Errorf("empty salt and password: got %d bytes", len(got))
		}
		// Outputs longer than one hash block come from successive blocks and
		// must be consistent prefixes of each other.
		long := pkcs12KDF(2, []byte("salt"), sesame, 3, 50)
		short := pkcs12KDF(2, []byte("salt"), sesame, 3, 8)
		if !bytes.Equal(long[:8], short) {
			t.Errorf("derivations of different lengths disagree: %x vs %x", long[:8], short)
		}
	})
}

// TestDecryptSafeContents_Interop decrypts the certificate SafeContents of
// files produced by every go-pkcs12 encoder and compares with the library's
// own decoding.
func TestDecryptSafeContents_Interop(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	self, _ := newTestCert(t, "self")
	certs := []named{{"root", root}, {"self", self}}
	encoders := []struct {
		name      string
		enc       *pkcs12.Encoder
		algorithm string
	}{
		{"Modern2023", pkcs12.Modern2023, "PBES2 with AES-256-CBC"},
		{"Modern2026", pkcs12.Modern2026, "PBES2 with AES-256-CBC"},
		{"LegacyDES", pkcs12.LegacyDES, "pbeWithSHA1And3-KeyTripleDES-CBC"},
		{"LegacyRC2", pkcs12.LegacyRC2, "pbeWithSHA1And40BitRC2-CBC"},
		{"Modern with 1 iteration", pkcs12.Modern.WithIterations(1), "PBES2 with AES-256-CBC"},
		{"Legacy with 50000 iterations", pkcs12.Legacy.WithIterations(50000), "pbeWithSHA1And3-KeyTripleDES-CBC"},
	}
	for _, tc := range encoders {
		t.Run(tc.name, func(t *testing.T) {
			data := mustTrustStore(t, tc.enc, "changeit", certs...)
			want, err := pkcs12.DecodeTrustStore(data, "changeit")
			if err != nil {
				t.Fatalf("go-pkcs12 cannot read its own output: %v", err)
			}
			p, err := parsePFX(data)
			if err != nil {
				t.Fatalf("parsePFX: %v", err)
			}
			if !p.hasMAC || len(p.contents) != 1 {
				t.Fatalf("hasMAC = %v, %d SafeContents; want a MAC and one SafeContents", p.hasMAC, len(p.contents))
			}
			results, _ := p.extract([]string{"wrong", "changeit"}, newKDFBudget())
			res := results[0]
			if res.err != nil {
				t.Fatalf("extract: %v", res.err)
			}
			if !res.encrypted || res.algorithm != tc.algorithm {
				t.Errorf("encrypted = %v, algorithm = %q; want true, %q", res.encrypted, res.algorithm, tc.algorithm)
			}
			if len(res.certs) != len(want) {
				t.Fatalf("got %d certificates, want %d", len(res.certs), len(want))
			}
			for i := range want {
				if !bytes.Equal(res.certs[i].raw, want[i].Raw) {
					t.Errorf("certificate %d differs from go-pkcs12's", i)
				}
				if res.certs[i].alias != certs[i].alias {
					t.Errorf("alias %d = %q, want %q", i, res.certs[i].alias, certs[i].alias)
				}
			}
			for _, passwords := range [][]string{nil, {""}, {"wrong", "CHANGEIT"}} {
				results, _ := p.extract(passwords, newKDFBudget())
				res := results[0]
				if res.err == nil || len(res.certs) != 0 {
					t.Errorf("passwords %q: err = %v, %d certificates; want failure", passwords, res.err, len(res.certs))
				}
			}
		})
	}
}

func TestDecryptSafeContents_EmptyPasswordEncodings(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	for _, enc := range []*pkcs12.Encoder{pkcs12.Modern, pkcs12.Legacy, pkcs12.LegacyRC2} {
		data := mustTrustStore(t, enc, "", named{"root", root})
		p, err := parsePFX(data)
		if err != nil {
			t.Fatal(err)
		}
		results, _ := p.extract([]string{""}, newKDFBudget())
		res := results[0]
		if res.err != nil || len(res.certs) != 1 || !bytes.Equal(res.certs[0].raw, root.Raw) {
			t.Errorf("%s: empty password: err = %v, %d certificates", res.algorithm, res.err, len(res.certs))
		}
	}
}

// encryptedContent is a test-side PBES2/PKCS#12-PBE encryptor used to produce
// parameter combinations go-pkcs12 never writes.
func encryptPBES2(t *testing.T, plain []byte, password string, prf asn1.ObjectIdentifier, prfFn func() hash.Hash, scheme asn1.ObjectIdentifier, keyLen int, newBlock func([]byte) (cipher.Block, error), iterations, keyLengthParam int) encryptedContentInfo {
	t.Helper()
	salt := randomBytes(11, 16)
	kdfParams := pbkdf2Params{Iterations: iterations, KeyLength: keyLengthParam}
	var err error
	if kdfParams.Salt.FullBytes, err = asn1.Marshal(salt); err != nil {
		t.Fatal(err)
	}
	if prf != nil {
		kdfParams.PRF = pkix.AlgorithmIdentifier{Algorithm: prf, Parameters: asn1.NullRawValue}
	}
	kdfDER, err := asn1.Marshal(kdfParams)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pbkdf2.Key(prfFn, password, salt, iterations, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := newBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := randomBytes(12, block.BlockSize())
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		t.Fatal(err)
	}
	paramsDER, err := asn1.Marshal(pbes2Params{
		KDF:              pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfDER}},
		EncryptionScheme: pkix.AlgorithmIdentifier{Algorithm: scheme, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	padLen := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return encryptedContentInfo{
		ContentType:                oidDataContentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: paramsDER}},
		EncryptedContent:           out,
	}
}

func TestPBES2Variants(t *testing.T) {
	self, _ := newTestCert(t, "self")
	bagsDER, err := asn1.Marshal([]safeBag{makeCertBag(t, self.Raw, "self", nil)})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		prf    asn1.ObjectIdentifier
		prfFn  func() hash.Hash
		scheme asn1.ObjectIdentifier
		keyLen int
	}{
		{"default PRF (SHA-1) with AES-128", nil, sha1.New, oidAES128CBC, 16},
		{"HMAC-SHA1 with AES-192", oidHMACWithSHA1, sha1.New, oidAES192CBC, 24},
		{"HMAC-SHA224 with AES-128", oidHMACWithSHA224, sha256.New224, oidAES128CBC, 16},
		{"HMAC-SHA256 with AES-256", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32},
		{"HMAC-SHA384 with AES-256", oidHMACWithSHA384, sha512.New384, oidAES256CBC, 32},
		{"HMAC-SHA512 with AES-256", oidHMACWithSHA512, sha512.New, oidAES256CBC, 32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eci := encryptPBES2(t, bagsDER, "pässword", tc.prf, tc.prfFn, tc.scheme, tc.keyLen, aes.NewCipher, 1000, tc.keyLen)
			bags, opened, err := decryptSafeContents(eci, []string{"wrong", "pässword"}, -1, newKDFBudget())
			if err != nil {
				t.Fatalf("decryptSafeContents: %v", err)
			}
			if len(bags) != 1 || !bags[0].ID.Equal(oidCertBag) || opened != 1 {
				t.Fatalf("got %d bags opened by password %d, want one certificate bag opened by password 1", len(bags), opened)
			}
			if _, _, err := decryptSafeContents(eci, []string{"wrong"}, -1, newKDFBudget()); !errors.Is(err, errIncorrectPassword) {
				t.Errorf("wrong password: err = %v, want errIncorrectPassword", err)
			}
		})
	}
}

func TestContentDecryptorParameterChecks(t *testing.T) {
	self, _ := newTestCert(t, "self")
	bagsDER, err := asn1.Marshal([]safeBag{makeCertBag(t, self.Raw, "self", nil)})
	if err != nil {
		t.Fatal(err)
	}
	good := encryptPBES2(t, bagsDER, "pw", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, 10, 0)

	withAlgorithm := func(alg pkix.AlgorithmIdentifier) encryptedContentInfo {
		eci := good
		eci.ContentEncryptionAlgorithm = alg
		return eci
	}
	pbeAlg := func(oid asn1.ObjectIdentifier, salt []byte, iterations int) pkix.AlgorithmIdentifier {
		params, err := asn1.Marshal(pbeParams{Salt: salt, Iterations: iterations})
		if err != nil {
			t.Fatal(err)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: params}}
	}
	tests := []struct {
		name    string
		eci     encryptedContentInfo
		wantMsg string
	}{
		{"empty content", encryptedContentInfo{ContentEncryptionAlgorithm: good.ContentEncryptionAlgorithm}, "empty encrypted content"},
		{"unsupported algorithm (RC4)", withAlgorithm(pbeAlg(oidPBEWithSHAAnd40BitRC4, []byte("salt"), 1)), "unsupported encryption algorithm pbeWithSHA1And40BitRC4"},
		{"unknown algorithm OID", withAlgorithm(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}), "unsupported encryption algorithm 1.2.3.4"},
		{"too many iterations", withAlgorithm(pbeAlg(oidPBEWithSHAAnd3KeyTripleDESCBC, []byte("salt"), maxKDFIterations+1)), "exceeds the supported maximum"},
		{"zero iterations", withAlgorithm(pbeAlg(oidPBEWithSHAAnd3KeyTripleDESCBC, []byte("salt"), 0)), "invalid iteration count 0"},
		{"huge salt", withAlgorithm(pbeAlg(oidPBEWithSHAAnd3KeyTripleDESCBC, make([]byte, maxKDFSaltLen+1), 1)), "salt length"},
		{"garbage PBE parameters", withAlgorithm(pkix.AlgorithmIdentifier{Algorithm: oidPBEWithSHAAnd40BitRC2CBC, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}), "decoding PBE parameters"},
		{"garbage PBES2 parameters", withAlgorithm(pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}), "decoding PBES2 parameters"},
		{"PBES2 key length mismatch", encryptPBES2(t, bagsDER, "pw", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, 10, 16), "key length 16 does not match"},
		{"PBES2 iterations too high", encryptPBES2(t, bagsDER, "pw", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, maxKDFIterations+1, 0), "exceeds the supported maximum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decryptSafeContents(tc.eci, []string{"pw"}, -1, newKDFBudget())
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
		})
	}

	t.Run("ciphertext not a multiple of the block size", func(t *testing.T) {
		eci := good
		eci.EncryptedContent = good.EncryptedContent[:len(good.EncryptedContent)-1]
		if _, _, err := decryptSafeContents(eci, []string{"pw"}, -1, newKDFBudget()); err == nil || !strings.Contains(err.Error(), "multiple of the block size") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no passwords", func(t *testing.T) {
		if _, _, err := decryptSafeContents(good, nil, -1, newKDFBudget()); err == nil || !strings.Contains(err.Error(), "no password supplied") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the right password still works", func(t *testing.T) {
		bags, _, err := decryptSafeContents(good, []string{"pw"}, -1, newKDFBudget())
		if err != nil || len(bags) != 1 {
			t.Errorf("bags = %d, err = %v", len(bags), err)
		}
	})
}

// TestPKCS12PBEWrongPasswordPaddingFluke makes sure a wrong password whose
// decryption happens to end in valid padding is still rejected because the
// plaintext is not a SafeContents.
func TestPKCS12PBEWrongPasswordPaddingFluke(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	data := mustTrustStore(t, pkcs12.LegacyRC2.WithIterations(1), "changeit", named{"root", root})
	p, err := parsePFX(data)
	if err != nil {
		t.Fatal(err)
	}
	// Try many wrong passwords; some of them pass the padding check by chance
	// and all of them must be reported as incorrect.
	passwords := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		passwords = append(passwords, strings.Repeat("x", i%7)+hex.EncodeToString(randomBytes(int64(i), 3)))
	}
	results, _ := p.extract(passwords, newKDFBudget())
	res := results[0]
	if !errors.Is(res.err, errIncorrectPassword) || len(res.certs) != 0 {
		t.Fatalf("err = %v, %d certificates; want errIncorrectPassword and none", res.err, len(res.certs))
	}
}

func TestDescribeAlgorithm(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	want := map[*pkcs12.Encoder]string{
		pkcs12.Modern:    "PBES2 with AES-256-CBC",
		pkcs12.Legacy:    "pbeWithSHA1And3-KeyTripleDES-CBC",
		pkcs12.LegacyRC2: "pbeWithSHA1And40BitRC2-CBC",
	}
	for enc, name := range want {
		p, err := parsePFX(mustTrustStore(t, enc, "changeit", named{"root", root}))
		if err != nil {
			t.Fatal(err)
		}
		var ed encryptedData
		if _, err := asn1.Unmarshal(p.contents[0].Content.Bytes, &ed); err != nil {
			t.Fatal(err)
		}
		if got := describeAlgorithm(ed.EncryptedContentInfo.ContentEncryptionAlgorithm); got != name {
			t.Errorf("describeAlgorithm = %q, want %q", got, name)
		}
	}
	if got := describeAlgorithm(pkix.AlgorithmIdentifier{Algorithm: oidPBES2}); got != "PBES2" {
		t.Errorf("PBES2 without parameters = %q", got)
	}
	if got := describeAlgorithm(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}); got != "1.2.3" {
		t.Errorf("unknown OID = %q", got)
	}
}

func TestDecodeBMPString(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		{nil, ""},
		{[]byte{0, 'a', 0, 'b'}, "ab"},
		{[]byte{0, 'a', 0}, "a"}, // odd trailing byte dropped
		{[]byte{0xd8, 0x3d, 0xde, 0x00}, "\U0001F600"},
		{[]byte{0x00, 0xfc}, "ü"},
	}
	for _, tc := range tests {
		if got := decodeBMPString(tc.in); got != tc.want {
			t.Errorf("decodeBMPString(%x) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
