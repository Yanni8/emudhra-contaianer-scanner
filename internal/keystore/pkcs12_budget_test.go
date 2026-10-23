package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Regression tests for the key-derivation budget: hostile files that ask for
// enormous amounts of work must be refused in milliseconds, not ground
// through. The two shapes found by fuzzing are rebuilt here: a 1.6 KB file
// whose MacData names 50,000,000 iterations, and a file with 1000 encrypted
// SafeContents each at the 5,000,000-iteration per-derivation cap.

// fast fails the test when a parse took longer than a budget-guarded parse
// possibly can; the bound is generous to survive slow CI machines.
const fast = 2 * time.Second

// setFileBudget lowers the per-file budget for one test.
func setFileBudget(t *testing.T, iterations int64) {
	t.Helper()
	old := kdfIterationsPerFile
	kdfIterationsPerFile = iterations
	t.Cleanup(func() { kdfIterationsPerFile = old })
}

// bogusEncryptedContent is an encryptedData ContentInfo whose PBES2
// parameters ask for the given PBKDF2-HMAC-SHA512 iteration count and whose
// "ciphertext" is random, exactly as a hostile generator would write it: no
// key derivation is needed to build it.
func bogusEncryptedContent(t *testing.T, iterations int, seed int64) contentInfo {
	t.Helper()
	kdf := pbkdf2Params{Iterations: iterations, PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA512, Parameters: asn1.NullRawValue}}
	var err error
	if kdf.Salt.FullBytes, err = asn1.Marshal(randomBytes(seed, 16)); err != nil {
		t.Fatal(err)
	}
	kdfDER, err := asn1.Marshal(kdf)
	if err != nil {
		t.Fatal(err)
	}
	ivDER, err := asn1.Marshal(randomBytes(seed+1, 16))
	if err != nil {
		t.Fatal(err)
	}
	params, err := asn1.Marshal(pbes2Params{
		KDF:              pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfDER}},
		EncryptionScheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encryptedContentOf(t, 0, encryptedContentInfo{
		ContentType:                oidDataContentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedContent:           randomBytes(seed+2, 16),
	})
}

// withMAC adds a MacData with the given iteration count (and a digest that
// is never checked) to a MAC-less PFX.
func withMAC(t *testing.T, data []byte, iterations int) []byte {
	t.Helper()
	var pfx pfxWithMAC
	if _, err := asn1.Unmarshal(data, &pfx); err != nil {
		t.Fatal(err)
	}
	pfx.MacData = macData{
		Mac:        digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Parameters: asn1.NullRawValue}, Digest: randomBytes(31, 20)},
		MacSalt:    randomBytes(32, 8),
		Iterations: iterations,
	}
	out, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// shroudedKeyBag builds a PKCS8ShroudedKeyBag whose PBES2 parameters ask for
// the given iteration count; the key material is random.
func shroudedKeyBag(t *testing.T, iterations int, localKeyID []byte) safeBag {
	t.Helper()
	ci := bogusEncryptedContent(t, iterations, 77)
	var ed encryptedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	return makeBag(t, oidPKCS8ShroudedKeyBag, encryptedPrivateKeyInfo{Algorithm: ed.EncryptedContentInfo.ContentEncryptionAlgorithm, Data: randomBytes(78, 48)}, "", localKeyID)
}

func TestParsePKCS12_RefusesAbsurdWork(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	self, _ := newTestCert(t, "leaf.example")
	plain := plainContent(t, []safeBag{makeCertBag(t, self.Raw, "leaf", nil), makeCertBag(t, root.Raw, "root", nil)})
	passwords := []string{"", "changeit", "changeme", "password"}

	tests := []struct {
		name        string
		data        []byte
		wantEntries int
		wantErr     error  // sentinel the error must wrap; nil means no error
		wantMsg     string // substring of the error
		wantPass    int
	}{
		{
			// hang-input.bin: 1.6 KB, MacData iterations 50,000,000, plain
			// certificates. The MAC is never verified; the certificates are read.
			name:        "MAC of 50 million iterations over plain certificates",
			data:        withMAC(t, buildPFX(t, []contentInfo{plain}), 50_000_000),
			wantEntries: 2,
			wantPass:    -1,
		},
		{
			// The same MAC on a file whose authSafe is not an OCTET STRING: the
			// structural parser rejects it, and go-pkcs12 (which would verify
			// the MAC first) never sees it.
			name:     "MAC of 50 million iterations over an unparsable authSafe",
			data:     withMAC(t, pfxWithRawAuthSafe(t, []contentInfo{plain}), 50_000_000),
			wantMsg:  "keystore: pkcs12: decoding authSafe: asn1: structure error: tags don't match (4 vs class 0 tag 16) @4",
			wantPass: -1,
		},
		{
			// c-many1000-5M.p12: 1000 encrypted SafeContents, each at the
			// per-derivation cap. 1000 x 5,000,000 x 4 passwords would take
			// hours; the file is refused before any derivation.
			name:     "1000 encrypted SafeContents at the per-derivation cap",
			data:     buildPFX(t, manyEncrypted(t, 1000, maxKDFIterations)),
			wantErr:  ErrTooExpensive,
			wantMsg:  "too expensive to decrypt (5000000000 iterations requested, 1000 encrypted SafeContents)",
			wantPass: -1,
		},
		{
			// Three SafeContents of 4,000,000: each is below the cap but one
			// password already needs more than the per-file budget.
			name:     "three SafeContents whose sum exceeds the budget",
			data:     buildPFX(t, manyEncrypted(t, 3, 4_000_000)),
			wantErr:  ErrTooExpensive,
			wantMsg:  "too expensive to decrypt (12000000 iterations requested): SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: key-derivation budget exhausted",
			wantPass: -1,
		},
		{
			// Plain certificates next to refused parts are still returned.
			name:        "plain certificates beside refused SafeContents",
			data:        buildPFX(t, append(manyEncrypted(t, 65, 1), plain)),
			wantEntries: 2,
			wantErr:     ErrTooExpensive,
			wantMsg:     "65 encrypted SafeContents",
			wantPass:    -1,
		},
		{
			// A shrouded private key with an absurd iteration count sits in a
			// plain SafeContents; go-pkcs12's DecodeChain would unwrap it.
			name:        "shrouded key with 2^31-1 iterations in a plain SafeContents",
			data:        buildPFX(t, []contentInfo{plainContent(t, []safeBag{shroudedKeyBag(t, 1<<31-1, []byte{1}), makeCertBag(t, self.Raw, "leaf", []byte{1})})}),
			wantEntries: 1,
			wantPass:    -1,
		},
		{
			// The same key hidden behind cheap encryption with the empty
			// password: the structural walk decrypts the SafeContents, sees the
			// key's parameters and keeps go-pkcs12 away from the file.
			name:        "shrouded key with 2^31-1 iterations behind cheap encryption",
			data:        buildPFX(t, []contentInfo{encryptedContentOf(t, 0, encryptPBES2(t, mustMarshal(t, []safeBag{shroudedKeyBag(t, 1<<31-1, []byte{1}), makeCertBag(t, self.Raw, "leaf", []byte{1})}), "", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, 10, 0))}),
			wantEntries: 1,
			wantPass:    0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got, password, err := OpenPKCS12(tc.data, passwords)
			if elapsed := time.Since(start); elapsed > fast {
				t.Fatalf("took %v; the file's key-derivation demands were not refused", elapsed)
			}
			if len(got) != tc.wantEntries {
				t.Errorf("got %d entries, want %d (err = %v)", len(got), tc.wantEntries, err)
			}
			if password != tc.wantPass {
				t.Errorf("password = %d, want %d", password, tc.wantPass)
			}
			switch {
			case tc.wantErr == nil && tc.wantMsg == "":
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case err == nil:
				t.Fatalf("expected an error")
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Errorf("err = %v, want it to wrap %v", err, tc.wantErr)
			}
			if err != nil && errors.Is(err, ErrFormat) {
				t.Errorf("a well-formed PFX must not be reported as ErrFormat: %v", err)
			}
			if tc.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantMsg)) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			if err != nil && strings.Count(err.Error(), "\n") > 0 {
				t.Errorf("error spans several lines: %q", err)
			}
		})
	}
}

// manyEncrypted builds n encrypted SafeContents at the given iteration count.
func manyEncrypted(t *testing.T, n, iterations int) []contentInfo {
	t.Helper()
	contents := make([]contentInfo, 0, n)
	for i := 0; i < n; i++ {
		contents = append(contents, bogusEncryptedContent(t, iterations, int64(100+3*i)))
	}
	return contents
}

// pfxWithRawAuthSafe builds a PFX whose authSafe content holds the
// AuthenticatedSafe SEQUENCE directly instead of inside an OCTET STRING, the
// layout of the fuzzer's hang input.
func pfxWithRawAuthSafe(t *testing.T, contents []contentInfo) []byte {
	t.Helper()
	authSafe, err := asn1.Marshal(contents)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pfxPDU{Version: 3, AuthSafe: contentInfo{ContentType: oidDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: authSafe}}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParsePKCS12_BudgetStopsMidFile(t *testing.T) {
	self, _ := newTestCert(t, "self")
	other, _ := newTestCert(t, "other")
	const iterations = 1000
	content := func(c []byte, alias string, seed int64) contentInfo {
		eci := encryptPBES2(t, mustMarshal(t, []safeBag{makeCertBag(t, c, alias, nil)}), "right", oidHMACWithSHA256, sha256.New, oidAES256CBC, 32, aes.NewCipher, iterations, 0)
		return encryptedContentOf(t, 0, eci)
	}
	data := buildPFX(t, []contentInfo{content(self.Raw, "first", 1), content(other.Raw, "second", 2)})
	passwords := []string{"wrong", "right"}

	t.Run("password that opened one SafeContents is tried first on the next", func(t *testing.T) {
		// #0 costs two derivations (wrong, then right); #1 only one, because
		// "right" is promoted. Twice that work would be needed otherwise.
		setFileBudget(t, 3*iterations)
		got, err := ParsePKCS12(data, passwords)
		if err != nil {
			t.Fatalf("ParsePKCS12: %v", err)
		}
		if len(got) != 2 || got[0].Alias != "first" || got[1].Alias != "second" {
			t.Fatalf("got %+v, want both certificates", got)
		}
	})
	t.Run("exhausted budget stops the remaining parts", func(t *testing.T) {
		setFileBudget(t, 2*iterations)
		got, err := ParsePKCS12(data, passwords)
		if !errors.Is(err, ErrTooExpensive) {
			t.Fatalf("err = %v, want ErrTooExpensive", err)
		}
		for _, m := range []string{"too expensive to decrypt (2000 iterations requested)", "SafeContents #1 (encrypted, PBES2 with AES-256-CBC) could not be read: key-derivation budget exhausted: 1000 iterations requested, 0 left for this file"} {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("error %q should mention %q", err, m)
			}
		}
		if len(got) != 1 || got[0].Alias != "first" || !got[0].Encrypted {
			t.Fatalf("got %+v, want only the first certificate", got)
		}
	})
	t.Run("budget covers go-pkcs12 as well", func(t *testing.T) {
		// A Java trust store (MAC and content at 500 iterations each) opens
		// with one derivation; go-pkcs12 would then spend MAC + content
		// again. With room for only the first, the structural walk's result
		// is returned without an error.
		root := blocklistCert(t, "emsign-ecc-root-ca-g3")
		store := mustTrustStore(t, pkcs12.Modern.WithIterations(500), "changeit", named{"root", root})
		setFileBudget(t, 1000)
		got, password, err := OpenPKCS12(store, []string{"changeit"})
		if err != nil || len(got) != 1 || password != 0 || !bytes.Equal(got[0].Raw, root.Raw) || !got[0].Encrypted {
			t.Fatalf("got %+v password %d err %v", got, password, err)
		}
	})
}

func TestOpenPKCS12_Password(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	encrypted := mustTrustStore(t, pkcs12.Modern, "changeit", named{"root", root})
	plain := mustTrustStore(t, pkcs12.Passwordless, "", named{"root", root})
	tests := []struct {
		name      string
		data      []byte
		passwords []string
		want      int
		wantErr   bool
	}{
		{"first password", encrypted, []string{"changeit", ""}, 0, false},
		{"later password", encrypted, []string{"", "nope", "changeit"}, 2, false},
		{"index counts duplicates in the caller's list", encrypted, []string{"nope", "nope", "changeit", "changeit"}, 2, false},
		{"no password worked", encrypted, []string{"nope"}, -1, true},
		{"password-less file", plain, []string{"changeit", ""}, -1, false},
		{"password-less file without the empty password", plain, []string{"changeit"}, -1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, password, err := OpenPKCS12(tc.data, tc.passwords)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if password != tc.want {
				t.Errorf("password = %d, want %d", password, tc.want)
			}
			if !tc.wantErr && (len(got) != 1 || !bytes.Equal(got[0].Raw, root.Raw)) {
				t.Errorf("got %+v, want the root certificate", got)
			}
		})
	}
}

func TestParsePKCS12_ErrorListsAtMostThreeProblems(t *testing.T) {
	data := buildPFX(t, manyEncrypted(t, 5, 1))
	_, err := ParsePKCS12(data, []string{"x"})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "keystore: pkcs12: none of the 1 supplied passwords opened the file: SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: incorrect password; SafeContents #1") {
		t.Errorf("unexpected message start: %s", msg)
	}
	if !strings.HasSuffix(msg, "; and 2 more") || strings.Count(msg, "SafeContents #") != 3 {
		t.Errorf("message should name three parts and count the rest: %s", msg)
	}
	if got := fmt.Sprint(err); strings.Contains(got, "\n") {
		t.Errorf("error spans several lines: %q", got)
	}
}
