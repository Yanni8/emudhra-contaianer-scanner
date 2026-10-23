package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
)

// --- shared helpers ---------------------------------------------------------

// newTestCert returns a self-signed ECDSA P-256 certificate and its key.
func newTestCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"keystore test"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert, key
}

// blocklistCert returns a real certificate from the embedded blocklist.
func blocklistCert(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	e := blocklist.Default().ByID(id)
	if e == nil || e.Certificate == nil {
		t.Fatalf("blocklist entry %q has no certificate", id)
	}
	return e.Certificate
}

// pemOf returns the PEM encoding of a certificate.
func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// elfHeader is the start of a 64-bit little-endian ELF file.
var elfHeader = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0}

// randomBytes returns deterministic pseudo-random data.
func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	mathrand.New(mathrand.NewSource(seed)).Read(b)
	return b
}

// checkEntry compares one entry with its expected values.
func checkEntry(t *testing.T, got Entry, alias string, raw []byte, fromKey, encrypted bool, created int64) {
	t.Helper()
	if got.Alias != alias {
		t.Errorf("alias = %q, want %q", got.Alias, alias)
	}
	if !bytes.Equal(got.Raw, raw) {
		t.Errorf("raw certificate bytes differ from the expected certificate (%d vs %d bytes)", len(got.Raw), len(raw))
	}
	if got.FromKeyEntry != fromKey {
		t.Errorf("FromKeyEntry = %v, want %v", got.FromKeyEntry, fromKey)
	}
	if got.Encrypted != encrypted {
		t.Errorf("Encrypted = %v, want %v", got.Encrypted, encrypted)
	}
	if got.Created != created {
		t.Errorf("Created = %d, want %d", got.Created, created)
	}
	if _, err := x509.ParseCertificate(got.Raw); err != nil {
		t.Errorf("entry does not hold a parsable certificate: %v", err)
	}
}

// expectBlocklistHit checks that the blocklist recognises the entry byte for byte.
func expectBlocklistHit(t *testing.T, e Entry, id string) {
	t.Helper()
	cert, err := x509.ParseCertificate(e.Raw)
	if err != nil {
		t.Fatalf("parsing entry %q: %v", e.Alias, err)
	}
	matches := blocklist.Default().MatchCertificate(cert)
	if len(matches) == 0 || matches[0].Kind != blocklist.MatchFingerprint || matches[0].Entry.ID != id {
		t.Errorf("entry %q: blocklist matches = %+v, want fingerprint match on %q", e.Alias, matches, id)
	}
}

// --- JKS writer -------------------------------------------------------------

type jksCert struct {
	typ string // certificate type written in version-2 stores; "" means "X.509"
	der []byte
}

type jksEntry struct {
	tag      uint32
	alias    string
	aliasRaw []byte // when set, written instead of alias (for modified UTF-8 cases)
	created  int64
	key      []byte    // tag 1: the (encrypted) private key blob
	certs    []jksCert // tag 1: the chain; tag 2: the single certificate
	blob     []byte    // tag 3: raw bytes standing in for the serialized SealedObject
}

type jksWriter struct{ b []byte }

func (w *jksWriter) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *jksWriter) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *jksWriter) i64(v int64)  { w.b = binary.BigEndian.AppendUint64(w.b, uint64(v)) }
func (w *jksWriter) utf(s []byte) { w.u16(uint16(len(s))); w.b = append(w.b, s...) }

// writeJKS serialises a keystore the way java.security.KeyStore does,
// including the SHA-1 integrity digest for the password "changeit".
func writeJKS(magic, version uint32, entries []jksEntry) []byte {
	w := &jksWriter{}
	w.u32(magic)
	w.u32(version)
	w.u32(uint32(len(entries)))
	for _, e := range entries {
		w.u32(e.tag)
		if e.aliasRaw != nil {
			w.utf(e.aliasRaw)
		} else {
			w.utf([]byte(e.alias))
		}
		w.i64(e.created)
		writeCert := func(c jksCert) {
			if version == 2 {
				typ := c.typ
				if typ == "" {
					typ = "X.509"
				}
				w.utf([]byte(typ))
			}
			w.u32(uint32(len(c.der)))
			w.b = append(w.b, c.der...)
		}
		switch e.tag {
		case jksTagPrivateKey:
			w.u32(uint32(len(e.key)))
			w.b = append(w.b, e.key...)
			w.u32(uint32(len(e.certs)))
			for _, c := range e.certs {
				writeCert(c)
			}
		case jksTagTrustedCert:
			writeCert(e.certs[0])
		default:
			w.b = append(w.b, e.blob...)
		}
	}
	w.b = append(w.b, jksDigest("changeit", w.b)...)
	return w.b
}

// jksDigest is SHA-1(password as UTF-16BE || "Mighty Aphrodite" || data).
func jksDigest(password string, data []byte) []byte {
	h := sha1.New()
	for _, r := range password {
		h.Write([]byte{byte(r >> 8), byte(r)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(data)
	return h.Sum(nil)
}

// sampleStore builds a representative store: two trusted certificates (one
// from the blocklist), a private-key entry with a three-certificate chain and
// a final trusted certificate. It returns the store and the expected entries.
func sampleStore(t *testing.T, magic, version uint32) ([]byte, []Entry) {
	t.Helper()
	self, _ := newTestCert(t, "self-signed test")
	leaf, _ := newTestCert(t, "leaf.example")
	emsign := blocklistCert(t, "emsign-ecc-root-ca-g3")
	aaa := blocklistCert(t, "aaa-certificate-services")
	dv := blocklistCert(t, "em-dv-tls-ca-g3b")
	data := writeJKS(magic, version, []jksEntry{
		{tag: jksTagTrustedCert, alias: "emsign ecc root ca - g3", created: 1_700_000_000_000, certs: []jksCert{{der: emsign.Raw}}},
		{tag: jksTagTrustedCert, alias: "self", created: 1_700_000_000_001, certs: []jksCert{{der: self.Raw}}},
		{tag: jksTagPrivateKey, alias: "server", created: 1_700_000_000_002, key: randomBytes(7, 100),
			certs: []jksCert{{der: leaf.Raw}, {der: dv.Raw}, {der: emsign.Raw}}},
		{tag: jksTagTrustedCert, alias: "aaa", created: 1_700_000_000_003, certs: []jksCert{{der: aaa.Raw}}},
	})
	want := []Entry{
		{Alias: "emsign ecc root ca - g3", Raw: emsign.Raw, Created: 1_700_000_000_000},
		{Alias: "self", Raw: self.Raw, Created: 1_700_000_000_001},
		{Alias: "server", Raw: leaf.Raw, FromKeyEntry: true, Created: 1_700_000_000_002},
		{Alias: "server", Raw: dv.Raw, FromKeyEntry: true, Created: 1_700_000_000_002},
		{Alias: "server", Raw: emsign.Raw, FromKeyEntry: true, Created: 1_700_000_000_002},
		{Alias: "aaa", Raw: aaa.Raw, Created: 1_700_000_000_003},
	}
	return data, want
}

func checkEntries(t *testing.T, got, want []Entry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		checkEntry(t, got[i], want[i].Alias, want[i].Raw, want[i].FromKeyEntry, want[i].Encrypted, want[i].Created)
	}
}

// --- IsJKS ------------------------------------------------------------------

func TestIsJKS(t *testing.T) {
	root := blocklistCert(t, "emsign-ecc-root-ca-g3")
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"JKS magic", []byte{0xFE, 0xED, 0xFE, 0xED}, true},
		{"JCEKS magic", []byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2}, true},
		{"empty", nil, false},
		{"three bytes of magic", []byte{0xFE, 0xED, 0xFE}, false},
		{"wrong magic", []byte{0xFE, 0xED, 0xFE, 0xEE}, false},
		{"PEM", pemOf(root), false},
		{"DER certificate", root.Raw, false},
		{"ELF", elfHeader, false},
		{"random", randomBytes(1, 64), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsJKS(tc.data); got != tc.want {
				t.Errorf("IsJKS = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- ParseJKS ---------------------------------------------------------------

func TestParseJKS_Formats(t *testing.T) {
	tests := []struct {
		name    string
		magic   uint32
		version uint32
	}{
		{"JKS version 2", magicJKS, 2},
		{"JKS version 1", magicJKS, 1},
		{"JCEKS version 2", magicJCEKS, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, want := sampleStore(t, tc.magic, tc.version)
			got, err := ParseJKS(data)
			if err != nil {
				t.Fatalf("ParseJKS: %v", err)
			}
			checkEntries(t, got, want)
			expectBlocklistHit(t, got[0], "emsign-ecc-root-ca-g3")
			expectBlocklistHit(t, got[3], "em-dv-tls-ca-g3b")
			expectBlocklistHit(t, got[5], "aaa-certificate-services")
			// Entries must not alias the input buffer.
			for i := range data {
				data[i] = 0
			}
			if _, err := x509.ParseCertificate(got[0].Raw); err != nil {
				t.Errorf("entry shares memory with the input: %v", err)
			}
		})
	}
}

func TestParseJKS_CertificateTypes(t *testing.T) {
	self, _ := newTestCert(t, "self")
	other, _ := newTestCert(t, "other")
	data := writeJKS(magicJKS, 2, []jksEntry{
		{tag: jksTagTrustedCert, alias: "pgp", certs: []jksCert{{typ: "OpenPGP", der: randomBytes(2, 300)}}},
		{tag: jksTagTrustedCert, alias: "x509-alias", certs: []jksCert{{typ: "X509", der: self.Raw}}},
		{tag: jksTagPrivateKey, alias: "key", key: randomBytes(3, 40),
			certs: []jksCert{{typ: "SDSI", der: randomBytes(4, 50)}, {der: other.Raw}}},
		{tag: jksTagPrivateKey, alias: "empty-chain", key: randomBytes(5, 40)},
		{tag: jksTagTrustedCert, alias: "last", certs: []jksCert{{der: self.Raw}}},
	})
	got, err := ParseJKS(data)
	if err != nil {
		t.Fatalf("ParseJKS: %v", err)
	}
	checkEntries(t, got, []Entry{
		{Alias: "x509-alias", Raw: self.Raw},
		{Alias: "key", Raw: other.Raw, FromKeyEntry: true},
		{Alias: "last", Raw: self.Raw},
	})
}

func TestParseJKS_Aliases(t *testing.T) {
	self, _ := newTestCert(t, "self")
	tests := []struct {
		name  string
		raw   []byte
		alias string
	}{
		{"plain", []byte("server"), "server"},
		{"standard UTF-8", []byte("ümlaut-ß"), "ümlaut-ß"},
		{"embedded NUL as C0 80", []byte{'a', 0xC0, 0x80, 'b'}, "a\x00b"},
		{"supplementary character as surrogate pair", []byte{'x', 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}, "x\U0001F600"},
		{"lone high surrogate", []byte{0xED, 0xA0, 0xBD, 'z'}, "�z"},
		{"truncated sequence", []byte{'a', 0xE2, 0x82}, "a��"},
		{"invalid bytes", []byte{0xFF, 0xFE, 'q'}, "��q"},
		{"empty", []byte{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := writeJKS(magicJKS, 2, []jksEntry{
				{tag: jksTagTrustedCert, aliasRaw: tc.raw, certs: []jksCert{{der: self.Raw}}},
			})
			got, err := ParseJKS(data)
			if err != nil {
				t.Fatalf("ParseJKS: %v", err)
			}
			if len(got) != 1 || got[0].Alias != tc.alias {
				t.Fatalf("got %+v, want one entry with alias %q", got, tc.alias)
			}
		})
	}
}

func TestParseJKS_SecretKeyEntryStopsParsing(t *testing.T) {
	self, _ := newTestCert(t, "self")
	data := writeJKS(magicJCEKS, 2, []jksEntry{
		{tag: jksTagTrustedCert, alias: "before", certs: []jksCert{{der: self.Raw}}},
		{tag: jksTagSecretKey, alias: "hmac-key", blob: append([]byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72}, randomBytes(6, 200)...)},
		{tag: jksTagTrustedCert, alias: "after", certs: []jksCert{{der: self.Raw}}},
	})
	got, err := ParseJKS(data)
	if !errors.Is(err, ErrSecretKeyEntry) {
		t.Fatalf("err = %v, want ErrSecretKeyEntry", err)
	}
	if errors.Is(err, ErrFormat) {
		t.Errorf("a secret-key entry must not be reported as ErrFormat: %v", err)
	}
	if !strings.Contains(err.Error(), `"hmac-key"`) || !strings.Contains(err.Error(), "1 entries after it") {
		t.Errorf("error should name the entry and the count of lost entries: %v", err)
	}
	checkEntries(t, got, []Entry{{Alias: "before", Raw: self.Raw}})
}

func TestParseJKS_Errors(t *testing.T) {
	self, _ := newTestCert(t, "self")
	one := writeJKS(magicJKS, 2, []jksEntry{{tag: jksTagTrustedCert, alias: "a", created: 5, certs: []jksCert{{der: self.Raw}}}})
	two := writeJKS(magicJKS, 2, []jksEntry{
		{tag: jksTagTrustedCert, alias: "a", certs: []jksCert{{der: self.Raw}}},
		{tag: jksTagTrustedCert, alias: "b", certs: []jksCert{{der: self.Raw}}},
	})
	patch := func(data []byte, off int, v uint32) []byte {
		out := bytes.Clone(data)
		binary.BigEndian.PutUint32(out[off:], v)
		return out
	}
	header := func(magic, version, count uint32) []byte {
		w := &jksWriter{}
		w.u32(magic)
		w.u32(version)
		w.u32(count)
		return w.b
	}
	// Offsets inside "one": 12 tag, 16 alias length, 18 alias ("a"), 19 date,
	// 27 type length, 29 type ("X.509"), 34 certificate length, 38 certificate.
	const certLenOff = 34
	corruptCert := bytes.Clone(one)
	for i := 38; i < 38+len(self.Raw); i++ {
		corruptCert[i] = 0
	}

	tests := []struct {
		name        string
		data        []byte
		wantEntries int
		wantErr     error // sentinel the error must wrap; nil means no error
		wantNoErr   bool
		wantMsg     string
	}{
		{name: "empty", data: nil, wantErr: ErrFormat},
		{name: "two bytes", data: []byte{0xFE, 0xED}, wantErr: ErrFormat},
		{name: "PEM", data: pemOf(self), wantErr: ErrFormat},
		{name: "random", data: randomBytes(9, 200), wantErr: ErrFormat},
		{name: "unsupported version 3", data: header(magicJKS, 3, 0), wantErr: ErrFormat, wantMsg: "version 3"},
		{name: "unsupported version 0", data: header(magicJKS, 0, 0), wantErr: ErrFormat},
		{name: "magic only", data: []byte{0xFE, 0xED, 0xFE, 0xED}, wantErr: io.ErrUnexpectedEOF},
		{name: "header only", data: header(magicJKS, 2, 1), wantErr: io.ErrUnexpectedEOF},
		{name: "zero entries without digest", data: header(magicJKS, 2, 0), wantErr: io.ErrUnexpectedEOF},
		{name: "zero entries with digest", data: append(header(magicJKS, 2, 0), make([]byte, 20)...), wantNoErr: true},
		{name: "unknown tag", data: patch(one, 12, 7), wantMsg: "unknown entry tag 7"},
		{name: "absurd certificate length", data: patch(one, certLenOff, 0xFFFFFFFF), wantErr: io.ErrUnexpectedEOF, wantMsg: "need 4294967295 bytes"},
		{name: "absurd alias length", data: append(bytes.Clone(one[:16]), 0xFF, 0xFF, 'a'), wantErr: io.ErrUnexpectedEOF, wantMsg: "alias"},
		{name: "absurd entry count", data: patch(two, 8, 0xFFFFFFFF), wantEntries: 2, wantErr: io.ErrUnexpectedEOF},
		{name: "missing digest", data: two[:len(two)-20], wantEntries: 2, wantErr: io.ErrUnexpectedEOF, wantMsg: "integrity digest"},
		{name: "short digest", data: two[:len(two)-1], wantEntries: 2, wantErr: io.ErrUnexpectedEOF},
		{name: "corrupt certificate bytes", data: corruptCert, wantEntries: 0, wantMsg: `entry 0 ("a") certificate`},
		{name: "count below actual entries", data: patch(two, 8, 1), wantEntries: 1, wantNoErr: true},
		{name: "trailing data after digest", data: append(bytes.Clone(two), randomBytes(10, 33)...), wantEntries: 2, wantNoErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseJKS(tc.data)
			if len(got) != tc.wantEntries {
				t.Errorf("got %d entries, want %d", len(got), tc.wantEntries)
			}
			switch {
			case tc.wantNoErr:
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case err == nil:
				t.Fatalf("expected an error")
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Errorf("err = %v, want it to wrap %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantMsg)) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			if err != nil && tc.wantErr != ErrFormat && errors.Is(err, ErrFormat) {
				t.Errorf("a store with valid magic and version must not be reported as ErrFormat: %v", err)
			}
		})
	}
}

func TestParseJKS_CorruptCertificateDoesNotHideOthers(t *testing.T) {
	a, _ := newTestCert(t, "a")
	b, _ := newTestCert(t, "b")
	broken := bytes.Clone(a.Raw)
	broken[len(broken)/2] ^= 0xFF
	data := writeJKS(magicJKS, 2, []jksEntry{
		{tag: jksTagTrustedCert, alias: "good-1", certs: []jksCert{{der: a.Raw}}},
		{tag: jksTagTrustedCert, alias: "broken", certs: []jksCert{{der: broken}}},
		{tag: jksTagPrivateKey, alias: "key", key: randomBytes(8, 10), certs: []jksCert{{der: broken}, {der: b.Raw}}},
		{tag: jksTagTrustedCert, alias: "good-2", certs: []jksCert{{der: b.Raw}}},
	})
	got, err := ParseJKS(data)
	if err == nil {
		t.Fatal("expected an error for the corrupt certificates")
	}
	for _, want := range []string{`entry 1 ("broken") certificate`, `entry 2 ("key") chain certificate 0`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrFormat) {
		t.Errorf("corrupt certificates are neither truncation nor a format error: %v", err)
	}
	checkEntries(t, got, []Entry{
		{Alias: "good-1", Raw: a.Raw},
		{Alias: "key", Raw: b.Raw, FromKeyEntry: true},
		{Alias: "good-2", Raw: b.Raw},
	})
}

func TestParseJKS_TruncationNeverPanics(t *testing.T) {
	data, want := sampleStore(t, magicJKS, 2)
	full, err := ParseJKS(data)
	if err != nil {
		t.Fatalf("full store: %v", err)
	}
	checkEntries(t, full, want)
	for n := 0; n < len(data); n++ {
		got, err := ParseJKS(data[:n])
		if err == nil {
			t.Fatalf("prefix of %d/%d bytes parsed without error", n, len(data))
		}
		if n >= 4 && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("prefix of %d bytes: err = %v, want io.ErrUnexpectedEOF", n, err)
		}
		if len(got) > len(full) {
			t.Fatalf("prefix of %d bytes returned %d entries, more than the full store", n, len(got))
		}
		for i := range got {
			if got[i].Alias != full[i].Alias || !bytes.Equal(got[i].Raw, full[i].Raw) || got[i].FromKeyEntry != full[i].FromKeyEntry {
				t.Fatalf("prefix of %d bytes: entry %d differs from the full store's", n, i)
			}
		}
	}
}

func TestParseJKS_RandomCorruptionNeverPanics(t *testing.T) {
	data, _ := sampleStore(t, magicJCEKS, 2)
	rng := mathrand.New(mathrand.NewSource(2026))
	for i := 0; i < 3000; i++ {
		mutated := bytes.Clone(data)
		for k := 0; k < 1+rng.Intn(4); k++ {
			mutated[rng.Intn(len(mutated))] = byte(rng.Intn(256))
		}
		if rng.Intn(4) == 0 {
			mutated = mutated[:rng.Intn(len(mutated)+1)]
		}
		got, err := ParseJKS(mutated)
		for _, e := range got {
			if _, perr := x509.ParseCertificate(e.Raw); perr != nil {
				t.Fatalf("iteration %d: returned an unparsable certificate (err=%v): %v", i, err, perr)
			}
		}
	}
}
