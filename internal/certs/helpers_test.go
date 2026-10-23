package certs

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
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Yanni8/emudhra-container-scanner/internal/blocklist"
)

// newCA returns a self-signed ECDSA P-256 CA certificate and its key.
func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(mathrand.Int63n(1<<62) + 1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"certs test"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// newLeaf returns a certificate for cn issued by parent.
func newLeaf(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(mathrand.Int63n(1<<62) + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// blocklistCert returns a certificate from the embedded blocklist.
func blocklistCert(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	e := blocklist.Default().ByID(id)
	if e == nil || e.Certificate == nil {
		t.Fatalf("blocklist entry %q missing", id)
	}
	return e.Certificate
}

// blocklistPatterns converts the blocklist's SPKI patterns for Scan.
func blocklistPatterns() []SPKIPattern {
	var out []SPKIPattern
	for _, p := range blocklist.Default().SPKIPatterns() {
		out = append(out, SPKIPattern{ID: p.Entry.ID, Pattern: p.Pattern})
	}
	return out
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemEncode(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

// randomBytes returns deterministic pseudo-random data.
func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	mathrand.New(mathrand.NewSource(seed)).Read(b)
	return b
}

// randomText returns deterministic printable data without PEM markers.
func randomText(seed int64, n int) []byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 \n"
	r := mathrand.New(mathrand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return b
}

// derTLV encodes one DER element with a definite length.
func derTLV(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	n := len(body)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, body...)
}

// pkcs7Bundle builds a DER PKCS#7 signedData structure that carries certs.
func pkcs7Bundle(certs ...*x509.Certificate) []byte {
	oidSignedData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	oidData := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	var certSet []byte
	for _, c := range certs {
		certSet = append(certSet, c.Raw...)
	}
	signed := derTLV(0x30,
		[]byte{0x02, 0x01, 0x01}, // version
		derTLV(0x31),             // digestAlgorithms
		derTLV(0x30, oidData),    // contentInfo
		derTLV(0xa0, certSet),    // certificates [0] IMPLICIT
		derTLV(0x31),             // signerInfos
	)
	return derTLV(0x30, oidSignedData, derTLV(0xa0, signed))
}

// --- JKS writer (format as in java.security.KeyStore) -----------------------

type jksEntry struct {
	alias string
	cert  *x509.Certificate
	chain []*x509.Certificate // private-key entry when set
}

func writeJKS(entries []jksEntry) []byte {
	var b []byte
	u32 := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	utf := func(s string) { b = binary.BigEndian.AppendUint16(b, uint16(len(s))); b = append(b, s...) }
	cert := func(c *x509.Certificate) { utf("X.509"); u32(uint32(len(c.Raw))); b = append(b, c.Raw...) }
	u32(0xFEEDFEED)
	u32(2)
	u32(uint32(len(entries)))
	for _, e := range entries {
		if e.chain != nil {
			u32(1)
			utf(e.alias)
			b = binary.BigEndian.AppendUint64(b, 1700000000000)
			key := []byte("not really an encrypted key")
			u32(uint32(len(key)))
			b = append(b, key...)
			u32(uint32(len(e.chain)))
			for _, c := range e.chain {
				cert(c)
			}
			continue
		}
		u32(2)
		utf(e.alias)
		b = binary.BigEndian.AppendUint64(b, 1700000000000)
		cert(e.cert)
	}
	h := sha1.New()
	for _, r := range "changeit" {
		h.Write([]byte{byte(r >> 8), byte(r)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(b)
	return append(b, h.Sum(nil)...)
}

// --- certdata.txt and p11-kit builders --------------------------------------

func octal(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		fmt.Fprintf(&sb, "\\%03o", c)
		if i%16 == 15 {
			sb.WriteByte('\n')
		}
	}
	sb.WriteString("\nEND\n")
	return sb.String()
}

// certdataText renders a CKO_CERTIFICATE object and its CKO_NSS_TRUST
// object with the given trust values ("" omits the trust object).
func certdataText(c *x509.Certificate, label, serverAuth, email, codeSign string) string {
	var sb strings.Builder
	sb.WriteString("#\n# Certificate \"" + label + "\"\n#\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n")
	sb.WriteString("CKA_TOKEN CK_BBOOL CK_TRUE\nCKA_PRIVATE CK_BBOOL CK_FALSE\nCKA_MODIFIABLE CK_BBOOL CK_FALSE\n")
	sb.WriteString("CKA_LABEL UTF8 \"" + label + "\"\nCKA_CERTIFICATE_TYPE CK_CERTIFICATE_TYPE CKC_X_509\n")
	sb.WriteString("CKA_SUBJECT MULTILINE_OCTAL\n" + octal(c.RawSubject))
	sb.WriteString("CKA_ID UTF8 \"0\"\n")
	sb.WriteString("CKA_ISSUER MULTILINE_OCTAL\n" + octal(c.RawIssuer))
	serial := c.SerialNumber.Bytes()
	if len(serial) > 0 && serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	serialDER := derTLV(0x02, serial)
	sb.WriteString("CKA_SERIAL_NUMBER MULTILINE_OCTAL\n" + octal(serialDER))
	sb.WriteString("CKA_VALUE MULTILINE_OCTAL\n" + octal(c.Raw))
	sb.WriteString("CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_TRUE\n\n")
	if serverAuth == "" {
		return sb.String()
	}
	sb.WriteString("# Trust for \"" + label + "\"\nCKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n")
	sb.WriteString("CKA_TOKEN CK_BBOOL CK_TRUE\nCKA_LABEL UTF8 \"" + label + "\"\n")
	sb.WriteString("CKA_CERT_SHA1_HASH MULTILINE_OCTAL\n" + octal(sha1sum(c.Raw)))
	sb.WriteString("CKA_ISSUER MULTILINE_OCTAL\n" + octal(c.RawIssuer))
	sb.WriteString("CKA_SERIAL_NUMBER MULTILINE_OCTAL\n" + octal(serialDER))
	sb.WriteString("CKA_TRUST_SERVER_AUTH CK_TRUST " + serverAuth + "\n")
	sb.WriteString("CKA_TRUST_EMAIL_PROTECTION CK_TRUST " + email + "\n")
	sb.WriteString("CKA_TRUST_CODE_SIGNING CK_TRUST " + codeSign + "\n")
	sb.WriteString("CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE\n\n")
	return sb.String()
}

func sha1sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

// p11Object renders a p11-kit certificate section.
func p11Object(c *x509.Certificate, label string, attrs ...string) string {
	var sb strings.Builder
	sb.WriteString("[p11-kit-object-v1]\nlabel: \"" + label + "\"\nclass: certificate\ncertificate-type: x-509\nmodifiable: false\n")
	for _, a := range attrs {
		sb.WriteString(a + "\n")
	}
	sb.Write(pemOf(c))
	sb.WriteString("\n")
	return sb.String()
}

// p11Extension renders a p11-kit x-certificate-extension section with the
// public key of c.
func p11Extension(c *x509.Certificate, label string) string {
	var sb strings.Builder
	sb.WriteString("[p11-kit-object-v1]\nlabel: \"" + label + "\"\nclass: x-certificate-extension\nobject-id: 2.5.29.37\nvalue: \"%30%16%06%03%55%1d%25%01%01%ff%04%0c%30%0a%06%08%2b%06%01%05%05%07%03%01\"\nmodifiable: false\n")
	sb.Write(pemEncode("PUBLIC KEY", c.RawSubjectPublicKeyInfo))
	sb.WriteString("\n")
	return sb.String()
}

// setWindow shrinks the scan window for a test and restores it afterwards.
func setWindow(t *testing.T, size, ov int) {
	t.Helper()
	oldSize, oldOverlap := windowSize, overlap
	windowSize, overlap = size, ov
	t.Cleanup(func() { windowSize, overlap = oldSize, oldOverlap })
}

// errReader fails after serving its data.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// maxReadReader serves data and records the largest read it was asked for.
// The scanner reads into the free space of its buffer, so a read longer than
// the window shows that the window grew.
type maxReadReader struct {
	r   *bytes.Reader
	max int
}

func (r *maxReadReader) Read(p []byte) (int, error) {
	r.max = max(r.max, len(p))
	return r.r.Read(p)
}

func offsets(found []Found) []int64 {
	var out []int64
	for _, f := range found {
		out = append(out, f.Offset)
	}
	return out
}

func findByKind(found []Found, kind Kind) []Found {
	var out []Found
	for _, f := range found {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func subjects(found []Found) []string {
	var out []string
	for _, f := range found {
		if f.Certificate != nil {
			out = append(out, f.Certificate.Subject.CommonName)
		} else {
			out = append(out, "spki:"+f.PatternID)
		}
	}
	return out
}
