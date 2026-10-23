package certs

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

var (
	pemBeginMarker = []byte("-----BEGIN ")
	pemEndMarker   = []byte("-----END ")
	pemDashes      = []byte("-----")
)

// labelContext is how far before a PEM block the label heuristics look.
const labelContext = 2048

// minReportedBody is the smallest decoded block body whose rejection by the
// certificate parser is worth a warning: shorter bodies are templates and
// placeholders ("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
// not damaged certificates.
const minReportedBody = 64

// pemBlock is a decoded PEM block together with its position in the data.
type pemBlock struct {
	start, end int // [start, end) of the block text
	block      *pem.Block
}

// eachPEM calls fn for every PEM block whose "-----BEGIN" marker lies in
// [from, limit) of data. fn returns false to stop. unfinished is the offset
// of the first block that begins like a real one (isPEMLabel and
// looksLikePEMBody) but whose END marker lies beyond the end of data, so
// that a longer buffer may complete it, or -1; label is that block's type.
func eachPEM(data []byte, from, limit int, fn func(b pemBlock) bool) (unfinished int, label string) {
	unfinished = -1
	if from < 0 {
		from = 0
	}
	if limit > len(data) {
		limit = len(data)
	}
	pos := from
	for pos < limit {
		i := bytes.Index(data[pos:], pemBeginMarker)
		if i < 0 {
			return unfinished, label
		}
		start := pos + i
		if start >= limit {
			return unfinished, label
		}
		typeStart := start + len(pemBeginMarker)
		typeEnd := bytes.Index(data[typeStart:], pemDashes)
		if typeEnd < 0 || typeEnd > 128 {
			pos = typeStart
			continue
		}
		typ := data[typeStart : typeStart+typeEnd]
		trailer := append(append([]byte("-----END "), typ...), pemDashes...)
		bodyStart := typeStart + typeEnd + len(pemDashes)
		j := bytes.Index(data[bodyStart:], trailer)
		if j < 0 {
			// Incomplete in this data. A block that begins like a real one
			// is remembered for a longer buffer; the search carries on
			// either way, since the marker may be a stray one.
			if unfinished < 0 && isPEMLabel(typ) && looksLikePEMBody(data[bodyStart:]) {
				unfinished, label = start, string(typ)
			}
			pos = typeStart
			continue
		}
		end := bodyStart + j + len(trailer)
		block := decodePEM(data[start:end], string(typ), data[bodyStart:bodyStart+j])
		if block == nil {
			pos = typeStart
			continue
		}
		if !fn(pemBlock{start: start, end: end, block: block}) {
			return unfinished, label
		}
		pos = end
	}
	return unfinished, label
}

// A block that runs past the end of a buffer is only worth completing from
// a longer one when it begins like a real block: "-----BEGIN " also occurs
// in binaries as a printf format string, a class constant and a neighbour
// of unrelated string constants, and those never have an END marker.
// maxPEMLabel bounds the label of a block worth completing; pemBodySample
// is how many bytes after its BEGIN line are examined and pemBodyMinBase64
// how many of them must be base64 characters.
const (
	maxPEMLabel      = 64
	pemBodySample    = 64
	pemBodyMinBase64 = 16
)

// isPEMLabel reports whether label is the type of a real PEM block: one to
// maxPEMLabel upper-case letters, digits and spaces, starting with a letter
// or digit ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE",
// "PKCS7", "PUBLIC KEY"). An empty label, "%s", lower-case text and binary
// garbage are not.
func isPEMLabel(label []byte) bool {
	if len(label) == 0 || len(label) > maxPEMLabel || label[0] == ' ' {
		return false
	}
	for _, c := range label {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ') {
			return false
		}
	}
	return true
}

// looksLikePEMBody reports whether rest, the bytes after the closing dashes
// of a BEGIN line, starts a base64 body: a line break (LF or CRLF, also
// written as the escape "\n" of a JSON or source string, which base64Body
// reads too), then nothing but base64 characters, '=' and whitespace in the
// first pemBodySample bytes that are present, at least pemBodyMinBase64 of
// them base64 characters. A "-----BEGIN CERTIFICATE-----\n" constant in a
// program's string table is followed by other strings and fails this.
func looksLikePEMBody(rest []byte) bool {
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	rest = rest[i:]
	switch {
	case bytes.HasPrefix(rest, []byte("\r\n")):
		rest = rest[2:]
	case bytes.HasPrefix(rest, []byte("\n")):
		rest = rest[1:]
	case bytes.HasPrefix(rest, []byte(`\r\n`)):
		rest = rest[4:]
	case bytes.HasPrefix(rest, []byte(`\n`)):
		rest = rest[2:]
	default:
		return false
	}
	n := 0
	for j := 0; j < len(rest) && j < pemBodySample; j++ {
		switch c := rest[j]; {
		case c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c == '\\' && j+1 < len(rest) && strings.IndexByte("nrt", rest[j+1]) >= 0:
			j++
		case isBase64Byte(c):
			n++
		default:
			return false
		}
	}
	return n >= pemBodyMinBase64
}

// decodePEM decodes one block whose text is text and whose body (between the
// BEGIN line's closing dashes and the END marker) is body. Blocks with
// headers are left to encoding/pem; everything else is base64-decoded
// leniently, so that indented blocks (YAML, Helm values, source literals)
// and JSON-escaped ones (literal "\n") are read too. nil means the block
// cannot be decoded.
func decodePEM(text []byte, typ string, body []byte) *pem.Block {
	if bytes.IndexByte(body, ':') >= 0 { // headers such as Proc-Type
		block, _ := pem.Decode(text)
		return block
	}
	b64, ok := base64Body(body)
	if !ok {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "="))
	}
	if err != nil {
		return nil
	}
	return &pem.Block{Type: typ, Bytes: raw}
}

// base64Body strips whitespace and escape sequences from a PEM body. Real
// newlines, carriage returns, tabs and spaces are dropped, as are the
// two-character escapes "\n", "\r" and "\t" of a JSON or source string; the
// escape "\/" stands for a slash. Any other character means the text is not
// a PEM body.
func base64Body(body []byte) (string, bool) {
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c == '\\' && i+1 < len(body) && strings.IndexByte("nrt", body[i+1]) >= 0:
			i++
		case c == '\\' && i+1 < len(body) && body[i+1] == '/':
			out = append(out, '/')
			i++
		case isBase64Byte(c):
			out = append(out, c)
		default:
			return "", false
		}
	}
	return string(out), true
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// isCertificateType reports whether a PEM block type holds one certificate.
func isCertificateType(typ string) bool {
	switch typ {
	case "CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE":
		return true
	}
	return false
}

// isPKCS7Type reports whether a PEM block type holds a PKCS#7 bundle.
func isPKCS7Type(typ string) bool {
	return strings.Contains(typ, "PKCS7") || strings.Contains(typ, "PKCS #7")
}

// pemFound converts a decoded PEM block into the certificates it holds.
// Blocks of other types yield nothing. Offsets are relative to base.
func pemFound(data []byte, b pemBlock, base int64, warn func(string)) []Found {
	offset := base + int64(b.start)
	switch typ := b.block.Type; {
	case isCertificateType(typ):
		return certificateBlock(data, b, base, KindPEM, warn)
	case typ == "TRUSTED CERTIFICATE":
		return certificateBlock(data, b, base, KindPEMTrusted, warn)
	case isPKCS7Type(typ):
		found, _ := carveDER(b.block.Bytes, 0, len(b.block.Bytes), 0, KindPKCS7)
		label := labelBefore(data, b.start)
		for i := range found {
			found[i].Offset = offset
			found[i].Label = label
		}
		return found
	}
	return nil
}

// certificateBlock reads the certificate of a CERTIFICATE or TRUSTED
// CERTIFICATE block: the first DER element of the body, as OpenSSL does.
// Bytes after it are read as a CertAux trust trailer when they are one (a
// TRUSTED CERTIFICATE block, or a CERTIFICATE block renamed from one, which
// OpenSSL's PEM_read_bio_X509_AUX honours) and noted otherwise.
func certificateBlock(data []byte, b pemBlock, base int64, kind Kind, warn func(string)) []Found {
	offset := base + int64(b.start)
	body := b.block.Bytes
	cert, raw, ok := parseCertificate(firstDER(body))
	if !ok {
		if len(body) >= minReportedBody {
			warnf(warn, "PEM %s block at offset %d was rejected by the strict X.509 parser", b.block.Type, offset)
		}
		return nil
	}
	f := Found{Certificate: cert, Raw: raw, Kind: kind, Offset: offset}
	switch aux := body[len(raw):]; {
	case len(aux) == 0 && kind == KindPEMTrusted:
		f.TrustDetail = "no CertAux trailer"
	case len(aux) == 0:
	default:
		ca, ok := DecodeCertAux(aux)
		switch {
		case ok && (kind == KindPEMTrusted || ca.Purposes != nil || ca.Alias != ""):
			f.Trust, f.TrustDetail, f.Purposes, f.Label = ca.Trust, ca.Detail, ca.Purposes, ca.Alias
			if kind == KindPEM {
				f.Note = "CertAux trust trailer after the certificate (a renamed TRUSTED CERTIFICATE block)"
			}
		case kind == KindPEMTrusted:
			f.TrustDetail = "unparsable CertAux trailer"
		default:
			f.Note = fmt.Sprintf("ignored %d trailing bytes after the certificate", len(aux))
		}
	}
	if f.Label == "" {
		f.Label = labelBefore(data, b.start)
	}
	return []Found{f}
}

// labelBefore recovers the human label that bundle generators write before a
// PEM block: certifi's "# Label: "..."" comment, the curl/Mozilla::CA style
// of a name line underlined with "=" (optionally followed by "# key: value"
// comments such as curl's fingerprint line) and p11-kit's bare "# Name"
// comment.
func labelBefore(data []byte, start int) string {
	lo := start - labelContext
	if lo < 0 {
		lo = 0
	}
	ctx := data[lo:start]
	if i := bytes.LastIndex(ctx, pemEndMarker); i >= 0 {
		// Only look between the previous block and this one.
		if nl := bytes.IndexByte(ctx[i:], '\n'); nl >= 0 {
			ctx = ctx[i+nl+1:]
		} else {
			ctx = nil
		}
	}
	lines := strings.Split(string(ctx), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if rest, ok := strings.CutPrefix(line, "# Label:"); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		// curl-style: the line before a line of "=" characters.
		if len(line) >= 3 && strings.Trim(line, "=") == "" && i >= 1 {
			if name := strings.TrimSpace(lines[i-1]); name != "" && !strings.HasPrefix(name, "#") {
				return name
			}
			return ""
		}
		rest, comment := strings.CutPrefix(line, "#")
		if !comment {
			return ""
		}
		name := strings.TrimSpace(rest)
		if strings.Contains(name, ": ") || strings.HasSuffix(name, ":") {
			continue // "# Serial: 1", "# Fingerprint (SHA-256): ...": metadata, keep looking
		}
		// p11-kit extracted bundles: a bare "# Name" comment right before
		// the block.
		if name != "" {
			return name
		}
		return ""
	}
	return ""
}

// ScanPEM decodes every PEM block in data. CERTIFICATE and X509 CERTIFICATE
// blocks yield KindPEM; TRUSTED CERTIFICATE blocks yield KindPEMTrusted with
// trust flags from the CertAux trailer; PKCS7 blocks yield KindPKCS7 for each
// certificate inside; other block types are ignored. Offsets are relative to
// base.
func ScanPEM(data []byte, base int64) []Found {
	var out []Found
	eachPEM(data, 0, len(data), func(b pemBlock) bool {
		out = append(out, pemFound(data, b, base, nil)...)
		return true
	})
	return out
}
