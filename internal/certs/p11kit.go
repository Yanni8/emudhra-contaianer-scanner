package certs

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// p11kitHeader starts every object in a p11-kit trust file.
var p11kitHeader = []byte("[p11-kit-object-v1]")

// oidExtKeyUsage is the id-ce-extKeyUsage extension (2.5.29.37), which
// p11-kit stores in x-certificate-extension objects to limit the purposes
// an anchor is trusted for.
const oidExtKeyUsage = "2.5.29.37"

// p11Section is one [p11-kit-object-v1] section.
type p11Section struct {
	offset int64
	attrs  map[string]string
	blocks []pemBlock
}

// parseP11Kit splits a p11-kit trust file into its sections.
func parseP11Kit(data []byte) []p11Section {
	var sections []p11Section
	pos := 0
	for pos < len(data) {
		i := bytes.Index(data[pos:], p11kitHeader)
		if i < 0 {
			break
		}
		start := pos + i
		next := len(data)
		if j := bytes.Index(data[start+len(p11kitHeader):], p11kitHeader); j >= 0 {
			next = start + len(p11kitHeader) + j
		}
		body := data[start:next]
		sec := p11Section{offset: int64(start), attrs: map[string]string{}}
		// Attribute lines: everything before the first PEM block, plus the
		// lines between blocks.
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "-----") {
				continue
			}
			if !strings.ContainsAny(line, ":") || isBase64Line(line) {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			if _, dup := sec.attrs[key]; dup {
				continue
			}
			sec.attrs[key] = p11Unquote(strings.TrimSpace(value))
		}
		eachPEM(body, 0, len(body), func(b pemBlock) bool {
			b.start += start
			b.end += start
			sec.blocks = append(sec.blocks, b)
			return true
		})
		sections = append(sections, sec)
		pos = next
	}
	return sections
}

// isBase64Line reports whether a line looks like PEM body text (which never
// contains ':' but is excluded defensively).
func isBase64Line(line string) bool {
	if len(line) < 4 {
		return false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// p11Unquote removes the quotes around a p11-kit attribute value and decodes
// its %XX escapes.
func p11Unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if !strings.Contains(v, "%") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			if d, err := hex.DecodeString(v[i+1 : i+3]); err == nil {
				b.WriteByte(d[0])
				i += 2
				continue
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// p11Trust derives trust from a section's attributes and the purposes of the
// extended-key-usage extension object attached to its public key, if any
// (hasEKU): "x-distrusted: true" distrusts every purpose; "trusted: true"
// anchors every purpose, or only the listed ones when an extension limits
// them (p11-kit extracts such a certificate only into the bundles of those
// purposes); anything else is neutral.
func p11Trust(attrs map[string]string, eku []Purpose, hasEKU bool) (TrustState, string, map[Purpose]TrustState) {
	trusted, hasTrusted := attrs["trusted"]
	distrusted, hasDistrusted := attrs["x-distrusted"]
	switch {
	case hasDistrusted && distrusted == "true":
		return TrustDistrusted, "x-distrusted: true", uniformPurposes(TrustDistrusted)
	case hasTrusted && trusted == "true" && hasEKU:
		purposes := uniformPurposes(TrustNeutral)
		for _, p := range eku {
			purposes[p] = TrustAnchor
		}
		return summariseTrust(purposes, false), "trusted: true; extended key usage: " + joinPurposes(eku), purposes
	case hasTrusted && trusted == "true":
		return TrustAnchor, "trusted: true", uniformPurposes(TrustAnchor)
	case hasTrusted:
		return TrustNeutral, "trusted: " + trusted, uniformPurposes(TrustNeutral)
	}
	return TrustNeutral, "no trusted/x-distrusted attribute", uniformPurposes(TrustNeutral)
}

// p11Certificate returns the DER certificate of a certificate section: its
// PEM CERTIFICATE block or, for a section that declares class "certificate"
// without a PEM block, its "value" attribute. Sections of other classes
// (x-certificate-extension objects carry only a PUBLIC KEY) yield nil.
func p11Certificate(sec p11Section) ([]byte, int64) {
	class, hasClass := sec.attrs["class"]
	if hasClass && class != "certificate" {
		return nil, 0
	}
	for _, b := range sec.blocks {
		if isCertificateType(b.block.Type) {
			return firstDER(b.block.Bytes), int64(b.start)
		}
	}
	if v := sec.attrs["value"]; hasClass && len(v) > 16 && v[0] == 0x30 {
		return firstDER([]byte(v)), sec.offset
	}
	return nil, 0
}

// p11Extensions collects, keyed by DER public key, the purposes named by the
// x-certificate-extension objects that carry an extended-key-usage
// extension. p11-kit attaches such objects to the public key of the
// certificate they limit.
func p11Extensions(sections []p11Section) map[string][]Purpose {
	var out map[string][]Purpose
	for _, sec := range sections {
		if sec.attrs["class"] != "x-certificate-extension" || sec.attrs["object-id"] != oidExtKeyUsage {
			continue
		}
		purposes, ok := extKeyUsagePurposes([]byte(sec.attrs["value"]))
		if !ok {
			continue
		}
		for _, b := range sec.blocks {
			if b.block.Type != "PUBLIC KEY" {
				continue
			}
			if out == nil {
				out = map[string][]Purpose{}
			}
			key := string(b.block.Bytes)
			out[key] = append(out[key], purposes...)
		}
	}
	return out
}

// extKeyUsagePurposes decodes an Extension holding id-ce-extKeyUsage
//
//	Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
//	ExtKeyUsageSyntax ::= SEQUENCE OF OBJECT IDENTIFIER
//
// into the standard purposes it names; anyExtendedKeyUsage names them all.
func extKeyUsagePurposes(der []byte) ([]Purpose, bool) {
	ext, _, ok := readTLV(der)
	if !ok || !ext.isSequence() {
		return nil, false
	}
	id, rest, ok := readTLV(ext.value)
	if !ok || id.class != 0 || id.tag != 6 || oidString(id.value) != oidExtKeyUsage {
		return nil, false
	}
	value, rest, ok := readTLV(rest)
	if ok && value.class == 0 && value.tag == 1 { // critical BOOLEAN
		value, _, ok = readTLV(rest)
	}
	if !ok || value.class != 0 || value.tag != 4 || value.compound {
		return nil, false
	}
	list, _, ok := readTLV(value.value)
	if !ok || !list.isSequence() {
		return nil, false
	}
	oids, ok := oidList(list.value)
	if !ok {
		return nil, false
	}
	var out []Purpose
	for _, oid := range oids {
		if oid == oidAnyExtendedKeyUsage {
			return append([]Purpose(nil), standardPurposes...), true
		}
		if p, known := purposeOIDs[oid]; known {
			out = append(out, p)
		}
	}
	return out, true
}

// p11Found converts the certificate sections of a parsed file into Founds.
func p11Found(sections []p11Section) []Found {
	extensions := p11Extensions(sections)
	var out []Found
	for _, sec := range sections {
		der, offset := p11Certificate(sec)
		if der == nil {
			continue
		}
		cert, raw, ok := parseCertificate(der)
		if !ok {
			continue
		}
		eku, hasEKU := extensions[string(cert.RawSubjectPublicKeyInfo)]
		trust, detail, purposes := p11Trust(sec.attrs, eku, hasEKU)
		out = append(out, Found{Certificate: cert, Raw: raw, Kind: KindP11Kit, Offset: offset, Label: sec.attrs["label"], Trust: trust, TrustDetail: detail, Purposes: purposes})
	}
	return out
}

// ParseP11Kit parses p11-kit trust files. Each [p11-kit-object-v1] section
// with class "certificate" (or no class at all, as in the bundles p11-kit's
// own tools write, where the PEM block implies the class) and a PEM
// CERTIFICATE payload becomes a Found with Kind KindP11Kit, Label from
// "label", and Trust and Purposes from the "trusted" and "x-distrusted"
// attributes together with the extended-key-usage extension object (class
// x-certificate-extension, object-id 2.5.29.37) attached to the same public
// key, which limits an anchor to the purposes it lists. Sections carrying
// only a PUBLIC KEY are matched against patterns by Scan, not here.
func ParseP11Kit(data []byte) []Found {
	return p11Found(parseP11Kit(data))
}
