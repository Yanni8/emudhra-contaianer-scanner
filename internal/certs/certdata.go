package certs

import (
	"bytes"
	"strings"
)

// certdataObject is one object of a certdata.txt file: its attributes with
// their raw (decoded for MULTILINE_OCTAL) values.
type certdataObject struct {
	offset int64
	attrs  map[string]string
}

// parseCertdata splits certdata.txt into objects. An object starts at a
// CKA_CLASS line and ends before the next one.
func parseCertdata(data []byte) []certdataObject {
	var objs []certdataObject
	var cur *certdataObject
	pos := 0
	for pos < len(data) {
		nl := bytes.IndexByte(data[pos:], '\n')
		var line []byte
		next := len(data)
		if nl >= 0 {
			line = data[pos : pos+nl]
			next = pos + nl + 1
		} else {
			line = data[pos:]
		}
		lineStart := pos
		pos = next
		text := strings.TrimSpace(string(line))
		if text == "" || strings.HasPrefix(text, "#") || !strings.HasPrefix(text, "CKA_") {
			continue
		}
		fields := attributeFields(text)
		if len(fields) < 2 {
			continue
		}
		name, typ := fields[0], fields[1]
		value := ""
		if len(fields) == 3 {
			value = fields[2]
		}
		if name == "CKA_CLASS" {
			objs = append(objs, certdataObject{offset: int64(lineStart), attrs: map[string]string{}})
			cur = &objs[len(objs)-1]
		}
		if cur == nil {
			continue
		}
		switch typ {
		case "MULTILINE_OCTAL":
			var body []byte
			for pos < len(data) {
				nl := bytes.IndexByte(data[pos:], '\n')
				var l []byte
				if nl >= 0 {
					l = data[pos : pos+nl]
					pos += nl + 1
				} else {
					l = data[pos:]
					pos = len(data)
				}
				if strings.TrimSpace(string(l)) == "END" {
					break
				}
				body = append(body, l...)
			}
			cur.attrs[name] = string(decodeOctal(body))
		case "UTF8":
			cur.attrs[name] = strings.Trim(value, `"`)
		default:
			cur.attrs[name] = value
		}
	}
	return objs
}

// attributeFields splits an attribute line into name, type and value: the
// first two are separated from the rest by spaces or tabs, the value keeps
// its internal spacing.
func attributeFields(text string) []string {
	var fields []string
	for len(fields) < 2 {
		i := strings.IndexAny(text, " \t")
		if i < 0 {
			return append(fields, text)
		}
		fields = append(fields, text[:i])
		text = strings.TrimLeft(text[i:], " \t")
	}
	if text != "" {
		fields = append(fields, text)
	}
	return fields
}

// decodeOctal turns "\060\202..." escapes into bytes; other characters are
// ignored, as certdata.txt only uses escapes.
func decodeOctal(b []byte) []byte {
	out := make([]byte, 0, len(b)/4)
	for i := 0; i+3 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		v, ok := 0, true
		for j := 1; j <= 3; j++ {
			c := b[i+j]
			if c < '0' || c > '7' {
				ok = false
				break
			}
			v = v*8 + int(c-'0')
		}
		if !ok {
			continue
		}
		out = append(out, byte(v))
		i += 3
	}
	return out
}

// trustKey identifies the certificate a CKO_NSS_TRUST object refers to.
func trustKey(attrs map[string]string) string {
	return attrs["CKA_ISSUER"] + "\x00" + attrs["CKA_SERIAL_NUMBER"]
}

// certdataTrustAttrs are the CKA_TRUST_* attributes and the purposes they
// decide, in the order they are printed.
var certdataTrustAttrs = []struct {
	attr    string
	purpose Purpose
}{
	{"CKA_TRUST_SERVER_AUTH", PurposeServerAuth},
	{"CKA_TRUST_EMAIL_PROTECTION", PurposeEmailProtection},
	{"CKA_TRUST_CODE_SIGNING", PurposeCodeSigning},
}

// certdataTrust derives trust from a CKO_NSS_TRUST object:
// CKT_NSS_TRUSTED_DELEGATOR makes the purpose an anchor, CKT_NSS_NOT_TRUSTED
// distrusts it, anything else (CKT_NSS_MUST_VERIFY_TRUST,
// CKT_NSS_TRUST_UNKNOWN, absent) leaves it neutral. The certificate as a
// whole is an anchor when any purpose is, distrusted when every recorded
// purpose is, neutral otherwise.
func certdataTrust(attrs map[string]string) (TrustState, string, map[Purpose]TrustState) {
	var parts []string
	purposes := make(map[Purpose]TrustState, len(certdataTrustAttrs))
	recorded, rejected := 0, 0
	for _, a := range certdataTrustAttrs {
		v := attrs[a.attr]
		if v == "" {
			continue
		}
		recorded++
		parts = append(parts, a.attr+"="+v)
		switch v {
		case "CKT_NSS_TRUSTED_DELEGATOR":
			purposes[a.purpose] = TrustAnchor
		case "CKT_NSS_NOT_TRUSTED":
			purposes[a.purpose] = TrustDistrusted
			rejected++
		default:
			purposes[a.purpose] = TrustNeutral
		}
	}
	detail := strings.Join(parts, ", ")
	if detail == "" {
		detail = "no CKA_TRUST_* attributes"
	}
	return summariseTrust(purposes, recorded > 0 && rejected == recorded), detail, purposes
}

// ParseCertdata parses Mozilla's certdata.txt format. Each CKO_CERTIFICATE
// object becomes a Found with Kind KindCertdata, Label from CKA_LABEL, and
// Trust and Purposes derived from the matching CKO_NSS_TRUST object (matched
// by issuer and serial number): CKA_TRUST_SERVER_AUTH,
// CKA_TRUST_EMAIL_PROTECTION and CKA_TRUST_CODE_SIGNING decide serverAuth,
// emailProtection and codeSigning respectively, with CKT_NSS_TRUSTED_DELEGATOR
// as anchor, CKT_NSS_NOT_TRUSTED as distrusted and anything else as neutral.
// A certificate without a trust object is TrustNeutral with nil Purposes.
func ParseCertdata(data []byte) []Found {
	objs := parseCertdata(data)
	type trustInfo struct {
		state    TrustState
		detail   string
		purposes map[Purpose]TrustState
	}
	trusts := map[string]trustInfo{}
	for _, o := range objs {
		if o.attrs["CKA_CLASS"] == "CKO_NSS_TRUST" {
			state, detail, purposes := certdataTrust(o.attrs)
			trusts[trustKey(o.attrs)] = trustInfo{state, detail, purposes}
		}
	}
	var out []Found
	for _, o := range objs {
		if o.attrs["CKA_CLASS"] != "CKO_CERTIFICATE" {
			continue
		}
		value := o.attrs["CKA_VALUE"]
		if value == "" {
			continue
		}
		cert, raw, ok := parseCertificate(firstDER([]byte(value)))
		if !ok {
			continue
		}
		f := Found{Certificate: cert, Raw: raw, Kind: KindCertdata, Offset: o.offset, Label: o.attrs["CKA_LABEL"], Trust: TrustNeutral}
		if t, ok := trusts[trustKey(o.attrs)]; ok {
			f.Trust, f.TrustDetail, f.Purposes = t.state, t.detail, t.purposes
		} else {
			f.TrustDetail = "no CKO_NSS_TRUST object"
		}
		out = append(out, f)
	}
	return out
}
