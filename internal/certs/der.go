package certs

import (
	"bytes"
	"crypto/x509"
)

// seqLong is the start of a DER SEQUENCE with a two-byte length: the shape of
// every real-world certificate (256 to 65535 bytes).
var seqLong = []byte{0x30, 0x82}

// certCandidate reports whether b starts with the byte shape of a DER X.509
// certificate (outer SEQUENCE with a two-byte length, TBSCertificate SEQUENCE
// in any length form, then either the explicit [0] version or a v1 serial
// number) and returns its total length. complete is false when the shape
// matches but b ends before the certificate does.
func certCandidate(b []byte) (total int, complete, ok bool) {
	if len(b) < 16 || b[0] != 0x30 || b[1] != 0x82 || b[4] != 0x30 {
		return 0, false, false
	}
	n := int(b[2])<<8 | int(b[3])
	if n < 256 { // DER uses the two-byte form only for lengths >= 256
		return 0, false, false
	}
	total = 4 + n
	h, m, good := derLength(b[5:])     // the TBSCertificate length
	if !good || m < 64 || 1+h+m >= n { // a signature must follow the TBSCertificate
		return 0, false, false
	}
	switch v := b[5+h:]; {
	case len(v) >= 5 && v[0] == 0xa0 && v[1] == 0x03 && v[2] == 0x02 && v[3] == 0x01 && v[4] <= 2:
		// explicit version (v2 or v3)
	case len(v) >= 2 && v[0] == 0x02 && v[1] != 0 && v[1] < 0x80:
		// v1: the serial number INTEGER comes first
	default:
		return 0, false, false
	}
	return total, total <= len(b), true
}

// derLength decodes the definite length at the start of b and returns the
// number of bytes it occupies and the value length it encodes.
func derLength(b []byte) (hdr, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	if b[0] < 0x80 {
		return 1, int(b[0]), true
	}
	k := int(b[0] & 0x7f)
	if k == 0 || k > 4 || len(b) < 1+k {
		return 0, 0, false
	}
	for _, c := range b[1 : 1+k] {
		n = n<<8 | int(c)
	}
	return 1 + k, n, true
}

// parseCertificate validates a candidate by parsing a private copy of it, so
// that the returned certificate never aliases the scan window.
func parseCertificate(b []byte) (*x509.Certificate, []byte, bool) {
	raw := bytes.Clone(b)
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, false
	}
	return cert, raw, true
}

// firstDER trims b to its first DER element when b starts with a complete
// one; producers such as certdata.txt and renamed TRUSTED CERTIFICATE blocks
// may follow a certificate with other data that the strict parser rejects.
func firstDER(b []byte) []byte {
	if n, ok := derTotalLength(b); ok && n < len(b) {
		return b[:n]
	}
	return b
}

// carveDER finds DER certificates in data whose first byte lies in
// [from, limit). Offsets are relative to base. After a certificate has been
// found the search resumes behind it, so nothing is reported from inside it.
// unfinished is the offset (relative to data) of the first candidate that
// has the shape of a certificate but runs past the end of data, or -1.
func carveDER(data []byte, from, limit int, base int64, kind Kind) (out []Found, unfinished int) {
	unfinished = -1
	if from < 0 {
		from = 0
	}
	if limit > len(data) {
		limit = len(data)
	}
	for i := from; i < limit; {
		j := bytes.Index(data[i:], seqLong)
		if j < 0 {
			break
		}
		i += j
		if i >= limit {
			break
		}
		if n, complete, ok := certCandidate(data[i:]); ok {
			if !complete {
				if unfinished < 0 {
					unfinished = i
				}
			} else if cert, raw, ok := parseCertificate(data[i : i+n]); ok {
				out = append(out, Found{Certificate: cert, Raw: raw, Kind: kind, Offset: base + int64(i)})
				i += n
				continue
			}
		}
		i++
	}
	return out, unfinished
}

// CarveDER finds DER-encoded X.509 certificates anywhere inside data and
// returns them with offsets relative to base. Every candidate is validated by
// parsing it; a certificate is returned at most once per offset.
func CarveDER(data []byte, base int64) []Found {
	found, _ := carveDER(data, 0, len(data), base, KindDER)
	return found
}
