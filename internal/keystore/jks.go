package keystore

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JKS/JCEKS file layout (all integers big-endian):
//
//	uint32 magic (0xFEEDFEED JKS, 0xCECECECE JCEKS)
//	uint32 version (1 or 2)
//	uint32 entry count
//	entries:
//	  uint32 tag; alias (Java modified UTF-8: uint16 length + bytes); int64 creation time (ms)
//	  tag 1, private key: uint32 keyLen, key bytes (encrypted PKCS#8, ignored);
//	                      uint32 chainLen; chainLen certificate records
//	  tag 2, trusted certificate: one certificate record
//	  tag 3, JCEKS secret key: a Java-serialized SealedObject without a length prefix
//	  certificate record: (version 2 only: type as modified UTF-8, e.g. "X.509") uint32 length, DER bytes
//	20-byte SHA-1 integrity digest (not verified here)
const (
	magicJKS   = 0xFEEDFEED
	magicJCEKS = 0xCECECECE

	jksTagPrivateKey  = 1
	jksTagTrustedCert = 2
	jksTagSecretKey   = 3

	jksDigestLen = 20 // SHA-1
)

func parseJKS(data []byte) ([]Entry, error) {
	if !IsJKS(data) {
		return nil, fmt.Errorf("keystore: jks: missing JKS/JCEKS magic number: %w", ErrFormat)
	}
	r := &byteReader{data: data, pos: 4}
	version, err := r.uint32("version")
	if err != nil {
		return nil, fmt.Errorf("keystore: jks: %w", err)
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("keystore: jks: unsupported keystore version %d: %w", version, ErrFormat)
	}
	count, err := r.uint32("entry count")
	if err != nil {
		return nil, fmt.Errorf("keystore: jks: %w", err)
	}

	var (
		entries  []Entry
		problems []error // non-fatal: unparsable certificates
	)
	fail := func(err error) ([]Entry, error) {
		return entries, errors.Join(append(problems, err)...)
	}
	for i := uint32(0); i < count; i++ {
		tag, err := r.uint32(fmt.Sprintf("entry %d tag", i))
		if err != nil {
			return fail(fmt.Errorf("keystore: jks: %w", err))
		}
		alias, err := r.javaUTF(fmt.Sprintf("entry %d alias", i))
		if err != nil {
			return fail(fmt.Errorf("keystore: jks: %w", err))
		}
		where := fmt.Sprintf("entry %d (%q)", i, alias)
		created, err := r.int64(where + " creation time")
		if err != nil {
			return fail(fmt.Errorf("keystore: jks: %w", err))
		}
		switch tag {
		case jksTagPrivateKey:
			keyLen, err := r.uint32(where + " private key length")
			if err != nil {
				return fail(fmt.Errorf("keystore: jks: %w", err))
			}
			if _, err := r.bytes(uint64(keyLen), where+" private key"); err != nil {
				return fail(fmt.Errorf("keystore: jks: %w", err))
			}
			chainLen, err := r.uint32(where + " chain length")
			if err != nil {
				return fail(fmt.Errorf("keystore: jks: %w", err))
			}
			for j := uint32(0); j < chainLen; j++ {
				what := fmt.Sprintf("%s chain certificate %d", where, j)
				raw, err := r.certificate(version, what)
				if err != nil {
					return fail(fmt.Errorf("keystore: jks: %w", err))
				}
				if raw == nil {
					continue // not an X.509 certificate
				}
				if _, err := x509.ParseCertificate(raw); err != nil {
					problems = append(problems, fmt.Errorf("keystore: jks: %s: %w", what, err))
					continue
				}
				entries = append(entries, Entry{Alias: alias, Raw: bytes.Clone(raw), FromKeyEntry: true, Created: created})
			}
		case jksTagTrustedCert:
			what := where + " certificate"
			raw, err := r.certificate(version, what)
			if err != nil {
				return fail(fmt.Errorf("keystore: jks: %w", err))
			}
			if raw == nil {
				continue
			}
			if _, err := x509.ParseCertificate(raw); err != nil {
				problems = append(problems, fmt.Errorf("keystore: jks: %s: %w", what, err))
				continue
			}
			entries = append(entries, Entry{Alias: alias, Raw: bytes.Clone(raw), Created: created})
		case jksTagSecretKey:
			return fail(fmt.Errorf("keystore: jks: %s is a secret-key entry (Java-serialized SealedObject without a length prefix); the %d entries after it cannot be read: %w",
				where, count-i-1, ErrSecretKeyEntry))
		default:
			return fail(fmt.Errorf("keystore: jks: %s has unknown entry tag %d", where, tag))
		}
	}
	if _, err := r.bytes(jksDigestLen, "integrity digest"); err != nil {
		return fail(fmt.Errorf("keystore: jks: %w", err))
	}
	return entries, errors.Join(problems...)
}

// byteReader reads big-endian fields from an in-memory buffer and returns an
// error wrapping io.ErrUnexpectedEOF, instead of panicking, when the data runs
// out.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) remaining() int { return len(r.data) - r.pos }

// bytes returns the next n bytes of the buffer (not a copy).
func (r *byteReader) bytes(n uint64, what string) ([]byte, error) {
	if n > uint64(r.remaining()) {
		return nil, fmt.Errorf("%s: need %d bytes at offset %d but only %d remain: %w", what, n, r.pos, r.remaining(), io.ErrUnexpectedEOF)
	}
	b := r.data[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b, nil
}

func (r *byteReader) uint16(what string) (uint16, error) {
	b, err := r.bytes(2, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *byteReader) uint32(what string) (uint32, error) {
	b, err := r.bytes(4, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *byteReader) int64(what string) (int64, error) {
	b, err := r.bytes(8, what)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

// javaUTF reads a string as written by java.io.DataOutput.writeUTF.
func (r *byteReader) javaUTF(what string) (string, error) {
	n, err := r.uint16(what + " length")
	if err != nil {
		return "", err
	}
	b, err := r.bytes(uint64(n), what)
	if err != nil {
		return "", err
	}
	return decodeModifiedUTF8(b), nil
}

// certificate reads one certificate record. It returns nil bytes (and no
// error) when the record is of a type other than X.509, after advancing past
// it.
func (r *byteReader) certificate(version uint32, what string) ([]byte, error) {
	isX509 := true
	if version == 2 {
		typ, err := r.javaUTF(what + " type")
		if err != nil {
			return nil, err
		}
		isX509 = strings.EqualFold(typ, "X.509") || strings.EqualFold(typ, "X509")
	}
	n, err := r.uint32(what + " length")
	if err != nil {
		return nil, err
	}
	raw, err := r.bytes(uint64(n), what)
	if err != nil {
		return nil, err
	}
	if !isX509 {
		return nil, nil
	}
	return raw, nil
}

// decodeModifiedUTF8 decodes Java's "modified UTF-8" (the encoding used by
// DataOutput.writeUTF): U+0000 is written as C0 80 and characters outside the
// BMP as two 3-byte encoded UTF-16 surrogates. Malformed sequences decode to
// U+FFFD rather than failing, since aliases are informational.
func decodeModifiedUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b) // standard UTF-8 is the common case (and has no C0 80 or surrogates)
	}
	var sb strings.Builder
	sb.Grow(len(b))
	three := func(i int) (rune, bool) {
		if i+2 < len(b) && b[i]&0xF0 == 0xE0 && b[i+1]&0xC0 == 0x80 && b[i+2]&0xC0 == 0x80 {
			return rune(b[i]&0x0F)<<12 | rune(b[i+1]&0x3F)<<6 | rune(b[i+2]&0x3F), true
		}
		return 0, false
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c < 0x80:
			sb.WriteByte(c)
			i++
		case c&0xE0 == 0xC0:
			if i+1 < len(b) && b[i+1]&0xC0 == 0x80 {
				sb.WriteRune(rune(c&0x1F)<<6 | rune(b[i+1]&0x3F))
				i += 2
			} else {
				sb.WriteRune(utf8.RuneError)
				i++
			}
		case c&0xF0 == 0xE0:
			r, ok := three(i)
			if !ok {
				sb.WriteRune(utf8.RuneError)
				i++
				continue
			}
			i += 3
			if !utf16.IsSurrogate(r) {
				sb.WriteRune(r)
				continue
			}
			if r2, ok := three(i); ok && r < 0xDC00 && r2 >= 0xDC00 && r2 <= 0xDFFF {
				sb.WriteRune(utf16.DecodeRune(r, r2))
				i += 3
				continue
			}
			sb.WriteRune(utf8.RuneError) // lone surrogate
		default:
			sb.WriteRune(utf8.RuneError)
			i++
		}
	}
	return sb.String()
}
