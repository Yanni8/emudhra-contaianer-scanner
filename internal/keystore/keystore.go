// Package keystore extracts X.509 certificates from Java keystores (JKS and
// JCEKS) and PKCS#12 files.
//
// Trusted-certificate entries in JKS/JCEKS are stored in the clear (the store
// password only protects an integrity digest), so they can always be read.
// PKCS#12 files are tried with each supplied password (JDK 18+ ships a
// password-less cacerts, keytool defaults to "changeit"); when every password
// fails, certificates stored in unencrypted SafeContents are still extracted.
//
// A hostile PKCS#12 file can ask for an enormous amount of key-derivation
// work (iteration counts in the millions, hundreds of encrypted parts). The
// package bounds that work per derivation and per file and reports a file
// that asks for more as too expensive instead of grinding on it.
package keystore

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Entry is one certificate extracted from a keystore.
type Entry struct {
	// Alias is the keystore alias or PKCS#12 friendlyName; empty when absent.
	Alias string
	// Raw is the DER-encoded certificate.
	Raw []byte
	// FromKeyEntry is true when the certificate came from the certificate chain
	// of a private-key entry rather than from a trusted-certificate entry.
	FromKeyEntry bool
	// Encrypted is true when the certificate could only be read after
	// decrypting the container with one of the supplied passwords.
	Encrypted bool
	// Created is the entry timestamp for JKS entries (Unix milliseconds), 0 otherwise.
	Created int64
}

// ErrFormat is returned when the data is not in the expected format.
var ErrFormat = errors.New("keystore: unrecognised format")

// ErrSecretKeyEntry is returned (wrapped) by ParseJKS when a JCEKS secret-key
// entry is encountered. Such entries are Java-serialized SealedObjects without
// a length prefix, so the entries that follow them cannot be located; the
// entries read before it are still returned.
var ErrSecretKeyEntry = errors.New("keystore: JCEKS secret-key entry cannot be skipped")

// ErrTooExpensive is returned (wrapped) by ParsePKCS12 and OpenPKCS12 when
// reading the encrypted parts of a file would take more key-derivation work
// than the package allows: an iteration count above the per-derivation
// maximum, more encrypted SafeContents than the maximum, or a total above the
// per-file budget. The message states the work the file asked for, and the
// certificates that could be read without that work are still returned.
var ErrTooExpensive = errors.New("keystore: pkcs12: too expensive to decrypt")

// IsJKS reports whether data starts with the JKS (0xFEEDFEED) or JCEKS
// (0xCECECECE) magic number.
func IsJKS(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(data) {
	case magicJKS, magicJCEKS:
		return true
	}
	return false
}

// ParseJKS parses a JKS or JCEKS keystore and returns every certificate it
// contains: trusted-certificate entries and the chains of private-key entries.
// No password is needed. The integrity digest at the end of the file is not
// verified. Returns ErrFormat (wrapped) when data is not a JKS/JCEKS file;
// truncated or corrupt stores return the entries read so far together with an
// error.
func ParseJKS(data []byte) ([]Entry, error) {
	return parseJKS(data)
}

// LooksLikePKCS12 reports whether data plausibly is a DER-encoded PKCS#12 PFX:
// an outer SEQUENCE whose first element is INTEGER 3 followed by a ContentInfo
// SEQUENCE. It is a cheap sniff, not a full parse.
func LooksLikePKCS12(data []byte) bool {
	const (
		tagSequence = 0x30
		tagInteger  = 0x02
	)
	body, definite, length, ok := berHeader(data, tagSequence)
	if !ok {
		return false
	}
	// INTEGER 3 (3 bytes) followed by at least the header of the ContentInfo
	// SEQUENCE: anything shorter cannot be a PFX.
	if definite && length < 5 {
		return false
	}
	if len(body) < 4 {
		return false
	}
	return body[0] == tagInteger && body[1] == 1 && body[2] == 3 && body[3] == tagSequence
}

// berHeader checks that b starts with the given tag and a well-formed BER
// length (short form, long form of up to four bytes, or the indefinite form)
// and returns the bytes that follow the header. For a definite length it also
// returns that length.
func berHeader(b []byte, tag byte) (body []byte, definite bool, length int, ok bool) {
	if len(b) < 2 || b[0] != tag {
		return nil, false, 0, false
	}
	first := b[1]
	switch {
	case first < 0x80:
		return b[2:], true, int(first), true
	case first == 0x80:
		return b[2:], false, 0, true // indefinite length (BER)
	}
	n := int(first & 0x7f)
	if n > 4 || len(b) < 2+n {
		return nil, false, 0, false
	}
	for _, c := range b[2 : 2+n] {
		length = length<<8 | int(c)
	}
	return b[2+n:], true, length, true
}

// ParsePKCS12 extracts certificates from a PKCS#12 file. Each password in
// passwords is tried in order (an empty string covers password-less files);
// the first one that opens the file wins. If none works, certificates held in
// unencrypted SafeContents are still returned (with Encrypted=false) and the
// returned error describes the failure for the encrypted parts. Returns
// ErrFormat (wrapped) when data is not PKCS#12 at all, and ErrTooExpensive
// (wrapped) when the file asks for more key-derivation work than the package
// is willing to spend.
//
// The package's own parser reads the structure, the unencrypted SafeContents
// and the encrypted ones it can decrypt (PBES2 with AES or 3DES,
// PBE-SHA1-3DES and PBE-SHA1-RC2) with the supplied passwords. Only once that
// has succeeded, and only when the remaining work fits the budget, is the
// file also decoded with go-pkcs12 (DecodeTrustStore, then DecodeChain),
// which verifies the MAC and settles the entry layout; a file that library
// cannot handle, such as a keystore holding several private keys or
// certificates without Java's trust attribute, keeps the parser's result.
func ParsePKCS12(data []byte, passwords []string) ([]Entry, error) {
	entries, _, err := OpenPKCS12(data, passwords)
	return entries, err
}

// OpenPKCS12 is ParsePKCS12 that also reports which password opened the file:
// the index into passwords of the one that decrypted its encrypted
// SafeContents (or, for a file without encrypted parts, verified its MAC), or
// -1 when no password was needed or none of them worked.
func OpenPKCS12(data []byte, passwords []string) (entries []Entry, password int, err error) {
	if !LooksLikePKCS12(data) {
		return nil, -1, fmt.Errorf("keystore: pkcs12: data is not a DER-encoded PFX: %w", ErrFormat)
	}
	unique, position := uniquePasswords(passwords)
	// go-pkcs12 accepts the same DER structures as parsePFX, so a file the
	// parser rejects is not handed to the library: that would verify the MAC
	// (with whatever iteration count the file names) before failing.
	pfx, err := parsePFX(data)
	if err != nil {
		return nil, -1, fmt.Errorf("keystore: pkcs12: %w", err)
	}
	budget, refused := pfx.budget()
	results, opened := pfx.extract(unique, budget)
	for _, i := range pfx.libraryPasswords(results, opened, unique) {
		certs, fromKey, ok := pfx.decodeWithLibrary(data, unique[i], results, budget)
		if ok {
			password = -1
			if opened >= 0 || pfx.hasMAC {
				password = position[i]
			}
			return libraryEntries(certs, fromKey, results), password, nil
		}
	}
	entries, err = pfx.entries(results, len(unique), refused)
	password = -1
	if opened >= 0 {
		password = position[opened]
	}
	return entries, password, err
}

// libraryPasswords lists the passwords go-pkcs12 is tried with, as indices
// into passwords. The library needs one password for the whole file, so it
// is only worth calling with the password that opened every encrypted
// SafeContents; a file without encrypted parts is tried with every password
// when it has a MAC to verify, and with the empty password alone when it has
// none (the library insists on it).
func (p *pfxFile) libraryPasswords(results []safeContentsResult, opened int, passwords []string) []int {
	encrypted := false
	for i := range results {
		encrypted = encrypted || results[i].encrypted
	}
	switch {
	case encrypted && opened >= 0:
		return []int{opened}
	case encrypted:
		return nil
	case p.hasMAC:
		all := make([]int, len(passwords))
		for i := range all {
			all[i] = i
		}
		return all
	}
	for i, pw := range passwords {
		if pw == "" {
			return []int{i}
		}
	}
	return nil
}

// libraryEntries converts certificates decoded by go-pkcs12 into entries.
// The library reports neither aliases nor which SafeContents a certificate
// came from, so both are recovered from the structural walk when possible; a
// certificate the walk could not place counts as encrypted.
func libraryEntries(certs []*x509.Certificate, fromKey bool, results []safeContentsResult) []Entry {
	known := catalogue(results)
	entries := make([]Entry, 0, len(certs))
	for _, c := range certs {
		e := Entry{Raw: bytes.Clone(c.Raw), FromKeyEntry: fromKey, Encrypted: true}
		if info, ok := known[string(c.Raw)]; ok {
			e.Alias = info.alias
			e.Encrypted = info.encrypted
		}
		entries = append(entries, e)
	}
	return entries
}

// decodeWithLibrary opens the file with go-pkcs12, first as a Java trust
// store and then as a key/certificate-chain file. Each attempt is charged to
// the budget beforehand with the work the library will do (MAC verification,
// every encrypted SafeContents and, for the chain, every shrouded key), and
// skipped when that does not fit. fromKey reports whether the certificates
// belong to a private-key entry.
func (p *pfxFile) decodeWithLibrary(data []byte, password string, results []safeContentsResult, budget *kdfBudget) (certs []*x509.Certificate, fromKey bool, ok bool) {
	base, shrouded, bounded := p.libraryCost(results)
	if !bounded || budget.charge(base) != nil {
		return nil, false, false
	}
	if certs, err := pkcs12.DecodeTrustStore(data, password); err == nil {
		return certs, false, true
	}
	if budget.charge(base+shrouded) != nil {
		return nil, false, false
	}
	_, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, false, false
	}
	certs = make([]*x509.Certificate, 0, 1+len(cas))
	certs = append(certs, leaf)
	certs = append(certs, cas...)
	return certs, true, true
}

// uniquePasswords returns passwords without duplicates, keeping the first
// occurrence, together with each kept password's index in the original list.
func uniquePasswords(passwords []string) (unique []string, position []int) {
	seen := make(map[string]struct{}, len(passwords))
	for i, v := range passwords {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		unique = append(unique, v)
		position = append(position, i)
	}
	return unique, position
}
