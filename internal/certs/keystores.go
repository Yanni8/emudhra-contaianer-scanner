package certs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Yanni8/emudhra-container-scanner/internal/keystore"
)

// keystoreFound converts keystore entries into Founds. Offsets are located
// by searching for the DER bytes, which are stored in the clear in JKS files
// and in unencrypted PKCS#12 SafeContents.
func keystoreFound(data []byte, entries []keystore.Entry, kind Kind, note string, warn func(string)) []Found {
	out := make([]Found, 0, len(entries))
	for _, e := range entries {
		cert, raw, ok := parseCertificate(e.Raw)
		if !ok {
			warnf(warn, "%s entry %q holds an unparsable certificate", kind, e.Alias)
			continue
		}
		f := Found{Certificate: cert, Raw: raw, Kind: kind, Label: e.Alias, Note: note}
		if i := bytes.Index(data, e.Raw); i >= 0 {
			f.Offset = int64(i)
		}
		if e.FromKeyEntry {
			f.Note = joinNotes(note, "certificate chain of a private-key entry")
		}
		out = append(out, f)
	}
	return out
}

// scanJKS reads a JKS/JCEKS keystore. When the store is damaged, the entries
// read before the damage are kept and the rest of the file is carved for DER
// certificates.
func scanJKS(data []byte, warn func(string)) []Found {
	entries, err := keystore.ParseJKS(data)
	found := keystoreFound(data, entries, KindJKS, "", warn)
	if err == nil {
		return found
	}
	if errors.Is(err, keystore.ErrFormat) {
		return CarveDER(data, 0)
	}
	switch {
	case errors.Is(err, keystore.ErrSecretKeyEntry):
		warnf(warn, "jks: %v; the remaining entries were carved for certificates instead", err)
	case errors.Is(err, io.ErrUnexpectedEOF):
		warnf(warn, "jks: keystore is truncated (%v); %d entries read", err, len(entries))
	default:
		warnf(warn, "jks: %v", err)
	}
	return mergeCarved(found, data)
}

// mergeCarved adds DER certificates carved from data that keystore parsing
// did not already return.
func mergeCarved(found []Found, data []byte) []Found {
	seen := make(map[string]bool, len(found))
	for _, f := range found {
		seen[string(f.Raw)] = true
	}
	for _, f := range CarveDER(data, 0) {
		if seen[string(f.Raw)] {
			continue
		}
		seen[string(f.Raw)] = true
		f.Note = "carved from a region of the keystore that could not be parsed"
		found = append(found, f)
	}
	return found
}

// scanPKCS12 reads a PKCS#12 file with the whole password list in one go,
// so that the keystore package's key-derivation budget spans every password.
// What could not be read is reported in one warning line that never names a
// password; the parts that were read are returned, and a file that failed
// structurally is carved for DER certificates as well.
func scanPKCS12(data []byte, passwords []string, warn func(string)) []Found {
	if passwords == nil {
		passwords = DefaultPasswords
	}
	passwords = uniqueStrings(passwords)
	entries, opened, err := keystore.OpenPKCS12(data, passwords)
	if err == nil {
		return keystoreFound(data, entries, KindPKCS12, pkcs12Note(entries, passwords, opened), warn)
	}
	if errors.Is(err, keystore.ErrFormat) {
		return CarveDER(data, 0)
	}
	warnf(warn, "%s", strings.TrimPrefix(err.Error(), "keystore: "))
	note := "pkcs12: read from unencrypted SafeContents; other parts of the file could not be read"
	if opened >= 0 {
		note = joinNotes(pkcs12Note(entries, passwords, opened), "other parts of the file could not be read")
	}
	return mergeCarved(keystoreFound(data, entries, KindPKCS12, note, warn), data)
}

// pkcs12Note describes how a PKCS#12 file was opened. Files without
// encryption (JDK 18+ cacerts) open with any password, so the password is
// only mentioned when it was actually needed, and only by its text when it
// is one of DefaultPasswords: a user-supplied password is referred to by its
// position in the list.
func pkcs12Note(entries []keystore.Entry, passwords []string, opened int) string {
	encrypted := false
	for _, e := range entries {
		if e.Encrypted {
			encrypted = true
			break
		}
	}
	switch {
	case !encrypted:
		return "pkcs12 certificates stored unencrypted (no password needed)"
	case opened < 0 || opened >= len(passwords):
		return "pkcs12 opened with one of the supplied passwords"
	case passwords[opened] == "":
		return "pkcs12 opened with an empty password"
	case isDefaultPassword(passwords[opened]):
		return fmt.Sprintf("pkcs12 opened with password %q", passwords[opened])
	}
	return fmt.Sprintf("pkcs12 opened with supplied password #%d", opened+1)
}

func isDefaultPassword(pw string) bool {
	for _, d := range DefaultPasswords {
		if d == pw {
			return true
		}
	}
	return false
}

func uniqueStrings(s []string) []string {
	out := make([]string, 0, len(s))
	seen := make(map[string]bool, len(s))
	for _, v := range s {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

func warnf(warn func(string), format string, args ...any) {
	if warn != nil {
		warn(fmt.Sprintf(format, args...))
	}
}
