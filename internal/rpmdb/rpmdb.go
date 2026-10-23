// Package rpmdb reads installed package names and versions from rpm
// databases without the rpm, SQLite or Berkeley DB libraries, so that a
// container image scanner can report what an rpm-based image has installed
// from the database files alone.
//
// Three on-disk formats exist, and each one is parsed natively:
//
//   - rpmdb.sqlite (SQLite 3; RHEL 9 and later, UBI 9, Fedora, Amazon Linux
//     2023): the SQLite file format is read directly. Only the main
//     database file is consulted; a -wal file left behind by a writer that
//     did not checkpoint is not applied.
//   - Packages.db (rpm's own "ndb" backend; SUSE and openSUSE since 15.3,
//     Tumbleweed).
//   - Packages (Berkeley DB hash database; RHEL 8 and older, UBI 8, Amazon
//     Linux 2, CentOS 7). Btree leaf pages are read as well, although rpm
//     only ever created hash databases.
//
// Each database stores one rpm header blob per installed package, from
// which the NAME, EPOCH, VERSION, RELEASE and ARCH tags are extracted.
package rpmdb

import (
	"errors"
	"fmt"
	"strings"
)

// Database format names understood by Parse and returned by IsDatabasePath.
const (
	FormatSQLite = "sqlite"
	FormatBDB    = "bdb"
	FormatNDB    = "ndb"
)

// ErrUnsupported is returned (wrapped) by Parse when the database format or
// a variant of it (an unknown format name, an encrypted Berkeley DB file, a
// future ndb version) is not implemented by this package.
var ErrUnsupported = errors.New("unsupported rpm database format")

// Package is an installed rpm package as recorded in its header.
type Package struct {
	// Name is the package name (rpm tag NAME).
	Name string
	// Version is the upstream version (tag VERSION).
	Version string
	// Release is the package release (tag RELEASE).
	Release string
	// Epoch is the decimal epoch (tag EPOCH) or "" when the header has none.
	Epoch string
	// Arch is the architecture (tag ARCH); "" for gpg-pubkey pseudo packages.
	Arch string
}

// EVR returns "version-release", prefixed with "epoch:" when the epoch is
// set and not "0", which is the form rpm uses for version comparisons.
func (p Package) EVR() string {
	evr := p.Version
	if p.Release != "" {
		evr += "-" + p.Release
	}
	if p.Epoch != "" && p.Epoch != "0" {
		evr = p.Epoch + ":" + evr
	}
	return evr
}

// String returns the package as rpm -q prints it: name-[epoch:]version-release.arch.
func (p Package) String() string {
	s := p.Name + "-" + p.EVR()
	if p.Arch != "" {
		s += "." + p.Arch
	}
	return s
}

// databaseDirs are the directories (without leading slash) in which rpm
// keeps its database: the traditional location, the location used by
// Fedora and recent SUSE releases, and the one used by rpm-ostree systems.
var databaseDirs = []string{"var/lib/rpm/", "usr/lib/sysimage/rpm/", "usr/share/rpm/"}

// IsDatabasePath reports whether path (with or without a leading slash) is
// an rpm package database and which format it uses: rpmdb.sqlite is
// "sqlite", Packages is "bdb" (Berkeley DB) and Packages.db is "ndb".
func IsDatabasePath(path string) (format string, ok bool) {
	rel := strings.TrimPrefix(path, "/")
	for _, dir := range databaseDirs {
		name, found := strings.CutPrefix(rel, dir)
		if !found {
			continue
		}
		switch name {
		case "rpmdb.sqlite":
			return FormatSQLite, true
		case "Packages":
			return FormatBDB, true
		case "Packages.db":
			return FormatNDB, true
		}
		return "", false
	}
	return "", false
}

// DetectFormat sniffs the format of a database file from its leading bytes.
// It is a convenience for callers that want to double-check a file found at
// one of the IsDatabasePath locations before calling Parse.
func DetectFormat(data []byte) (format string, ok bool) {
	switch {
	case len(data) >= len(sqliteMagic) && string(data[:len(sqliteMagic)]) == sqliteMagic:
		return FormatSQLite, true
	case len(data) >= len(ndbMagic) && string(data[:len(ndbMagic)]) == ndbMagic:
		return FormatNDB, true
	case len(data) >= 16 && isBDBMagic(data[12:16]):
		return FormatBDB, true
	}
	return "", false
}

// Parse decodes a whole rpm database file held in memory and returns the
// installed packages in database order. format is one of the names
// returned by IsDatabasePath; any other name yields an error wrapping
// ErrUnsupported. Structural damage (truncation, bad magic, broken page
// chains, undecodable header blobs) is reported as an error rather than as
// a partial result, so that a caller never mistakes an incomplete list for
// the installed set.
func Parse(format string, data []byte) ([]Package, error) {
	var pkgs []Package
	var err error
	switch format {
	case FormatSQLite:
		pkgs, err = parseSQLite(data)
	case FormatBDB:
		pkgs, err = parseBDB(data)
	case FormatNDB:
		pkgs, err = parseNDB(data)
	default:
		return nil, fmt.Errorf("rpmdb: %w: %q", ErrUnsupported, format)
	}
	if err != nil {
		return nil, fmt.Errorf("rpmdb: %s: %w", format, err)
	}
	return pkgs, nil
}
