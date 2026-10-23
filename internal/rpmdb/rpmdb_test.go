package rpmdb

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageEVR(t *testing.T) {
	tests := []struct {
		name string
		pkg  Package
		evr  string
		str  string
	}{
		{"plain", Package{Name: "zlib", Version: "1.2.13", Release: "4.el9", Arch: "x86_64"}, "1.2.13-4.el9", "zlib-1.2.13-4.el9.x86_64"},
		{"epoch", Package{Name: "openssl-libs", Version: "3.5.8", Release: "2.el9_8", Epoch: "1", Arch: "x86_64"}, "1:3.5.8-2.el9_8", "openssl-libs-1:3.5.8-2.el9_8.x86_64"},
		{"epoch zero", Package{Name: "p11-kit", Version: "0.26.4", Release: "1.el9_8", Epoch: "0", Arch: "x86_64"}, "0.26.4-1.el9_8", "p11-kit-0.26.4-1.el9_8.x86_64"},
		{"no release", Package{Name: "x", Version: "1"}, "1", "x-1"},
		{"no arch", Package{Name: "gpg-pubkey", Version: "fd431d51", Release: "4ae0493b"}, "fd431d51-4ae0493b", "gpg-pubkey-fd431d51-4ae0493b"},
		{"empty", Package{}, "", "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pkg.EVR(); got != tt.evr {
				t.Errorf("EVR() = %q, want %q", got, tt.evr)
			}
			if got := tt.pkg.String(); got != tt.str {
				t.Errorf("String() = %q, want %q", got, tt.str)
			}
		})
	}
}

func TestIsDatabasePath(t *testing.T) {
	tests := []struct {
		path   string
		format string
		ok     bool
	}{
		{"/var/lib/rpm/rpmdb.sqlite", FormatSQLite, true},
		{"/usr/lib/sysimage/rpm/rpmdb.sqlite", FormatSQLite, true},
		{"/usr/share/rpm/rpmdb.sqlite", FormatSQLite, true},
		{"/var/lib/rpm/Packages", FormatBDB, true},
		{"/usr/lib/sysimage/rpm/Packages", FormatBDB, true},
		{"/var/lib/rpm/Packages.db", FormatNDB, true},
		{"/usr/lib/sysimage/rpm/Packages.db", FormatNDB, true},
		{"var/lib/rpm/Packages.db", FormatNDB, true},
		{"usr/share/rpm/Packages", FormatBDB, true},
		{"/var/lib/rpm/Name", "", false},
		{"/var/lib/rpm/Index.db", "", false},
		{"/var/lib/rpm/Packages.db.bak", "", false},
		{"/var/lib/rpm/packages", "", false},
		{"/var/lib/rpm/sub/Packages", "", false},
		{"/var/lib/rpmdb.sqlite", "", false},
		{"/etc/Packages", "", false},
		{"/var/lib/dpkg/status", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			format, ok := IsDatabasePath(tt.path)
			if format != tt.format || ok != tt.ok {
				t.Errorf("IsDatabasePath(%q) = %q, %v; want %q, %v", tt.path, format, ok, tt.format, tt.ok)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	sqlite, err := os.ReadFile(filepath.Join("testdata", "packages-small.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	bdbBE := make([]byte, 512)
	binary.BigEndian.PutUint32(bdbBE[12:], bdbBtreeMagic)
	tests := []struct {
		name   string
		data   []byte
		format string
		ok     bool
	}{
		{"sqlite", sqlite, FormatSQLite, true},
		{"ndb", buildNDB(1, nil), FormatNDB, true},
		{"bdb hash little endian", buildBDB(binary.LittleEndian, 512, bdbHashMagic, bdbPageHashMeta), FormatBDB, true},
		{"bdb btree big endian", bdbBE, FormatBDB, true},
		{"garbage", []byte("certainly not a database of any kind"), "", false},
		{"short", []byte("SQLite"), "", false},
		{"empty", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, ok := DetectFormat(tt.data)
			if format != tt.format || ok != tt.ok {
				t.Errorf("DetectFormat = %q, %v; want %q, %v", format, ok, tt.format, tt.ok)
			}
		})
	}
}

func TestParseUnknownFormat(t *testing.T) {
	for _, format := range []string{"", "rpm", "SQLite", "berkeley"} {
		pkgs, err := Parse(format, []byte("x"))
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Parse(%q): err = %v, want ErrUnsupported", format, err)
		}
		if pkgs != nil {
			t.Errorf("Parse(%q): packages = %v, want nil", format, pkgs)
		}
	}
}

// TestParseMismatchedFormat checks that data of one format handed to
// another backend is rejected with a plain error, not misread.
func TestParseMismatchedFormat(t *testing.T) {
	sqlite, err := os.ReadFile(filepath.Join("testdata", "packages-small.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	ndb := buildNDB(1, []ndbBlob{{1, buildHeader(false, strEntry(tagName, "a"), strEntry(tagVersion, "1"))}})
	bdb := buildBDB(binary.LittleEndian, 512, bdbHashMagic, bdbPageHashMeta)
	tests := []struct {
		format string
		data   []byte
		want   string
	}{
		{FormatSQLite, ndb, "not a SQLite 3 database"},
		{FormatSQLite, bdb, "not a SQLite 3 database"},
		{FormatNDB, sqlite, "not an rpm ndb database"},
		{FormatNDB, bdb, "not an rpm ndb database"},
		{FormatBDB, sqlite, "not a Berkeley DB file"},
		{FormatBDB, ndb, "not a Berkeley DB file"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			_, err := Parse(tt.format, tt.data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse(%s) error = %v, want one containing %q", tt.format, err, tt.want)
			}
			if errors.Is(err, ErrUnsupported) {
				t.Errorf("Parse(%s) wrongly reports ErrUnsupported: %v", tt.format, err)
			}
			if !strings.HasPrefix(err.Error(), "rpmdb: "+tt.format+": ") {
				t.Errorf("Parse(%s) error %q lacks the format prefix", tt.format, err)
			}
		})
	}
}
