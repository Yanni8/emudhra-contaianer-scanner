package rpmdb

import (
	"os"
	"path/filepath"
	"testing"
)

// Real-world databases are not committed. The tests below look for them
// under testdata/real (ignored by git) or at the path in the environment
// variable named per test, and skip when neither exists. To obtain the
// Amazon Linux file without a Docker daemon:
//
//	crane export --platform linux/amd64 amazonlinux:2023 - | tar -x var/lib/rpm/rpmdb.sqlite
//	mv var/lib/rpm/rpmdb.sqlite internal/rpmdb/testdata/real/amazonlinux-2023-rpmdb.sqlite

// realDatabase returns the content of a real database or skips the test.
func realDatabase(t *testing.T, envVar, defaultName string) []byte {
	t.Helper()
	path := os.Getenv(envVar)
	if path == "" {
		path = filepath.Join("testdata", "real", defaultName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("real database not available (%s=%q): %v", envVar, path, err)
	}
	return data
}

// TestRealAmazonLinux2023 checks the reader against the rpmdb.sqlite of the
// amazonlinux:2023 image (digest sha256:2fd517a7... as verified end to end
// on 2026-10-23): 106 packages, ca-certificates at the version the
// independent verification found.
func TestRealAmazonLinux2023(t *testing.T) {
	data := realDatabase(t, "ECS_RPMDB_AMAZONLINUX2023", "amazonlinux-2023-rpmdb.sqlite")
	if format, ok := DetectFormat(data); !ok || format != FormatSQLite {
		t.Fatalf("DetectFormat = %q, %v; want sqlite", format, ok)
	}
	pkgs, err := Parse(FormatSQLite, data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 106 {
		t.Errorf("got %d packages, want 106", len(pkgs))
	}
	want := map[string]Package{
		"ca-certificates": {Name: "ca-certificates", Version: "2025.2.76", Release: "1.0.amzn2023.0.3", Arch: "noarch"},
		"openssl-libs":    {Name: "openssl-libs", Version: "3.5.8", Release: "1.amzn2023.0.1", Epoch: "1", Arch: "x86_64"},
		"p11-kit":         {Name: "p11-kit", Version: "0.24.1", Release: "2.amzn2023.0.3", Arch: "x86_64"},
	}
	found := map[string]Package{}
	for _, p := range pkgs {
		if _, ok := want[p.Name]; ok {
			found[p.Name] = p
		}
	}
	for name, w := range want {
		if got, ok := found[name]; !ok {
			t.Errorf("%s not listed", name)
		} else if got != w {
			t.Errorf("%s: got %+v, want %+v", name, got, w)
		}
	}
	if evr := found["ca-certificates"].EVR(); evr != "2025.2.76-1.0.amzn2023.0.3" {
		t.Errorf("ca-certificates EVR = %q", evr)
	}
}
