package main

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/scan"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
)

// fixture is the docker-archive built by TestMain: a linux/s390x image (a
// platform no test host has) holding a Debian CA bundle with an anchor root
// and a related root, a certifi bundle with the anchor, an executable with
// the anchor's bare public key, a dpkg database with an outdated
// ca-certificates and 21 malformed PEM files that each yield a warning.
var fixture string

// fixturePlatform is the platform recorded in the fixture's config.
const fixturePlatform = "linux/s390x"

// brokenPEMs is the number of malformed PEM files in the fixture; it is
// above the text report's warning cap of 20.
const brokenPEMs = 21

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ecs-main-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fixture = filepath.Join(dir, "img.tar")
	if err := writeFixture(fixture); err != nil {
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "building fixture:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type tarEntry struct {
	name    string
	content []byte
}

// tarOf builds an uncompressed tar with the given regular files; parent
// directories are implied.
func tarOf(entries []tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.content)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// writeFixture writes the docker-archive fixture to path.
func writeFixture(path string) error {
	bl := blocklist.Default()
	anchor, related := bl.ByID("emsign-ecc-root-ca-g3"), bl.ByID("emsign-root-ca-g1")
	if anchor == nil || anchor.Certificate == nil || related == nil || related.Certificate == nil {
		return fmt.Errorf("blocklist entries missing")
	}
	var pattern []byte
	for _, p := range bl.SPKIPatterns() {
		if p.Entry.ID == anchor.ID {
			pattern = p.Pattern
		}
	}
	if pattern == nil {
		return fmt.Errorf("no SPKI pattern for %s", anchor.ID)
	}
	binary := append([]byte("\x7fELF"), make([]byte, 60)...)
	binary = append(binary, pattern...)
	binary = append(binary, make([]byte, 64)...)

	entries := []tarEntry{
		{"etc/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")},
		{"etc/ssl/certs/ca-certificates.crt", append(pemOf(anchor.Certificate), pemOf(related.Certificate)...)},
		{"var/lib/dpkg/status", []byte("Package: ca-certificates\nStatus: install ok installed\nVersion: 20230311\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.15-1~deb12u1\n\n")},
		{"usr/local/lib/python3.12/site-packages/certifi/cacert.pem", pemOf(anchor.Certificate)},
		{"usr/local/lib/python3.12/site-packages/certifi-2024.2.2.dist-info/METADATA", []byte("Name: certifi\nVersion: 2024.2.2\n")},
		{"usr/local/bin/app", binary},
	}
	// A PEM body that decodes (to 96 bytes) but is no certificate: the
	// strict parser rejects it with a warning.
	body := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 96))
	broken := "-----BEGIN CERTIFICATE-----\n" + body[:64] + "\n" + body[64:] + "\n-----END CERTIFICATE-----\n"
	for i := 1; i <= brokenPEMs; i++ {
		entries = append(entries, tarEntry{fmt.Sprintf("opt/fixtures/broken-%02d.pem", i), []byte(broken)})
	}
	layerTar, err := tarOf(entries)
	if err != nil {
		return err
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerTar)), nil
	})
	if err != nil {
		return err
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return err
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "s390x"
	cf.Config.Env = []string{"PATH=/usr/local/bin:/usr/bin"}
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		return err
	}
	return tarball.WriteToFile(path, name.MustParseReference("test/x:1"), img)
}

// syncWriter serialises writes: progress messages arrive from the goroutine
// that flattens the image while the scan writes from the test goroutine.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// runCLI runs the command line and returns its exit code and output.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errw syncWriter
	code = run(args, &out, &errw)
	return code, out.String(), errw.String()
}

// scanArgs prefixes args with the scan command and the fixture source.
func scanArgs(args ...string) []string {
	return append([]string{"scan", "--quiet", "--input", fixture}, args...)
}

func TestCommandLine(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOut    []string
		wantErr    []string
		notErr     []string
		emptyErr   bool
		emptyOut   bool
		errMatches map[string]int // substring -> exact number of occurrences on stderr
	}{
		{name: "no arguments", wantCode: 0, wantOut: []string{"Usage:", appName + " scan [flags] IMAGE"}, emptyErr: true},
		{name: "help", args: []string{"help"}, wantCode: 0, wantOut: []string{"Usage:"}, emptyErr: true},
		{name: "--help", args: []string{"--help"}, wantCode: 0, wantOut: []string{"Usage:"}, emptyErr: true},
		{name: "-h", args: []string{"-h"}, wantCode: 0, wantOut: []string{"Usage:"}, emptyErr: true},
		{name: "unknown command", args: []string{"frob"}, wantCode: 1, wantErr: []string{appName + `: unknown command "frob"`, "Run '" + appName + " help' for usage."}, emptyOut: true},
		{name: "scan without image", args: []string{"scan"}, wantCode: 1, wantErr: []string{"an image reference is required", "Run '" + appName + " scan --help' for the flags."}, emptyOut: true},
		{name: "unknown flag printed once", args: []string{"scan", "--bogus", "x"}, wantCode: 1, errMatches: map[string]int{"flag provided but not defined: -bogus": 1, "Usage": 0}, emptyOut: true},
		{name: "scan --help goes to stdout", args: []string{"scan", "--help"}, wantCode: 0, wantOut: []string{"Usage: " + appName + " scan [flags] IMAGE", "-platform", "-input", "Flags must come before IMAGE", "Exit codes:"}, emptyErr: true},
		{name: "scan -h goes to stdout", args: []string{"scan", "-h"}, wantCode: 0, wantOut: []string{"Usage: " + appName + " scan [flags] IMAGE"}, emptyErr: true},
		{name: "flags after IMAGE", args: []string{"scan", "--input", "x.tar", "test/x:1", "--format", "json"}, wantCode: 1, wantErr: []string{`flags must come before IMAGE: "--format" was read as an argument after "test/x:1"`}, emptyOut: true},
		{name: "too many arguments", args: []string{"scan", "a", "b", "c"}, wantCode: 1, wantErr: []string{"too many arguments: b c"}, emptyOut: true},
		{name: "fail-on names never", args: []string{"scan", "--fail-on", "none", "x"}, wantCode: 1, wantErr: []string{`--fail-on: unknown severity "none" (want one of critical, high, medium, low, info or never)`}, emptyOut: true},
		{name: "unknown format", args: []string{"scan", "--format", "xml", "x"}, wantCode: 1, wantErr: []string{`unknown --format "xml" (want text or json)`}, emptyOut: true},
		{name: "zero timeout", args: []string{"scan", "--timeout", "0", "x"}, wantCode: 1, wantErr: []string{"--timeout must be positive (got 0s)"}, emptyOut: true},
		{name: "negative timeout", args: []string{"scan", "--timeout", "-1s", "x"}, wantCode: 1, wantErr: []string{"--timeout must be positive (got -1s)"}, emptyOut: true},
		{name: "missing blocklist", args: []string{"scan", "--blocklist", filepath.Join(os.TempDir(), "ecs-no-such-blocklist.json"), "--input", "x.tar"}, wantCode: 1, wantErr: []string{"--blocklist: open "}, notErr: []string{"Run '"}, emptyOut: true},
		{name: "missing input", args: []string{"scan", "--quiet", "--input", filepath.Join(os.TempDir(), "ecs-no-such-image.tar")}, wantCode: 1, wantErr: []string{"reading local image source"}, emptyOut: true},
		{name: "tag not in archive", args: scanArgs("test/other:1"), wantCode: 1, wantErr: []string{"tag index.docker.io/test/other:1 not found", "test/x:1"}, emptyOut: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("stdout lacks %q:\n%s", want, out)
				}
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(errOut, want) {
					t.Errorf("stderr lacks %q:\n%s", want, errOut)
				}
			}
			for _, unwanted := range tt.notErr {
				if strings.Contains(errOut, unwanted) {
					t.Errorf("stderr contains %q:\n%s", unwanted, errOut)
				}
			}
			for sub, n := range tt.errMatches {
				if got := strings.Count(errOut, sub); got != n {
					t.Errorf("stderr has %d occurrences of %q, want %d:\n%s", got, sub, n, errOut)
				}
			}
			if tt.emptyErr && errOut != "" {
				t.Errorf("stderr not empty:\n%s", errOut)
			}
			if tt.emptyOut && out != "" {
				t.Errorf("stdout not empty:\n%s", out)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 0 || errOut != "" {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errOut)
		}
		// The release workflow greps " <tag> " out of this line.
		if ok, _ := regexp.MatchString(`^emudhra-container-scanner \S+ \(blocklist \S+, go\S+, \S+/\S+\)\n$`, out); !ok {
			t.Errorf("%v: version output %q", args, out)
		}
	}
}

func TestScanExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  []string
		wantErr  []string
	}{
		{name: "default threshold", args: scanArgs(), wantCode: 2, wantOut: []string{"Exit code: 2 (findings at or above high; highest is high)"}},
		{name: "explicit tag", args: scanArgs("test/x:1"), wantCode: 2, wantOut: []string{"Image:     docker-archive:" + fixture + ":test/x:1"}},
		{name: "fail-on critical", args: scanArgs("--fail-on", "critical"), wantCode: 0, wantOut: []string{"Exit code: 0 (no findings at or above critical; highest is high)"}},
		{name: "fail-on low", args: scanArgs("--fail-on", "LOW"), wantCode: 2, wantOut: []string{"Exit code: 2 (findings at or above low; highest is high)"}},
		{name: "fail-on never, any case", args: scanArgs("--fail-on", "NeVeR"), wantCode: 0, wantOut: []string{"Exit code: 0 (--fail-on never)"}},
		{name: "no platform requested accepts the image's own", args: scanArgs(), wantCode: 2, wantOut: []string{"Platform:  " + fixturePlatform + " (1 layer, "}},
		{name: "matching platform requested", args: scanArgs("--platform", fixturePlatform), wantCode: 2, wantOut: []string{"Platform:  " + fixturePlatform}},
		{name: "other platform requested", args: scanArgs("--platform", "linux/amd64"), wantCode: 1, wantErr: []string{"no image for platform linux/amd64", "choose one with --platform"}},
		{name: "operator heuristic off", args: scanArgs("--no-operator-heuristic", "--fail-on", "never"), wantCode: 0},
		{name: "extra keystore password accepted", args: scanArgs("--keystore-password", "s3cret", "--fail-on", "never"), wantCode: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("stdout lacks %q:\n%s", want, out)
				}
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(errOut, want) {
					t.Errorf("stderr lacks %q:\n%s", want, errOut)
				}
			}
			if tt.wantCode != 1 && errOut != "" {
				t.Errorf("--quiet run wrote to stderr:\n%s", errOut)
			}
		})
	}
}

func TestScanTextReport(t *testing.T) {
	code, out, _ := runCLI(t, scanArgs()...)
	if code != 2 {
		t.Fatalf("exit code = %d\n%s", code, out)
	}
	for _, want := range []string{
		"OS:        Debian GNU/Linux 12 (bookworm)\n",
		"Packages (dpkg):\n",
		"OUTDATED: fixed in 20250419~deb12u2",
		"  openssl ",
		"  certifi ",
		"      from: /usr/local/lib/python3.12/site-packages/certifi-2024.2.2.dist-info",
		"Findings (3 high, 1 low; 2 distinct certificates):",
		"/etc/ssl/certs/ca-certificates.crt\n  [HIGH] emSign ECC Root CA - G3 (anchor, fingerprint match)",
		"/usr/local/bin/app\n  [HIGH] emSign ECC Root CA - G3 (anchor, spki match)",
		"         spki:    " + blocklist.Default().ByID("emsign-ecc-root-ca-g3").SPKISHA256 + " (public key only)",
		"/usr/local/lib/python3.12/site-packages/certifi/cacert.pem\n  [HIGH]",
		"Low/info findings (related roots, distrusted or disabled copies, heuristics; run with --verbose for details):\n  [LOW] emSign Root CA - G1 (related) in /etc/ssl/certs/ca-certificates.crt (trusted)",
		"Stores with findings:\n  certificates  findings  class",
		"Warnings (21):",
		"  ... 1 more (run with --verbose)",
		"Exit code: 2 (findings at or above high; highest is high)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"why:", "refs:", "\x1b["} {
		if strings.Contains(out, unwanted) {
			t.Errorf("non-verbose report contains %q:\n%s", unwanted, out)
		}
	}
	// Package rows of different lengths share one set of columns.
	column := -1
	for _, line := range strings.Split(out, "\n") {
		for _, row := range []string{"  ca-certificates ", "  openssl ", "  certifi "} {
			if !strings.HasPrefix(line, row) {
				continue
			}
			i := strings.Index(line, "  dpkg  ")
			if i < 0 {
				i = strings.Index(line, "  pip   ")
			}
			if i < 0 {
				t.Errorf("package row without an aligned manager column: %q", line)
				continue
			}
			if column >= 0 && i != column {
				t.Errorf("manager column at %d, want %d: %q", i, column, line)
			}
			column = i
		}
	}
	if column < 0 {
		t.Errorf("no package rows found:\n%s", out)
	}

	code, verbose, _ := runCLI(t, scanArgs("--verbose")...)
	if code != 2 {
		t.Fatalf("verbose exit code = %d", code)
	}
	for _, want := range []string{"Stores scanned (", "         why:     This is byte-for-byte the listed certificate", "         refs:    https://", "  - /opt/fixtures/broken-21.pem: PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser"} {
		if !strings.Contains(verbose, want) {
			t.Errorf("verbose report lacks %q:\n%s", want, verbose)
		}
	}
	if strings.Contains(verbose, "more (run with --verbose)") {
		t.Errorf("verbose report caps the warnings:\n%s", verbose)
	}
}

func TestScanProgress(t *testing.T) {
	code, _, errOut := runCLI(t, "scan", "--input", fixture, "--fail-on", "never")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, errOut)
	}
	for _, want := range []string{appName + ": resolving docker-archive:" + fixture, appName + ": reading layer 1/1 (", appName + ": scanned "} {
		if !strings.Contains(errOut, want) {
			t.Errorf("progress lacks %q:\n%s", want, errOut)
		}
	}
}

func TestScanOutputFile(t *testing.T) {
	dir := t.TempDir()
	t.Run("written", func(t *testing.T) {
		path := filepath.Join(dir, "report.txt")
		code, out, errOut := runCLI(t, "scan", "--input", fixture, "--output", path)
		if code != 2 || out != "" {
			t.Fatalf("exit code = %d, stdout %q, stderr:\n%s", code, out, errOut)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "Exit code: 2 (findings at or above high; highest is high)") {
			t.Errorf("report file lacks the exit line:\n%s", data)
		}
		if want := "report written to " + path + " (Exit code: 2"; !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	})
	t.Run("overwritten", func(t *testing.T) {
		path := filepath.Join(dir, "old.json")
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, errOut := runCLI(t, scanArgs("--format", "json", "--output", path)...); code != 2 {
			t.Fatalf("exit code = %d\n%s", code, errOut)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(data) {
			t.Errorf("report file is not JSON:\n%s", data)
		}
	})
	t.Run("unwritable path fails before the image is read", func(t *testing.T) {
		path := filepath.Join(dir, "no", "such", "dir", "report.txt")
		code, out, errOut := runCLI(t, "scan", "--input", fixture, "--output", path)
		if code != 1 || out != "" {
			t.Fatalf("exit code = %d, stdout %q", code, out)
		}
		if !strings.Contains(errOut, "--output: open "+path) {
			t.Errorf("stderr lacks the --output error:\n%s", errOut)
		}
		if strings.Contains(errOut, "resolving") || strings.Contains(errOut, "reading layer") {
			t.Errorf("the image was read although the output could not be created:\n%s", errOut)
		}
	})
	t.Run("removed when the scan fails", func(t *testing.T) {
		path := filepath.Join(dir, "removed.txt")
		code, _, errOut := runCLI(t, "scan", "--quiet", "--input", filepath.Join(dir, "missing.tar"), "--output", path)
		if code != 1 {
			t.Fatalf("exit code = %d\n%s", code, errOut)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("output file left behind after a failed scan (stat error %v)", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		code, _, errOut := runCLI(t, scanArgs("--output", dir)...)
		if code != 1 || !strings.Contains(errOut, "--output:") {
			t.Errorf("exit code = %d, stderr:\n%s", code, errOut)
		}
	})
}

// selfSignedPEM returns a certificate that is on no list, for a custom
// blocklist that must not produce findings.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Test Custom CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestScanJSON(t *testing.T) {
	extra := filepath.Join(t.TempDir(), "custom.pem")
	if err := os.WriteFile(extra, selfSignedPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, scanArgs("--format", "JSON", "--blocklist", extra)...)
	if code != 2 || errOut != "" {
		t.Fatalf("exit code = %d, stderr:\n%s", code, errOut)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	for _, key := range []string{"scanner", "image", "os", "packages", "env_hints", "stores", "findings", "summary", "warnings", "exit"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON lacks key %q", key)
		}
	}
	var exit struct {
		FailOn          string   `json:"fail_on"`
		Code            int      `json:"code"`
		ExtraBlocklists []string `json:"extra_blocklists"`
	}
	if err := json.Unmarshal(doc["exit"], &exit); err != nil {
		t.Fatal(err)
	}
	if exit.FailOn != "high" || exit.Code != 2 || len(exit.ExtraBlocklists) != 1 || exit.ExtraBlocklists[0] != extra {
		t.Errorf("exit block = %+v", exit)
	}
	var findings []struct {
		Severity string `json:"severity"`
		Category string `json:"category"`
		Match    string `json:"match"`
		Path     string `json:"path"`
		Cert     struct {
			Kind      string `json:"kind"`
			NotBefore string `json:"not_before"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(doc["findings"], &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 || findings[0].Severity != "high" || findings[3].Severity != "low" || findings[3].Category != "related" {
		t.Errorf("findings = %+v", findings)
	}
	for _, f := range findings {
		if f.Cert.Kind == "spki" && f.Cert.NotBefore != "" {
			t.Errorf("SPKI finding carries a validity: %+v", f)
		}
	}
	var summary struct {
		BySeverity   map[string]int `json:"findings_by_severity"`
		MaxSeverity  string         `json:"max_severity"`
		Affected     int            `json:"affected_certificates"`
		SystemBundle bool           `json:"system_bundle_found"`
		Database     string         `json:"package_database"`
	}
	if err := json.Unmarshal(doc["summary"], &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.BySeverity) != 5 || summary.BySeverity["high"] != 3 || summary.BySeverity["critical"] != 0 || summary.MaxSeverity != "high" || summary.Affected != 2 || !summary.SystemBundle || summary.Database != "dpkg" {
		t.Errorf("summary = %+v", summary)
	}
	var warnings []string
	if err := json.Unmarshal(doc["warnings"], &warnings); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != brokenPEMs {
		t.Errorf("got %d warnings, want %d", len(warnings), brokenPEMs)
	}

	code, out, _ = runCLI(t, scanArgs("--format", "json", "--fail-on", "never")...)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out, "\"exit\": {\n    \"fail_on\": \"never\",\n    \"code\": 0\n  }") {
		t.Errorf("exit block for --fail-on never missing:\n%s", out)
	}
}

func TestScanTimeoutHint(t *testing.T) {
	code, out, errOut := runCLI(t, scanArgs("--timeout", "1ns")...)
	if code != 1 || out != "" {
		t.Fatalf("exit code = %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "(timeout 1ns; raise it with --timeout)") {
		t.Errorf("stderr lacks the timeout hint:\n%s", errOut)
	}
}

func TestExitFor(t *testing.T) {
	withFindings := &scan.Result{Findings: []scan.Finding{{Severity: blocklist.SeverityHigh}, {Severity: blocklist.SeverityLow}}}
	tests := []struct {
		name string
		cfg  scanConfig
		res  *scan.Result
		want scan.Exit
	}{
		{"above threshold", scanConfig{failOnName: "medium", failOn: blocklist.SeverityMedium, failEnabled: true, blocklists: []string{"a.pem"}}, withFindings, scan.Exit{FailOn: "medium", Code: 2, ExtraBlocklists: []string{"a.pem"}}},
		{"at threshold", scanConfig{failOnName: "high", failOn: blocklist.SeverityHigh, failEnabled: true}, withFindings, scan.Exit{FailOn: "high", Code: 2}},
		{"below threshold", scanConfig{failOnName: "critical", failOn: blocklist.SeverityCritical, failEnabled: true}, withFindings, scan.Exit{FailOn: "critical"}},
		{"never", scanConfig{failOnName: "never"}, withFindings, scan.Exit{FailOn: "never"}},
		{"no findings", scanConfig{failOnName: "info", failOn: blocklist.SeverityInfo, failEnabled: true}, &scan.Result{}, scan.Exit{FailOn: "info"}},
	}
	for _, tt := range tests {
		if got := exitFor(tt.res, &tt.cfg); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: exitFor = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}
