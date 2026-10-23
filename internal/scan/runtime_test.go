package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Yanni8/emudhra-container-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-container-scanner/internal/certs"
	"github.com/Yanni8/emudhra-container-scanner/internal/stores"
)

// spkiInner returns the value bytes of a SubjectPublicKeyInfo without its
// outer SEQUENCE header, as webpki-roots tables store keys.
func spkiInner(spki []byte) []byte {
	hdr := 2
	if spki[1]&0x80 != 0 {
		hdr = 2 + int(spki[1]&0x7f)
	}
	return spki[hdr:]
}

// fakeBinary builds an ELF-like blob with the given pieces spread through
// random padding.
func fakeBinary(seed int64, pieces ...[]byte) []byte {
	out := append([]byte(nil), elfHeader...)
	for i, p := range pieces {
		out = append(out, randomBytes(seed+int64(i), 3000)...)
		out = append(out, p...)
	}
	return append(out, randomBytes(seed+100, 2000)...)
}

func TestRuntimeBinaries(t *testing.T) {
	inter := blocklistCert(t, "em-dv-tls-ca-g3b")
	g3 := blocklistCert(t, "emsign-ecc-root-ca-g3")
	g1 := blocklistCert(t, "emsign-root-ca-g1")

	b := newTar()
	b.file("usr/bin/deno", fakeBinary(21, []byte("Deno/2.9.8 (unknown; linux x86_64)\x00"), spkiInner(inter.RawSubjectPublicKeyInfo), g1.Raw))
	b.file("usr/local/bin/bun", fakeBinary(31, []byte("Bun v1.4.4 (38afee6c8) Linux x64\x00"), g3.Raw))
	b.file("usr/local/bin/uv", fakeBinary(41, []byte("uv/0.13.3 (abc)\x00"), spkiInner(g3.RawSubjectPublicKeyInfo)))
	b.file("usr/local/go/VERSION", []byte("go1.25.14\ntime 2026-10-01T00:00:00Z\n"))
	b.file("etc/os-release", []byte("ID=debian\nVERSION_ID=\"13\"\n"))
	res := scanTar(t, b.bytes(), Options{Env: []string{
		"GOLANG_VERSION=1.25.14", "DENO_VERSION=2.9.9", "JAVA_VERSION=jdk-21.0.12+7", "NODE_VERSION=v22.23.4", "BUN_VERSION=",
	}})

	// The compromised keys inside a fixed Deno are its SPKI blocklist.
	f, ok := findingFor(res, "/usr/bin/deno", "em-dv-tls-ca-g3b")
	if !ok {
		t.Fatal("deno SPKI finding missing")
	}
	if f.Severity != blocklist.SeverityInfo || f.Trust.State != TrustDistrusted || f.Category != blocklist.CategoryCompromisedKey || f.Certificate.Kind != certs.KindSPKI {
		t.Errorf("deno blocklist entry: severity %s trust %s category %s kind %s", f.Severity, f.Trust.State, f.Category, f.Certificate.Kind)
	}
	if !strings.Contains(f.Trust.Detail, "SPKI blocklist a fixed runtime carries") || !strings.Contains(f.Remediation, "No action needed") || strings.Contains(f.Remediation, "Upgrade") {
		t.Errorf("deno blocklist entry: detail %q remediation %q", f.Trust.Detail, f.Remediation)
	}
	if f.Certificate.Subject != inter.Subject.String() || f.Certificate.Issuer != inter.Issuer.String() || !f.Certificate.NotAfter.IsZero() || f.Certificate.SHA256 != "" {
		t.Errorf("deno blocklist entry certificate = %+v", f.Certificate)
	}
	if f, _ := findingFor(res, "/usr/bin/deno", "emsign-root-ca-g1"); f.Severity != blocklist.SeverityLow || f.Trust.State != TrustEmbedded || f.Store.Ecosystem != "deno" || !strings.Contains(f.Remediation, "No action is required") {
		t.Errorf("deno related root: severity %s trust %s ecosystem %s remediation %q", f.Severity, f.Trust.State, f.Store.Ecosystem, f.Remediation)
	}
	// Bun is at the fixed release: no upgrade advice.
	if f, _ := findingFor(res, "/usr/local/bin/bun", "emsign-ecc-root-ca-g3"); f.Severity != blocklist.SeverityHigh || f.Trust.State != TrustEmbedded || !strings.Contains(f.Remediation, "Bun 1.4.4 is already at a fixed release (first fixed: 1.4.4)") || strings.Contains(f.Remediation, "Upgrade to") {
		t.Errorf("bun finding: severity %s trust %s remediation %q", f.Severity, f.Trust.State, f.Remediation)
	}
	// An outdated uv with a bare anchor key in its trust-anchor table.
	if f, _ := findingFor(res, "/usr/local/bin/uv", "emsign-ecc-root-ca-g3"); f.Severity != blocklist.SeverityHigh || f.Trust.State != TrustEmbedded || f.Certificate.Kind != certs.KindSPKI || !strings.Contains(f.Trust.Detail, "compiled into uv as a bare trust-anchor table") || !strings.Contains(f.Remediation, "Upgrade to 0.13.4") {
		t.Errorf("uv finding: severity %s trust %+v remediation %q", f.Severity, f.Trust, f.Remediation)
	}

	// Version rows: binaries win over the environment, the environment fills the gaps.
	pkgs := packagesByKey(res)
	if p := pkgs["deno:deno"]; p.Version != "2.9.8" || p.Outdated == nil || *p.Outdated || p.FixedVersion != "2.9.8" || p.Path != "/usr/bin/deno" {
		t.Errorf("deno = %+v", p)
	}
	if p := pkgs["bun:bun"]; p.Version != "1.4.4" || p.Outdated == nil || *p.Outdated || p.Path != "/usr/local/bin/bun" {
		t.Errorf("bun = %+v", p)
	}
	if p := pkgs["uv:uv"]; p.Version != "0.13.3" || p.Outdated == nil || !*p.Outdated || p.FixedVersion != "0.13.4" || !strings.Contains(p.Note, "0.13.5") {
		t.Errorf("uv = %+v", p)
	}
	if p := pkgs["go:go"]; p.Version != "1.25.14" || p.Outdated == nil || !*p.Outdated || p.FixedVersion != "" || !strings.Contains(p.Note, "1.26.10") || p.Path != "/usr/local/go" {
		t.Errorf("go = %+v", p)
	}
	if p := pkgs["jdk:java (from JAVA_VERSION)"]; p.Version != "21.0.12+7" || p.Outdated == nil || !*p.Outdated || p.FixedVersion != "21.0.13.0.2" || p.Path != "JAVA_VERSION (image environment)" {
		t.Errorf("java from env = %+v", p)
	}
	if p := pkgs["node:node"]; p.Version != "22.23.4" || p.Outdated == nil || *p.Outdated || p.Path != "NODE_VERSION (image environment)" {
		t.Errorf("node from env = %+v", p)
	}
	counts := map[string]int{}
	for _, p := range res.Packages {
		counts[p.Manager]++
	}
	if counts["go"] != 1 || counts["deno"] != 1 || len(res.Packages) != 6 {
		t.Errorf("package rows = %+v", res.Packages)
	}
	if s, _ := storeFor(res, "/usr/bin/deno"); s.Class != stores.ClassEmbeddedRuntime || s.Certificates != 1 || s.Findings != 2 {
		t.Errorf("deno store = %+v", s)
	}
}

func TestVersionProbeChunks(t *testing.T) {
	payload := append(append(randomBytes(5, 500), []byte("OTel-OTLP-Exporter-Deno/0.82.0grpc Deno/abc Deno/2.9 Deno/2.9.8-canary Deno/2.9.8+fe7ed01 (linux)")...), randomBytes(6, 300)...)
	for _, chunk := range []int{1, 7, 63, 64, 65, 1000, len(payload)} {
		p := newVersionProbe("Deno")
		for i := 0; i < len(payload); i += chunk {
			if _, err := p.Write(payload[i:min(i+chunk, len(payload))]); err != nil {
				t.Fatal(err)
			}
		}
		if p.versions["deno"] != "2.9.8" {
			t.Errorf("chunk %d: versions = %v", chunk, p.versions)
		}
	}
	// A version cut off by the end of the file is not reported.
	p := newVersionProbe("Deno")
	p.Write([]byte("Deno/2.9"))
	if len(p.versions) != 0 {
		t.Errorf("incomplete version reported: %v", p.versions)
	}
	// Node.js: the release download URL; Bun: both forms; unknown runtimes have no probe.
	p = newVersionProbe("Node.js")
	p.Write([]byte("https://nodejs.org/download/release/v20.18.0/node-v20.18.0.tar.gz"))
	if p.versions["node"] != "20.18.0" {
		t.Errorf("node versions = %v", p.versions)
	}
	p = newVersionProbe("Bun")
	p.Write([]byte("bun/1.4.4 npm/? node/v26.3.0"))
	if p.versions["bun"] != "1.4.4" {
		t.Errorf("bun versions = %v", p.versions)
	}
	if newVersionProbe("Chromium") != nil || newVersionProbe("") != nil {
		t.Error("unexpected probe for a runtime without version strings")
	}
	for in, want := range map[string]string{"1.2.3 (": "1.2.3", "10.20.30x": "10.20.30", "1.2": "", "a.b.c": "", "1.2.3": "", "1..3 ": "", "1234567.1.1 ": ""} {
		got, ok, _ := semverAt([]byte(in))
		if got != want || ok != (want != "") {
			t.Errorf("semverAt(%q) = %q, %v", in, got, ok)
		}
	}
	if !bytes.Equal(newVersionProbe("uv").patterns[0].prefix, []byte("uv/")) {
		t.Error("uv probe pattern")
	}
	p = newVersionProbe("Bun")
	p.Write([]byte("bun/1.4.4 npm/? node/v26.3.0 ... Bun v1.4.5 (x) ... bun/0.1.0"))
	if p.versions["bun"] != "1.4.5" {
		t.Errorf("highest version must win: %v", p.versions)
	}
}
