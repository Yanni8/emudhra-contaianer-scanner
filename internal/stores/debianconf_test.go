package stores

import (
	"testing"

	"emudhra-container-scanner/internal/blocklist"
)

const sampleDebianConf = `# This file lists certificates that you wish to use or to ignore to be
# installed in /etc/ssl/certs.
# Lines that begin with "!" will remove the certificate on next update.

mozilla/ACCVRAIZ1.crt
!mozilla/emSign_ECC_Root_CA_-_G3.crt
  mozilla/Comodo_AAA_Services_root.crt  
! mozilla/Certigna.crt
./mozilla/ISRG_Root_X1.crt
/mozilla/ISRG_Root_X2.crt
!
#!mozilla/Commented.crt
`

func TestParseDebianConf(t *testing.T) {
	c := ParseDebianConf([]byte(sampleDebianConf))
	want := map[string]bool{
		"mozilla/ACCVRAIZ1.crt":                true,
		"mozilla/emSign_ECC_Root_CA_-_G3.crt":  false,
		"mozilla/Comodo_AAA_Services_root.crt": true,
		"mozilla/Certigna.crt":                 false,
		"mozilla/ISRG_Root_X1.crt":             true,
		"mozilla/ISRG_Root_X2.crt":             true,
	}
	if len(c.Enabled) != len(want) {
		t.Errorf("got %d entries, want %d: %v", len(c.Enabled), len(want), c.Enabled)
	}
	for rel, enabled := range want {
		got, ok := c.Enabled[rel]
		if !ok || got != enabled {
			t.Errorf("Enabled[%q] = %v, %v; want %v, true", rel, got, ok, enabled)
		}
	}
	if _, ok := c.Enabled["mozilla/Commented.crt"]; ok {
		t.Error("comment line was parsed as an entry")
	}
	if empty := ParseDebianConf(nil); empty.Enabled == nil || len(empty.Enabled) != 0 {
		t.Errorf("ParseDebianConf(nil) = %+v, want an empty, non-nil map", empty)
	}
	if crlf := ParseDebianConf([]byte("mozilla/A.crt\r\n!mozilla/B.crt\r\n")); !crlf.Enabled["mozilla/A.crt"] || crlf.Enabled["mozilla/B.crt"] {
		t.Errorf("CRLF input mis-parsed: %v", crlf.Enabled)
	}
}

func TestDebianConfStatus(t *testing.T) {
	c := ParseDebianConf([]byte(sampleDebianConf))
	tests := []struct {
		path           string
		enabled, known bool
	}{
		{"/usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt", true, true},
		{"usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt", true, true},
		{"./usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt", true, true},
		{"/usr/share/ca-certificates//mozilla/./ACCVRAIZ1.crt", true, true},
		{"mozilla/ACCVRAIZ1.crt", true, true},
		{"/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", false, true},
		{"/usr/share/ca-certificates/mozilla/Certigna.crt", false, true},
		{"/usr/share/ca-certificates/mozilla/Unknown.crt", false, false},
		{"/usr/local/share/ca-certificates/ACCVRAIZ1.crt", false, false},
		{"/usr/share/ca-certificates/mozilla/accvraiz1.crt", false, false}, // names are case-sensitive
		{"", false, false},
	}
	for _, tt := range tests {
		enabled, known := c.Status(tt.path)
		if enabled != tt.enabled || known != tt.known {
			t.Errorf("Status(%q) = %v, %v; want %v, %v", tt.path, enabled, known, tt.enabled, tt.known)
		}
	}
	var zero DebianConf
	if enabled, known := zero.Status("/usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt"); enabled || known {
		t.Error("zero DebianConf must report unknown")
	}
}

func TestDebianSourceName(t *testing.T) {
	tests := []struct{ label, want string }{
		{"emSign ECC Root CA - G3", "mozilla/emSign_ECC_Root_CA_-_G3.crt"},
		{"Comodo AAA Services root", "mozilla/Comodo_AAA_Services_root.crt"},
		{"GlobalSign Root CA - R3", "mozilla/GlobalSign_Root_CA_-_R3.crt"},
		{"NetLock Arany (Class Gold) Főtanúsítvány", "mozilla/NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt"},
		{"TWCA Root Certification Authority", "mozilla/TWCA_Root_Certification_Authority.crt"},
		{"AC RAIZ FNMT-RCM SERVIDORES SEGUROS", "mozilla/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt"},
		{" Hellenic Academic and Research Institutions RootCA 2015 ", "mozilla/Hellenic_Academic_and_Research_Institutions_RootCA_2015.crt"},
		{"a/b,c", "mozilla/a_b_c.crt"},
	}
	for _, tt := range tests {
		if got := DebianSourceName(tt.label); got != tt.want {
			t.Errorf("DebianSourceName(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

// The removed root, as Debian names it, round-trips through the conf parser
// and Status so that the scanner can tell whether it is deselected.
func TestDebianConfWithBlocklistRoot(t *testing.T) {
	root := blocklist.Default().ByID("emsign-ecc-root-ca-g3").Certificate
	rel := DebianSourceName(root.Subject.CommonName)
	c := ParseDebianConf([]byte("mozilla/ISRG_Root_X1.crt\n!" + rel + "\n"))
	enabled, known := c.Status(debianSourcePrefix + rel)
	if enabled || !known {
		t.Fatalf("Status(%q) = %v, %v; want deselected and known", rel, enabled, known)
	}
	if s := Classify(debianSourcePrefix+rel, nil); s.Class != ClassSystemSource || s.TrustedByDefault {
		t.Fatalf("source file classified as %+v", s)
	}
}
