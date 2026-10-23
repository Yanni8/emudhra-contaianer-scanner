package stores

import (
	"bufio"
	"bytes"
	"path"
	"strings"
)

// debianSourcePrefix is where /etc/ca-certificates.conf entries live.
const debianSourcePrefix = "/usr/share/ca-certificates/"

// parseDebianConf implements ParseDebianConf.
func parseDebianConf(data []byte) DebianConf {
	c := DebianConf{Enabled: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		enabled := true
		if strings.HasPrefix(line, "!") {
			enabled = false
			line = strings.TrimSpace(line[1:])
		}
		rel := cleanRelative(line)
		if rel == "" {
			continue
		}
		c.Enabled[rel] = enabled
	}
	return c
}

// status implements DebianConf.Status.
func (c DebianConf) status(absPath string) (enabled, known bool) {
	enabled, known = c.Enabled[debianRelative(absPath)]
	return enabled && known, known
}

// debianRelative strips the /usr/share/ca-certificates/ prefix from a path
// given in any of the forms "/usr/share/ca-certificates/x", "usr/share/..."
// or "./usr/share/..."; a path without the prefix is returned cleaned, so
// that a bare relative name ("mozilla/x.crt") works too.
func debianRelative(p string) string {
	abs := normalisePath(p)
	if strings.HasPrefix(abs, debianSourcePrefix) {
		return abs[len(debianSourcePrefix):]
	}
	return strings.TrimPrefix(abs, "/")
}

// cleanRelative normalises a configuration entry to a clean relative path.
func cleanRelative(rel string) string {
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	if rel == "." {
		return ""
	}
	return rel
}

// DebianSourceName returns the file name under /usr/share/ca-certificates
// that Debian, Ubuntu and Alpine give a Mozilla root certificate, derived
// from its NSS label the way certdata2pem does ("emSign ECC Root CA - G3"
// becomes "mozilla/emSign_ECC_Root_CA_-_G3.crt"). It is the name to use in
// /etc/ca-certificates.conf.
func DebianSourceName(label string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "(", "=", ")", "=", ",", "_")
	return "mozilla/" + r.Replace(strings.TrimSpace(label)) + ".crt"
}
