package stores

import (
	"bufio"
	"bytes"
	"strings"
)

// parseDpkgStatus implements ParseDpkgStatus: a stanza counts only when its
// Status field says the package is installed.
func parseDpkgStatus(data []byte, names []string) []Package {
	return parseDpkgStanzas(data, names, false)
}

// parseDpkgStatusD implements ParseDpkgStatusD: the status.d files written
// by distroless image builds carry no Status field, so a stanza without one
// is installed; a Status field, when present, is still honoured.
func parseDpkgStatusD(data []byte, names []string) []Package {
	return parseDpkgStanzas(data, names, true)
}

// parseDpkgStanzas reads dpkg control stanzas separated by blank lines. A
// package counts as installed when the third word of its Status field is
// "installed" (or a triggers state, which is installed with pending
// triggers), or when the field is absent and installedImplied is set.
func parseDpkgStanzas(data []byte, names []string, installedImplied bool) []Package {
	want := nameSet(names)
	var out []Package
	var name, version, status string
	flush := func() {
		installed := dpkgInstalled(status) || (status == "" && installedImplied)
		if name != "" && want[name] && installed {
			out = appendPackage(out, Package{Name: name, Version: version, Manager: "dpkg"})
		}
		name, version, status = "", "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a multi-line field
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case strings.EqualFold(key, "Package"):
			name = value
		case strings.EqualFold(key, "Version"):
			version = value
		case strings.EqualFold(key, "Status"):
			status = value
		}
	}
	flush()
	return out
}

// dpkgInstalled interprets a dpkg Status field ("want flag status").
func dpkgInstalled(status string) bool {
	f := strings.Fields(status)
	if len(f) < 3 {
		return false
	}
	switch f[2] {
	case "installed", "triggers-awaited", "triggers-pending":
		return true
	}
	return false
}

// parseApkInstalled implements ParseApkInstalled: stanzas of single-letter
// fields, "P:" being the package name and "V:" its version.
func parseApkInstalled(data []byte, names []string) []Package {
	want := nameSet(names)
	var out []Package
	var name, version string
	flush := func() {
		if name != "" && want[name] {
			out = appendPackage(out, Package{Name: name, Version: version, Manager: "apk"})
		}
		name, version = "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			name = strings.TrimSpace(value)
		case "V":
			version = strings.TrimSpace(value)
		}
	}
	flush()
	return out
}

func nameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			set[n] = true
		}
	}
	return set
}

// appendPackage adds p unless an identical entry is already present (dpkg
// lists multi-arch packages once per architecture).
func appendPackage(list []Package, p Package) []Package {
	for _, q := range list {
		if q == p {
			return list
		}
	}
	return append(list, p)
}
