package stores

import (
	"bufio"
	"bytes"
	"strings"
)

// parseOSRelease implements ParseOSRelease. Later assignments win, as they
// would when the file is sourced by a shell.
func parseOSRelease(data []byte) OSInfo {
	var info OSInfo
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = unquoteShell(strings.TrimSpace(value))
		switch strings.TrimSpace(key) {
		case "ID":
			info.ID = value
		case "ID_LIKE":
			info.IDLike = value
		case "VERSION_ID":
			info.VersionID = value
		case "PRETTY_NAME":
			info.PrettyName = value
		}
	}
	return info
}

// unquoteShell strips one level of shell quoting from an os-release value:
// 'single quotes' are literal, "double quotes" allow \", \\, \$ and \`.
func unquoteShell(v string) string {
	if len(v) < 2 {
		return v
	}
	q := v[0]
	if (q != '"' && q != '\'') || v[len(v)-1] != q {
		return v
	}
	v = v[1 : len(v)-1]
	if q == '\'' || !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '"', '\\', '$', '`':
				i++
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
