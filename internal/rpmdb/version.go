package rpmdb

import "strings"

// CompareEVR compares two rpm version strings of the form
// "[epoch:]version[-release]" with rpm's own rules (rpmvercmp): the epochs
// (0 when absent) first, then the versions, then the releases, which are
// only compared when both strings carry one, so that a bare fixed version
// matches every release of that version. The result is -1, 0 or 1.
func CompareEVR(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := CompareVersion(ea, eb); c != 0 {
		return c
	}
	if c := CompareVersion(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		return 0
	}
	return CompareVersion(ra, rb)
}

// splitEVR splits "epoch:version-release"; the epoch defaults to "0" and
// the release starts at the last hyphen.
func splitEVR(evr string) (epoch, version, release string) {
	epoch = "0"
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		if i > 0 {
			epoch = evr[:i]
		}
		evr = evr[i+1:]
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		return epoch, evr[:i], evr[i+1:]
	}
	return epoch, evr, ""
}

// CompareVersion compares two version (or release) strings the way rpm's
// rpmvercmp does: the strings are cut into runs of digits and runs of
// letters, every other character being a separator; digit runs compare
// numerically, letter runs lexically, a digit run beats a letter run, "~"
// sorts before anything including the end of the string, "^" sorts after
// the end of the string but before anything else, and when all segments
// are equal the string with segments left over is the greater one.
func CompareVersion(a, b string) int {
	if a == b {
		return 0
	}
	for a != "" || b != "" {
		a = strings.TrimLeftFunc(a, isSeparator)
		b = strings.TrimLeftFunc(b, isSeparator)
		if hasPrefix(a, '~') || hasPrefix(b, '~') {
			if !hasPrefix(a, '~') {
				return 1
			}
			if !hasPrefix(b, '~') {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if hasPrefix(a, '^') || hasPrefix(b, '^') {
			switch {
			case a == "":
				return -1
			case b == "":
				return 1
			case !hasPrefix(a, '^'):
				return 1
			case !hasPrefix(b, '^'):
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := isDigit(a[0])
		var segA, segB string
		if numeric {
			segA, a = cutRun(a, isDigit)
			segB, b = cutRun(b, isDigit)
		} else {
			segA, a = cutRun(a, isAlpha)
			segB, b = cutRun(b, isAlpha)
		}
		if segB == "" { // the other string starts a segment of the other kind
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}

// cutRun splits the longest prefix of s whose bytes satisfy class.
func cutRun(s string, class func(byte) bool) (run, rest string) {
	i := 0
	for i < len(s) && class(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func hasPrefix(s string, c byte) bool { return s != "" && s[0] == c }
func isDigit(c byte) bool             { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool             { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// isSeparator reports whether r is skipped between segments: anything that
// is not an ASCII letter or digit, "~" or "^".
func isSeparator(r rune) bool {
	return r < 0x80 && !isDigit(byte(r)) && !isAlpha(byte(r)) && r != '~' && r != '^' || r >= 0x80
}
