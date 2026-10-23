package stores

import "strings"

// compareVersion implements CompareVersion: a leading "v" is dropped, then
// the dpkg algorithm decides.
func compareVersion(a, b string) int {
	return compareDebVersion(trimVersionPrefix(a), trimVersionPrefix(b))
}

// trimVersionPrefix removes the "v" that tags and release names put in front
// of a version number ("v22.23.4").
func trimVersionPrefix(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && isDigit(v[1]) {
		return v[1:]
	}
	return v
}

// javaVersionMajor implements JavaVersionMajor. The legacy "1.N.0_update"
// scheme (JDK 8 and older) is folded into the modern one so that
// "1.8.0_462" becomes major 8, "8.0.462".
func javaVersionMajor(v string) (int, string, bool) {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if strings.HasPrefix(v, "1.") && len(v) > 2 && isDigit(v[2]) {
		v = v[2:]
	}
	i := 0
	for i < len(v) && isDigit(v[i]) {
		i++
	}
	if i == 0 || i > 4 {
		return 0, "", false
	}
	major := 0
	for _, c := range v[:i] {
		major = major*10 + int(c-'0')
	}
	if major <= 1 {
		// 0 is not a Java version and a lone 1 is a legacy "1.x" prefix
		// without the release number.
		return 0, "", false
	}
	return major, strings.ReplaceAll(v, "_", "."), true
}

// compareDebVersion implements CompareDebVersion with dpkg's algorithm:
// epochs compare numerically, then the upstream version and the Debian
// revision with verrevcmp.
func compareDebVersion(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// splitDebVersion splits "epoch:upstream-revision". The epoch must be all
// digits to count as one; the revision starts at the last hyphen.
func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i > 0 && allDigits(v[:i]) {
		for _, c := range v[:i] {
			epoch = epoch*10 + int(c-'0')
			if epoch > 1<<30 {
				epoch = 1 << 30 // clamp absurd epochs instead of overflowing
			}
		}
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order ranks a character the way dpkg does: '~' before everything (even
// the end of the string), then the end of the string and digits, then
// letters, then all other characters.
func order(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's comparison of one version component: alternating runs
// of non-digits (compared character by character through order) and digits
// (compared numerically).
func verrevcmp(a, b string) int {
	for a != "" || b != "" {
		firstDiff := 0
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ac, bc := order(a), order(b)
			if ac != bc {
				return sign(ac - bc)
			}
			// Equal orders of non-digits imply both strings are non-empty here.
			a, b = a[1:], b[1:]
		}
		a = strings.TrimLeft(a, "0")
		b = strings.TrimLeft(b, "0")
		for a != "" && b != "" && isDigit(a[0]) && isDigit(b[0]) {
			if firstDiff == 0 {
				firstDiff = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		if a != "" && isDigit(a[0]) {
			return 1
		}
		if b != "" && isDigit(b[0]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
