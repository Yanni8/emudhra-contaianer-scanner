// Package units formats quantities for human-readable output. It holds the
// helpers that several packages print the same way, so that a byte count
// reads identically in progress messages, reports and warnings.
package units

import (
	"strconv"
	"strings"
)

// Bytes formats a byte count with binary units: "512 B", "1.5 KiB", "12 MiB"
// (a trailing ".0" is dropped). A negative count means that the size is not
// known and reads "size unknown".
func Bytes(n int64) string {
	const unit = 1024
	if n < 0 {
		return "size unknown"
	}
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	s := strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s + " " + string("KMGTPE"[exp]) + "iB"
}

// Plural joins a count with the singular or plural form of its noun:
// Plural(1, "layer", "layers") is "1 layer", Plural(3, "layer", "layers")
// is "3 layers". Zero takes the plural form.
func Plural(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}
