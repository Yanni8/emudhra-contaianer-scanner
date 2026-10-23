package image

// reporter returns f, or a no-op when f is nil, so callers can report
// unconditionally.
func reporter(f func(string)) func(string) {
	if f == nil {
		return func(string) {}
	}
	return f
}
