package stores

import "testing"

func TestCompareDebVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// The classic cases from the task.
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "2.0", 1},
		{"20250419+deb13u1", "20250419", 1},
		{"20250419~deb12u2", "20250419", -1},
		{"20260816+nmu1", "20250419+deb13u1", 1},
		{"20261020-r0", "20240226-r0", 1},
		{"3.98-1ubuntu0.3", "3.98-1ubuntu0.2", 1},

		// Equality and normalisation.
		{"1.0", "1.0", 0},
		{"", "", 0},
		{"1.0", "1.0-0", 0},
		{"0:1.0", "1.0", 0},
		{"1.01", "1.1", 0},
		{"1.0", "1.00", 0},
		{" 1.0 ", "1.0", 0},

		// Epochs.
		{"1:0.1", "0:9.9", 1},
		{"2:1.0", "1:9.0", 1},
		{"1:1.0", "1:1.0", 0},
		{"a:1.0", "1.0", 1}, // not an epoch: 'a' is compared as a letter

		// Tildes sort before everything, including the end of a part.
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0~", "1.0~a", -1},
		{"1.0~beta", "1.0~rc", -1},
		{"1.0-1~bpo12+1", "1.0-1", -1},
		{"1.0-1~bpo12+1", "1.0-1~bpo11+1", 1},

		// Letters sort before non-letters; digits compare numerically.
		{"1.0a", "1.0+", -1},
		{"1.0a", "1.0b", -1},
		{"1.0", "1.0a", -1},
		{"1.0+dfsg", "1.0", 1},
		{"1.10", "1.9", 1},
		{"1.2", "1.10", -1},
		{"2.0", "10.0", -1},
		{"1.0.0", "1.0", 1},
		{"1.0", "1.0.0", -1},

		// Revisions.
		{"1.0-1", "1.0-2", -1},
		{"1.0-10", "1.0-9", 1},
		{"1.0-1", "1.0-1", 0},
		{"1.0-1.1", "1.0-1", 1},
		{"1.0-1-2", "1.0-1-1", 1}, // revision starts at the last hyphen
		{"1.0-1-2", "1.0-2-1", -1},
		{"1:1.0-1", "1:1.0-1+b1", -1},

		// Distribution versions that matter for ca-certificates and friends.
		{"20250419+deb13u1", "20250419+deb13u2", -1},
		{"20250419~deb12u2", "20250419~deb12u1", 1},
		{"20230311", "20250419~deb12u2", -1},
		{"20240203", "20260816+nmu1", -1},
		{"20260816ubuntu0.24.04.1", "20260816", 1},
		{"20260816ubuntu0.24.04.1", "20260816ubuntu0.24.04.2", -1},
		{"20240203ubuntu1", "20260816ubuntu0.24.04.1", -1},
		{"20240705-r0", "20261020-r0", -1},
		{"20261020-r0", "20261020-r1", -1},
		{"2026.2.92_v9.0.319", "2024.2.69_v8.0.303", 1},
		{"3.131.1-1", "3.130-1", 1},
		{"3.0.15-1~deb12u1", "3.0.15-1", -1},
		{"2:3.87.1-1+deb12u1", "2:3.87.1-1", 1},
		{"17.0.13+11-2~deb12u1", "17.0.21+9-1~deb12u1", -1},
	}
	for _, tt := range tests {
		if got := CompareDebVersion(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareDebVersion(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := CompareDebVersion(tt.b, tt.a); got != -tt.want {
			t.Errorf("CompareDebVersion(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestCompareDebVersionIsTransitiveOnSortedList(t *testing.T) {
	// Ascending order; every pair must agree with the list order.
	sorted := []string{
		"1.0~~", "1.0~", "1.0~a", "1.0~rc1", "1.0", "1.0-0", "1.0-1~bpo11+1", "1.0-1", "1.0-1+b1", "1.0-2",
		"1.0a", "1.0+dfsg", "1.0.0", "1.1", "1.10", "2.0", "10.0", "1:0.1", "1:1.0", "2:0.1",
	}
	for i := range sorted {
		for j := range sorted {
			want := sign(i - j)
			// 1.0 and 1.0-0 are equal; the list keeps them adjacent.
			if (sorted[i] == "1.0" && sorted[j] == "1.0-0") || (sorted[i] == "1.0-0" && sorted[j] == "1.0") {
				want = 0
			}
			if got := CompareDebVersion(sorted[i], sorted[j]); got != want {
				t.Errorf("CompareDebVersion(%q, %q) = %d, want %d", sorted[i], sorted[j], got, want)
			}
		}
	}
}

func TestSplitDebVersion(t *testing.T) {
	tests := []struct {
		v       string
		epoch   int
		up, rev string
	}{
		{"1.0", 0, "1.0", ""},
		{"1.0-1", 0, "1.0", "1"},
		{"1:1.0-1", 1, "1.0", "1"},
		{"12:1.0-1-2", 12, "1.0-1", "2"},
		{"a:1.0", 0, "a:1.0", ""},
		{":1.0", 0, ":1.0", ""},
		{"1.0-", 0, "1.0", ""},
		{"-1", 0, "", "1"},
		{"", 0, "", ""},
	}
	for _, tt := range tests {
		e, u, r := splitDebVersion(tt.v)
		if e != tt.epoch || u != tt.up || r != tt.rev {
			t.Errorf("splitDebVersion(%q) = %d, %q, %q; want %d, %q, %q", tt.v, e, u, r, tt.epoch, tt.up, tt.rev)
		}
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Node.js, Deno, Bun, uv.
		{"20.20.2", "22.23.4", -1},
		{"22.9.0", "22.23.4", -1},
		{"22.23.4", "22.23.4", 0},
		{"22.23.5", "22.23.4", 1},
		{"v22.23.4", "22.23.4", 0},
		{"V24.22.1", "24.22.1", 0},
		{"2.9.7", "2.9.8", -1},
		{"2.10.0", "2.9.8", 1},
		{"1.4.3", "1.4.4", -1},
		{"0.13.3", "0.13.4", -1},
		{"0.13.5", "0.13.4", 1},
		// PyPI date versions, with and without leading zeros.
		{"2026.7.22", "2026.10.18", -1},
		{"2026.10.18", "2026.10.19", -1},
		{"2024.08.30", "2024.8.30", 0},
		{"2024.08.30", "2026.10.18", -1},
		{"26.2.1", "26.2.2", -1},
		{"25.0.1", "26.2.2", -1},
		// Go.
		{"1.25.14", "1.27.3", -1},
		{"1.27.2", "1.27.3", -1},
		{"1.27.3", "1.27.3", 0},
		{"1.26.10", "1.26.9", 1},
		// Normalised JDK versions against the fixed .0.2 re-releases.
		{"17.0.20.1", "17.0.21.0.2", -1},
		{"17.0.21", "17.0.21.0.2", -1},
		{"17.0.21+9", "17.0.21.0.2", -1},
		{"17.0.21+9-LTS", "17.0.21.0.2", -1},
		{"17.0.21.0.2", "17.0.21.0.2", 0},
		{"17.0.21.0.2+1", "17.0.21.0.2", 1},
		{"17.0.21.0.2-LTS", "17.0.21.0.2", 1},
		{"17.0.22", "17.0.21.0.2", 1},
		{"21.0.12.1", "21.0.13.0.2", -1},
		{"21.0.13+11", "21.0.13.0.2", -1},
		{"8.0.462", "8.0.512", -1},
		{"8.0.512-b07", "8.0.512", 1},
		{"8.0.462-b08", "8.0.512", -1},
		// Distribution packages still follow dpkg.
		{"20250419~deb12u1", "20250419~deb12u2", -1},
		{"2026.2.92_v9.0.319-1", "2026.2.92_v9.0.319-2", -1},
		{"20260413-r0", "20261020-r0", -1},
		{"", "", 0},
		{"v", "v", 0},
	}
	for _, tt := range tests {
		if got := CompareVersion(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersion(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := CompareVersion(tt.b, tt.a); got != -tt.want {
			t.Errorf("CompareVersion(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestJavaVersionMajor(t *testing.T) {
	tests := []struct {
		v          string
		major      int
		normalised string
		ok         bool
	}{
		{"1.8.0_462", 8, "8.0.462", true},
		{"1.8.0_462-b08", 8, "8.0.462-b08", true},
		{"1.8.0_512", 8, "8.0.512", true},
		{"1.8.0", 8, "8.0", true},
		{"1.7.0_80", 7, "7.0.80", true},
		{"17.0.20.1", 17, "17.0.20.1", true},
		{"17.0.21+9", 17, "17.0.21+9", true},
		{"17.0.21.0.2", 17, "17.0.21.0.2", true},
		{"21.0.9", 21, "21.0.9", true},
		{"21.0.12.1+1-LTS", 21, "21.0.12.1+1-LTS", true},
		{"11.0.33.0.2", 11, "11.0.33.0.2", true},
		{"25-ea", 25, "25-ea", true},
		{"27", 27, "27", true},
		{"9", 9, "9", true},
		{` "17.0.21" `, 17, "17.0.21", true},
		{"", 0, "", false},
		{"openjdk", 0, "", false},
		{"0.1", 0, "", false},
		{"1.x", 0, "", false},
		{"123456", 0, "", false},
	}
	for _, tt := range tests {
		major, normalised, ok := JavaVersionMajor(tt.v)
		if major != tt.major || normalised != tt.normalised || ok != tt.ok {
			t.Errorf("JavaVersionMajor(%q) = %d, %q, %v; want %d, %q, %v", tt.v, major, normalised, ok, tt.major, tt.normalised, tt.ok)
		}
	}
	// The normalised form compares against the fixed versions.
	for _, tt := range []struct {
		installed string
		outdated  bool
	}{
		{"17.0.20.1", true}, {"17.0.21+9", true}, {"17.0.21.0.2", false}, {"17.0.21.0.2+1", false},
		{"21.0.12.1", true}, {"21.0.13.0.2-LTS", false}, {"11.0.32", true}, {"25.0.5", true}, {"25.0.5.0.2", false}, {"27.0.1.0.2", false},
	} {
		major, normalised, ok := JavaVersionMajor(tt.installed)
		fix, found := JavaFix(major)
		if !ok || !found || fix.FixedVersion == "" {
			t.Fatalf("%s: major %d ok %v fix %+v", tt.installed, major, ok, fix)
		}
		if got := CompareVersion(normalised, fix.FixedVersion) < 0; got != tt.outdated {
			t.Errorf("%s vs %s: outdated = %v, want %v", tt.installed, fix.FixedVersion, got, tt.outdated)
		}
	}
	if major, normalised, ok := JavaVersionMajor("1.8.0_462"); !ok || major != 8 || CompareVersion(normalised, "8.0.512") >= 0 {
		t.Errorf("1.8.0_462 must sort below 8.0.512: %d %q %v", major, normalised, ok)
	}
}
