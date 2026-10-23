package units

import "testing"

func TestBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{-1, "size unknown"},
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{12 << 20, "12 MiB"},
		{123456789, "117.7 MiB"},
		{5 << 30, "5 GiB"},
		{3 << 40, "3 TiB"},
		{7 << 50, "7 PiB"},
		{2 << 60, "2 EiB"},
	}
	for _, tt := range tests {
		if got := Bytes(tt.n); got != tt.want {
			t.Errorf("Bytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestPlural(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0 layers"},
		{1, "1 layer"},
		{2, "2 layers"},
		{-1, "-1 layers"},
	}
	for _, tt := range tests {
		if got := Plural(tt.n, "layer", "layers"); got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
