package stores

import (
	"strings"
	"testing"
)

func TestKnownRuntimeBinary(t *testing.T) {
	tests := []struct {
		path    string
		runtime string // "" means not known
	}{
		{"/usr/local/bin/node", "Node.js"},
		{"/usr/bin/nodejs", "Node.js"},
		{"/usr/bin/node22", "Node.js"},
		{"/usr/bin/node-22", "Node.js"},
		{"/usr/bin/nodejs18", "Node.js"},
		{"/opt/node-v22.1.0/bin/node", "Node.js"},
		{"/usr/bin/NODE.EXE", "Node.js"},
		{"/usr/lib/x86_64-linux-gnu/libnode.so.115", "Node.js (libnode shared library)"},
		{"/usr/lib64/libnode.so", "Node.js (libnode shared library)"},
		{"/usr/lib/libnode115.so", "Node.js (libnode shared library)"},
		{"/usr/lib/libnode.dylib", "Node.js (libnode shared library)"},
		{"/usr/bin/deno", "Deno"},
		{"/usr/local/bin/bun", "Bun"},
		{"/opt/app/electron", "Electron"},
		{"/opt/app/electron25", "Electron"},
		{"/opt/google/chrome/chrome", "Chromium"},
		{"/usr/bin/chromium", "Chromium"},
		{"/usr/bin/chromium-browser", "Chromium"},
		{"/usr/bin/google-chrome", "Chromium"},
		{"/usr/bin/google-chrome-stable", "Chromium"},
		{"/usr/bin/google-chrome-beta", "Chromium"},
		{"/usr/bin/google-chrome-unstable", "Chromium"},
		{"/opt/microsoft/msedge/msedge", "Chromium"},
		{"/usr/bin/microsoft-edge-stable", "Chromium"},
		{"/opt/brave.com/brave/brave", "Chromium"},
		{"/usr/bin/brave-browser", "Chromium"},
		{"/usr/bin/brave-browser-nightly", "Chromium"},
		{"/opt/chrome-headless-shell/headless_shell", "Chromium"},
		{"/opt/cef/libcef.so", "Chromium Embedded Framework (libcef)"},
		{"/opt/nwjs/nw", "NW.js"},
		{"/usr/lib/x86_64-linux-gnu/nss/libnssckbi.so", "NSS builtin roots (libnssckbi)"},
		{"/Applications/Firefox.app/Contents/MacOS/libnssckbi.dylib", "NSS builtin roots (libnssckbi)"},
		{`C:\Program Files\Firefox\nssckbi.dll`, "NSS builtin roots (libnssckbi)"},
		{"/usr/lib/dart/bin/dart", "Dart"},
		{"/opt/flutter/bin/flutter", "Flutter (Dart runtime)"},
		{"/usr/local/bin/uv", "uv"},
		{"/usr/local/bin/uvx", "uv"},
		{"uv", "uv"},

		// Not runtimes that embed roots.
		{"/usr/bin/python3.12", ""},
		{"/usr/bin/node_exporter", ""},
		{"/usr/bin/node-gyp", ""},
		{"/usr/bin/nodemon", ""},
		{"/usr/bin/firefox", ""},
		{"/usr/bin/java", ""},
		{"/usr/bin/cargo", ""},
		{"/usr/bin/rustup", ""},
		{"/usr/bin/ruff", ""},
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", ""},
		{"/usr/lib/p11-kit/p11-kit-trust.so", ""},
		{"/usr/bin/22", ""},
		{"", ""},
		{"/", ""},
	}
	for _, tt := range tests {
		got, ok := KnownRuntimeBinary(tt.path)
		if ok != (tt.runtime != "") || got != tt.runtime {
			t.Errorf("KnownRuntimeBinary(%q) = %q, %v; want %q, %v", tt.path, got, ok, tt.runtime, tt.runtime != "")
		}
	}
}

func TestRuntimeStoreMentionsFix(t *testing.T) {
	for name, rt := range runtimes {
		s := runtimeStore(rt)
		if s.Class != ClassEmbeddedRuntime || !s.TrustedByDefault || s.Ecosystem == "" || len(s.Consumers) == 0 {
			t.Errorf("%s: bad store %+v", name, s)
		}
		if !strings.Contains(s.Remediation, rt.Description) {
			t.Errorf("%s: remediation %q lacks description", name, s.Remediation)
		}
		if rt.Fix != "" {
			fix, ok := fixByComponent(rt.Fix)
			if !ok {
				t.Errorf("%s: fix component %q is not in EcosystemFixes", name, rt.Fix)
				continue
			}
			if !strings.Contains(s.Remediation, fix.FixedVersion) {
				t.Errorf("%s: remediation %q does not mention fixed version %q", name, s.Remediation, fix.FixedVersion)
			}
			got, ok := FixForStore(s)
			if !ok || got != fix {
				t.Errorf("%s: FixForStore = %+v, %v; want %+v", name, got, ok, fix)
			}
		} else if _, ok := FixForStore(s); ok {
			t.Errorf("%s: FixForStore reported a fix for a runtime without one", name)
		}
	}
}

func TestIsExecutableHeader(t *testing.T) {
	tests := []struct {
		name string
		h    []byte
		want bool
	}{
		{"elf", elfHeader, true},
		{"pe", peHeader, true},
		{"pe-short", []byte("MZ"), true},
		{"macho64", machOHeader, true},
		{"macho32", []byte{0xce, 0xfa, 0xed, 0xfe}, true},
		{"macho64-be", []byte{0xfe, 0xed, 0xfa, 0xcf}, true},
		{"macho32-be", []byte{0xfe, 0xed, 0xfa, 0xce}, true},
		{"fat", []byte{0xca, 0xfe, 0xba, 0xbe}, true},
		{"empty", nil, false},
		{"short", []byte{0x7f, 'E'}, false},
		{"elf-truncated", []byte{0x7f, 'E', 'L'}, false},
		{"pem", pemHeader, false},
		{"der", []byte{0x30, 0x82, 0x05, 0x1a}, false},
		{"script", shHeader, false},
		{"text-m", []byte("Mozilla"), false},
	}
	for _, tt := range tests {
		if got := isExecutableHeader(tt.h); got != tt.want {
			t.Errorf("%s: isExecutableHeader = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsLibraryName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"libssl.so", true},
		{"libssl.so.3", true},
		{"libnode.so.115", true},
		{"libc.so.6.1", true},
		{"libfoo.dylib", true},
		{"foo.dll", true},
		{"FOO.DLL", true},
		{"foo.sock", false},
		{"foo.so.bar", false},
		{"foo.so.", false},
		{"cacert.pem", false},
		{"node", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isLibraryName(tt.name); got != tt.want {
			t.Errorf("isLibraryName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
