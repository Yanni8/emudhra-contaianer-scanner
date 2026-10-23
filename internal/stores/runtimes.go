package stores

import "strings"

// runtimeBinary describes an executable or shared object that embeds its own
// root store.
type runtimeBinary struct {
	// Runtime is the short name returned by KnownRuntimeBinary.
	Runtime     string
	Ecosystem   string
	Description string
	Consumers   []string
	// Fix is the EcosystemFixes component that fixes this runtime, if any.
	Fix string
	// Workaround is an optional way to stop using the embedded store.
	Workaround string
}

var (
	rtNode = runtimeBinary{
		Runtime:     "Node.js",
		Ecosystem:   ecoNode,
		Description: "Node.js: bundled Mozilla root store compiled into the binary, used by every Node program unless --use-openssl-ca",
		Consumers:   []string{"every Node.js program (https, tls) unless --use-openssl-ca is set", "npm, yarn, pnpm"},
		Fix:         fixNode,
		Workaround:  "NODE_OPTIONS=--use-openssl-ca switches Node.js to the system OpenSSL store.",
	}
	rtLibnode = runtimeBinary{
		Runtime:     "Node.js (libnode shared library)",
		Ecosystem:   ecoNode,
		Description: "Node.js shared library: bundled Mozilla root store compiled in, used by every program embedding Node unless --use-openssl-ca",
		Consumers:   []string{"Node.js (distribution builds link against libnode)", "programs embedding Node.js"},
		Fix:         fixNode,
		Workaround:  "NODE_OPTIONS=--use-openssl-ca switches Node.js to the system OpenSSL store.",
	}
	rtDeno = runtimeBinary{
		Runtime:     "Deno",
		Ecosystem:   ecoDeno,
		Description: "Deno: Rust webpki-roots trust anchors compiled in",
		Consumers:   []string{"Deno programs (fetch, Deno.connectTls, node:https)"},
		Fix:         fixDeno,
		Workaround:  "DENO_TLS_CA_STORE=system switches Deno to the operating system store.",
	}
	rtBun = runtimeBinary{
		Runtime:     "Bun",
		Ecosystem:   ecoBun,
		Description: "Bun: root store compiled into the binary (BoringSSL)",
		Consumers:   []string{"Bun programs (fetch, node:tls, node:https)"},
		Fix:         fixBun,
	}
	rtElectron = runtimeBinary{
		Runtime:     "Electron",
		Ecosystem:   ecoBrowser,
		Description: "Electron: Chrome Root Store compiled in",
		Consumers:   []string{"Electron applications (Chromium network stack and bundled Node.js)"},
		Fix:         fixElectron,
	}
	rtChromium = runtimeBinary{
		Runtime:     "Chromium",
		Ecosystem:   ecoBrowser,
		Description: "Chromium: Chrome Root Store compiled in",
		Consumers:   []string{"Chrome/Chromium/Edge/Brave browsers", "headless Chrome drivers (Puppeteer, Playwright, Selenium)"},
	}
	rtCEF = runtimeBinary{
		Runtime:     "Chromium Embedded Framework (libcef)",
		Ecosystem:   ecoBrowser,
		Description: "CEF: Chrome Root Store compiled in",
		Consumers:   []string{"applications embedding CEF"},
	}
	rtNW = runtimeBinary{
		Runtime:     "NW.js",
		Ecosystem:   ecoBrowser,
		Description: "NW.js: Chrome Root Store compiled in",
		Consumers:   []string{"NW.js applications"},
	}
	rtNSSCKBI = runtimeBinary{
		Runtime:     "NSS builtin roots (libnssckbi)",
		Ecosystem:   ecoBrowser,
		Description: "NSS built-in root module used by Firefox, Thunderbird and p11-kit",
		Consumers:   []string{"Firefox", "Thunderbird", "p11-kit (when libnssckbi is not replaced by p11-kit-trust)", "NSS applications (certutil, curl built with NSS)"},
		Fix:         fixNSS,
	}
	rtDart = runtimeBinary{
		Runtime:     "Dart",
		Ecosystem:   ecoDart,
		Description: "Dart runtime: BoringSSL root store compiled in",
		Consumers:   []string{"Dart and Flutter applications (dart:io HttpClient, SecurityContext.defaultContext)"},
	}
	rtFlutter = runtimeBinary{
		Runtime:     "Flutter (Dart runtime)",
		Ecosystem:   ecoDart,
		Description: "Dart runtime: BoringSSL root store compiled in",
		Consumers:   []string{"Flutter applications (dart:io HttpClient, SecurityContext.defaultContext)"},
	}
	rtUV = runtimeBinary{
		Runtime:     "uv",
		Ecosystem:   ecoPython,
		Description: "uv: webpki-roots compiled in",
		Consumers:   []string{"uv and uvx (package index and download TLS unless --native-tls / UV_NATIVE_TLS=1)"},
		Fix:         fixUV,
		Workaround:  "UV_NATIVE_TLS=1 switches uv to the platform trust store.",
	}
)

// runtimes maps normalised base names to runtime descriptions.
var runtimes = map[string]runtimeBinary{
	"node":                  rtNode,
	"nodejs":                rtNode,
	"libnode":               rtLibnode,
	"deno":                  rtDeno,
	"bun":                   rtBun,
	"electron":              rtElectron,
	"chrome":                rtChromium,
	"chromium":              rtChromium,
	"chromium-browser":      rtChromium,
	"google-chrome":         rtChromium,
	"msedge":                rtChromium,
	"microsoft-edge":        rtChromium,
	"brave":                 rtChromium,
	"brave-browser":         rtChromium,
	"headless_shell":        rtChromium,
	"chrome-headless-shell": rtChromium,
	"libcef":                rtCEF,
	"nw":                    rtNW,
	"libnssckbi":            rtNSSCKBI,
	"nssckbi":               rtNSSCKBI,
	"dart":                  rtDart,
	"flutter":               rtFlutter,
	"uv":                    rtUV,
	"uvx":                   rtUV,
}

// releaseChannels are suffixes distributions append to browser binaries.
var releaseChannels = []string{"-stable", "-beta", "-unstable", "-dev", "-canary", "-nightly"}

// runtimeInfo looks a base name up in the runtime table, tolerating version
// suffixes (node22, nodejs-18, electron25), release channels
// (google-chrome-stable) and shared-library decorations (libnode.so.115).
func runtimeInfo(base string) (runtimeBinary, bool) {
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	if rt, ok := runtimes[base]; ok {
		return rt, true
	}
	if stem, ok := libSuffix(base); ok {
		if rt, ok := runtimes[stem]; ok {
			return rt, true
		}
		rt, ok := runtimes[strings.TrimRight(stem, "0123456789.-_")]
		return rt, ok
	}
	for _, ch := range releaseChannels {
		if strings.HasSuffix(base, ch) {
			base = strings.TrimSuffix(base, ch)
			break
		}
	}
	if rt, ok := runtimes[base]; ok {
		return rt, true
	}
	stem := strings.TrimRight(base, "0123456789.-_")
	if stem == base || stem == "" {
		return runtimeBinary{}, false
	}
	if rt, ok := runtimes[stem]; ok {
		return rt, true
	}
	if strings.HasSuffix(stem, "v") {
		// node-v22.1.0 style names.
		if rt, ok := runtimes[strings.TrimRight(strings.TrimSuffix(stem, "v"), ".-_")]; ok {
			return rt, true
		}
	}
	return runtimeBinary{}, false
}

// knownRuntimeBinary implements KnownRuntimeBinary.
func knownRuntimeBinary(p string) (string, bool) {
	rt, ok := runtimeInfo(baseName(p))
	if !ok {
		return "", false
	}
	return rt.Runtime, true
}

// baseName returns the last path element, accepting both "/" and "\" separators.
func baseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// runtimeStore builds the Store for a known runtime binary.
func runtimeStore(rt runtimeBinary) Store {
	rem := rt.Description + "."
	if fix, ok := fixByComponent(rt.Fix); ok {
		rem += " Upgrade to " + fix.FixedVersion + " or later (" + fix.Reference + ")."
	} else {
		rem += " " + remEmbedded
	}
	if rt.Workaround != "" {
		rem += " " + rt.Workaround
	}
	return mkStore(ClassEmbeddedRuntime, rt.Runtime+" (embedded root store)", rt.Ecosystem, rt.Consumers, true, rem)
}

// isExecutableHeader recognises ELF, PE and Mach-O magic numbers in the first
// bytes of a file.
func isExecutableHeader(h []byte) bool {
	if len(h) >= 2 && h[0] == 'M' && h[1] == 'Z' {
		return true
	}
	if len(h) < 4 {
		return false
	}
	switch {
	case h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F':
		return true
	case h[0] == 0xcf && h[1] == 0xfa && h[2] == 0xed && h[3] == 0xfe, // Mach-O 64-bit
		h[0] == 0xce && h[1] == 0xfa && h[2] == 0xed && h[3] == 0xfe, // Mach-O 32-bit
		h[0] == 0xfe && h[1] == 0xed && h[2] == 0xfa && h[3] == 0xcf, // Mach-O 64-bit, big-endian
		h[0] == 0xfe && h[1] == 0xed && h[2] == 0xfa && h[3] == 0xce, // Mach-O 32-bit, big-endian
		h[0] == 0xca && h[1] == 0xfe && h[2] == 0xba && h[3] == 0xbe: // Mach-O universal (fat)
		return true
	}
	return false
}

// isLibraryName reports whether base looks like a shared library file name.
func isLibraryName(base string) bool {
	_, ok := libSuffix(strings.ToLower(base))
	return ok
}

// libSuffix strips a shared-library suffix (.so, .so.N.N..., .dylib, .dll)
// from a lower-cased base name and returns the stem.
func libSuffix(base string) (stem string, ok bool) {
	if strings.HasSuffix(base, ".dylib") {
		return strings.TrimSuffix(base, ".dylib"), true
	}
	if strings.HasSuffix(base, ".dll") {
		return strings.TrimSuffix(base, ".dll"), true
	}
	for i := strings.Index(base, ".so"); i >= 0; {
		if isVersionTail(base[i+3:]) {
			return base[:i], true
		}
		j := strings.Index(base[i+1:], ".so")
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return "", false
}

// isVersionTail accepts "" and sequences of ".N" components such as ".6.1".
func isVersionTail(rest string) bool {
	if rest == "" {
		return true
	}
	if rest[0] != '.' {
		return false
	}
	digits := 0
	for i := 1; i < len(rest); i++ {
		switch {
		case isDigit(rest[i]):
			digits++
		case rest[i] == '.' && digits > 0:
			digits = 0
		default:
			return false
		}
	}
	return digits > 0
}
