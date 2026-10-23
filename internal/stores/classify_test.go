package stores

import (
	"encoding/pem"
	"path"
	"strings"
	"testing"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
)

var (
	elfHeader   = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	peHeader    = []byte("MZ\x90\x00\x03\x00")
	machOHeader = []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01}
	shHeader    = []byte("#!/bin/sh\nexec /usr/lib/node/bin/node \"$@\"\n")
	pemHeader   = []byte("-----BEGIN CERTIFICATE-----\nMIIB")
)

func TestClassify(t *testing.T) {
	type want struct {
		class     Class
		ecosystem string
		trusted   bool
		name      string // substring of Store.Name, "" to skip
	}
	tests := []struct {
		path   string
		header []byte
		want   want
	}{
		// System bundles.
		{"/etc/ssl/certs/ca-certificates.crt", pemHeader, want{ClassSystemBundle, "system", true, "Debian/Ubuntu/Alpine"}},
		{"/etc/ssl/cert.pem", nil, want{ClassSystemBundle, "system", true, "cert.pem"}},
		{"/etc/ssl/ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "SUSE"}},
		{"/etc/ssl/certs/ca-bundle.crt", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/etc/ssl1.1/cert.pem", nil, want{ClassSystemBundle, "system", true, "Alpine"}},
		{"/etc/pki/tls/certs/ca-bundle.crt", nil, want{ClassSystemBundle, "system", true, "RHEL/Fedora"}},
		{"/etc/pki/tls/certs/ca-bundle.trust.crt", nil, want{ClassSystemBundle, "system", true, "TRUSTED CERTIFICATE"}},
		{"/etc/pki/tls/cert.pem", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/etc/pki/tls/cacert.pem", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "TLS"}},
		{"/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "S/MIME"}},
		{"/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "code-signing"}},
		{"/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", nil, want{ClassSystemBundle, "system", true, "trust"}},
		{"/etc/pki/ca-trust/extracted/edk2/cacerts.bin", nil, want{ClassSystemBundle, "system", true, "EDK2"}},
		{"/etc/pki/ca-trust/extracted/pem/directory-hash/2e5ac55d.0", nil, want{ClassSystemBundle, "system", true, "hashed"}},
		{"/etc/ca-certificates/extracted/tls-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "Arch"}},
		{"/etc/ca-certificates/extracted/cadir/2e5ac55d.0", nil, want{ClassSystemBundle, "system", true, "Arch"}},
		{"/usr/share/ssl/certs/ca-bundle.crt", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/usr/local/share/certs/ca-root-nss.crt", nil, want{ClassSystemBundle, "system", true, "FreeBSD"}},
		{"/usr/local/etc/ssl/cert.pem", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/usr/lib/ssl/cert.pem", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/usr/lib/ssl/certs/ca-certificates.crt", nil, want{ClassSystemBundle, "system", true, ""}},
		{"/etc/openssl/certs/ca-certificates.crt", nil, want{ClassSystemBundle, "system", true, "NetBSD"}},
		{"/nix/store/abc123-nss-cacert-3.101/etc/ssl/certs/ca-bundle.crt", nil, want{ClassSystemBundle, "system", true, "Nix"}},
		{"/etc/ca-certificates/extracted/email-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "S/MIME"}},
		{"/etc/ca-certificates/extracted/objsign-ca-bundle.pem", nil, want{ClassSystemBundle, "system", true, "code-signing"}},

		// SUSE: update-ca-certificates writes every consumer store under
		// /var/lib/ca-certificates (/etc/ssl/certs and /etc/ssl/ca-bundle.pem
		// are symlinks into it).
		{"/var/lib/ca-certificates/ca-bundle.pem", pemHeader, want{ClassSystemBundle, "system", true, "SUSE"}},
		{"/var/lib/ca-certificates/pem/emSign_ECC_Root_CA_-_G3.pem", pemHeader, want{ClassSystemBundle, "system", true, "SUSE"}},
		{"/var/lib/ca-certificates/pem/14bc7599.0", nil, want{ClassSystemBundle, "system", true, "/etc/ssl/certs"}},
		{"/var/lib/ca-certificates/openssl/emSign_ECC_Root_CA_-_G3.pem", nil, want{ClassSystemBundle, "system", true, "SUSE"}},

		// Homebrew (Linuxbrew and macOS prefixes).
		{"/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem", pemHeader, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/home/linuxbrew/.linuxbrew/etc/openssl@3/cert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/home/linuxbrew/.linuxbrew/Cellar/ca-certificates/2025-09-09/share/ca-certificates/cacert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/opt/homebrew/etc/ca-certificates/cert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/opt/homebrew/etc/openssl@3/cert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/opt/homebrew/Cellar/ca-certificates/2026-10-21/share/ca-certificates/cacert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/usr/local/etc/ca-certificates/cert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/usr/local/etc/openssl@3/cert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},
		{"/usr/local/Cellar/ca-certificates/2026-10-21/share/ca-certificates/cacert.pem", nil, want{ClassAppBundle, "homebrew", true, "Homebrew"}},

		// Android.
		{"/system/etc/security/cacerts/3513523f.0", nil, want{ClassSystemAnchorDir, "system", true, "Android"}},
		{"/apex/com.android.conscrypt/cacerts/3513523f.0", nil, want{ClassSystemAnchorDir, "system", true, "Android"}},

		// Source directories.
		{"/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", pemHeader, want{ClassSystemSource, "system", false, "Debian/Ubuntu/Alpine"}},
		{"/usr/share/ca-certificates/trust-source/mozilla.trust.p11-kit", nil, want{ClassSystemSource, "system", false, "Arch"}},
		{"/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", nil, want{ClassSystemSource, "system", false, "RHEL/Fedora"}},
		{"/usr/share/pki/ca-trust-legacy/ca-bundle.legacy.default.crt", nil, want{ClassSystemSource, "system", false, "legacy"}},
		{"/usr/share/pki/trust/mozilla.trust.p11-kit", nil, want{ClassSystemSource, "system", false, "SUSE"}},
		{"/usr/src/nss/lib/ckfw/builtins/certdata.txt", nil, want{ClassSystemSource, "browser", false, "certdata"}},

		// Anchor directories.
		{"/usr/local/share/ca-certificates/corp/root.crt", nil, want{ClassSystemAnchorDir, "system", true, "local CA anchors"}},
		{"/etc/pki/ca-trust/source/anchors/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "RHEL/Fedora"}},
		{"/etc/pki/ca-trust/source/corp.p11-kit", nil, want{ClassSystemAnchorDir, "system", true, "p11-kit"}},
		{"/etc/pki/ca-trust/source/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "p11-kit"}},
		{"/usr/share/pki/ca-trust-source/anchors/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "package-provided"}},
		{"/etc/pki/trust/anchors/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "SUSE"}},
		{"/usr/share/pki/trust/anchors/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "SUSE"}},
		{"/etc/ca-certificates/trust-source/anchors/corp.crt", nil, want{ClassSystemAnchorDir, "system", true, "Arch"}},
		{"/usr/share/ca-certificates/trust-source/anchors/corp.crt", nil, want{ClassSystemAnchorDir, "system", true, "Arch"}},
		{"/etc/ssl/certs/DST_Root_CA_X3.pem", nil, want{ClassSystemAnchorDir, "system", true, "/etc/ssl/certs"}},
		{"/etc/ssl/certs/2e5ac55d.0", nil, want{ClassSystemAnchorDir, "system", true, "/etc/ssl/certs"}},
		{"/etc/ssl/certs/ca-cert-emSign_ECC_Root_CA_-_G3.pem", nil, want{ClassSystemAnchorDir, "system", true, "/etc/ssl/certs"}},
		{"/etc/openssl/certs/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, "NetBSD"}},
		{"/usr/local/etc/ssl/certs/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, ""}},
		{"/etc/pki/tls/certs/localhost.crt", nil, want{ClassSystemAnchorDir, "system", true, "/etc/pki/tls/certs"}},
		{"/usr/lib/ssl/certs/corp.pem", nil, want{ClassSystemAnchorDir, "system", true, ""}},

		// Blocklists.
		{"/etc/pki/ca-trust/source/blocklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "blocklist"}},
		{"/etc/pki/ca-trust/source/blacklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "legacy"}},
		{"/usr/share/pki/ca-trust-source/blocklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, ""}},
		{"/usr/share/pki/ca-trust-source/blacklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, ""}},
		{"/etc/pki/trust/blocklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "SUSE"}},
		{"/etc/pki/trust/blacklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "SUSE"}},
		{"/etc/ca-certificates/trust-source/blocklist/emsign.crt", nil, want{ClassSystemBlocklist, "system", false, "Arch"}},
		{"/etc/ca-certificates/trust-source/blacklist/emsign.crt", nil, want{ClassSystemBlocklist, "system", false, "Arch"}},
		{"/usr/share/ca-certificates/trust-source/blocklist/emsign.crt", nil, want{ClassSystemBlocklist, "system", false, "Arch"}},
		{"/usr/share/certs/untrusted/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "FreeBSD"}},
		{"/etc/ssl/untrusted/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "FreeBSD"}},
		{"/etc/ssl/blacklist/emsign.pem", nil, want{ClassSystemBlocklist, "system", false, "FreeBSD"}},

		// Java keystores.
		{"/usr/lib/jvm/java-17-openjdk-amd64/lib/security/cacerts", nil, want{ClassJavaKeystore, "java", true, "cacerts"}},
		{"/opt/java/openjdk/lib/security/jssecacerts", nil, want{ClassJavaKeystore, "java", true, "jssecacerts"}},
		// Java cacerts regenerated by the distribution from its trust store.
		{"/etc/ssl/certs/java/cacerts", nil, want{ClassJavaKeystore, "java", true, "ca-certificates-java"}},
		{"/etc/pki/java/cacerts", nil, want{ClassJavaKeystore, "java", true, "update-ca-trust"}},
		{"/etc/pki/ca-trust/extracted/java/cacerts", nil, want{ClassJavaKeystore, "java", true, "update-ca-trust"}},
		{"/etc/ca-certificates/extracted/java-cacerts", nil, want{ClassJavaKeystore, "java", true, "Arch"}},
		{"/etc/ca-certificates/extracted/java/cacerts", nil, want{ClassJavaKeystore, "java", true, "Arch"}},
		{"/var/lib/ca-certificates/java-cacerts", nil, want{ClassJavaKeystore, "java", true, "SUSE"}},
		{"/cacerts", nil, want{ClassJavaKeystore, "java", true, "cacerts"}},
		{"/opt/app/app.truststore", nil, want{ClassJavaKeystore, "java", true, "truststore"}},
		{"/opt/app/truststore.jks", nil, want{ClassJavaKeystore, "java", true, "truststore"}},
		{"/opt/app/my-TrustStore.p12", nil, want{ClassJavaKeystore, "java", true, "truststore"}},
		{"/opt/app/cacerts.p12", nil, want{ClassJavaKeystore, "java", true, "truststore"}},
		{"/opt/app/keystore.jks", nil, want{ClassJavaKeystore, "java", false, "JKS"}},
		{"/opt/app/app.keystore", nil, want{ClassJavaKeystore, "java", false, "JKS"}},
		{"/opt/app/APP.JKS", nil, want{ClassJavaKeystore, "java", false, "JKS"}},
		{"/opt/app/client.p12", nil, want{ClassJavaKeystore, "other", false, "PKCS#12"}},
		{"/opt/app/cert.pfx", nil, want{ClassJavaKeystore, "other", false, "PKCS#12"}},
		{"/opt/app/cert.pkcs12", nil, want{ClassJavaKeystore, "other", false, "PKCS#12"}},

		// NSS databases.
		// NSS trust flags are per certificate and unparsed: not trusted by default.
		{"/etc/pki/nssdb/cert9.db", nil, want{ClassNSSDB, "browser", false, "cert9"}},
		{"/root/.mozilla/firefox/abc.default/cert8.db", nil, want{ClassNSSDB, "browser", false, "cert8"}},
		{"/etc/pki/nssdb/key4.db", nil, want{ClassLooseFile, "other", false, ""}},

		// Python.
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", pemHeader, want{ClassAppBundle, "python", true, "certifi"}},
		{"/usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", nil, want{ClassAppBundle, "python", true, "pip"}},
		// pip's vendored copy stays pip's inside a cloud SDK's bundled Python.
		{"/usr/lib/google-cloud-sdk/platform/bundledpythonunix/lib/python3.14/site-packages/pip/_vendor/certifi/cacert.pem", nil, want{ClassAppBundle, "python", true, "pip"}},
		{"/usr/local/lib/python3.12/site-packages/botocore/cacert.pem", nil, want{ClassAppBundle, "python", true, "botocore"}},
		{"/usr/lib/python3/dist-packages/httplib2/cacerts.txt", nil, want{ClassAppBundle, "python", true, "httplib2"}},
		{"/usr/local/lib/python3.12/site-packages/grpc/_cython/_credentials/roots.pem", nil, want{ClassAppBundle, "python", true, "gRPC"}},
		{"/usr/lib/python2.7/site-packages/requests/cacert.pem", nil, want{ClassAppBundle, "python", true, "requests"}},
		{"/opt/conda/ssl/cacert.pem", nil, want{ClassAppBundle, "python", true, "Conda"}},
		{"/opt/conda/ssl/cert.pem", nil, want{ClassAppBundle, "python", true, "Conda"}},
		{"/root/miniconda3/envs/ml/ssl/cacert.pem", nil, want{ClassAppBundle, "python", true, "Conda"}},
		{"/root/anaconda3/ssl/cert.pem", nil, want{ClassAppBundle, "python", true, "Conda"}},
		{"/opt/micromamba/ssl/cacert.pem", nil, want{ClassAppBundle, "python", true, "micromamba"}},
		{"/opt/miniforge3/ssl/cacert.pem", nil, want{ClassAppBundle, "python", true, "miniforge"}},

		// Cloud CLIs win over the Python rules.
		{"/usr/local/aws-cli/v2/2.15.0/dist/awscli/botocore/cacert.pem", nil, want{ClassAppBundle, "cloud-cli", true, "AWS CLI"}},
		{"/usr/lib/google-cloud-sdk/lib/third_party/certifi/cacert.pem", nil, want{ClassAppBundle, "cloud-cli", true, "Google Cloud"}},
		{"/opt/azure-cli/lib/python3.12/site-packages/certifi/cacert.pem", nil, want{ClassAppBundle, "cloud-cli", true, "Azure"}},
		{"/usr/lib/google-cloud-sdk/platform/bq/third_party/certifi/cacert.pem", nil, want{ClassAppBundle, "cloud-cli", true, "Google Cloud"}},
		{"/usr/lib/google-cloud-sdk/lib/third_party/botocore/cacert.pem", nil, want{ClassAppBundle, "cloud-cli", true, "Google Cloud"}},

		// Perl, PHP, Ruby, Erlang.
		{"/usr/share/perl5/Mozilla/CA/cacert.pem", nil, want{ClassAppBundle, "perl", true, "Mozilla::CA"}},
		{"/usr/local/lib/perl5/site_perl/5.36/Mozilla/CA/cacert.pem", nil, want{ClassAppBundle, "perl", true, "Mozilla::CA"}},
		{"/app/vendor/composer/ca-bundle/res/cacert.pem", nil, want{ClassAppBundle, "php", true, "composer"}},
		{"/usr/local/lib/ruby/3.3.0/rubygems/ssl_certs/rubygems.org/GlobalSignRootCA.pem", nil, want{ClassAppBundle, "ruby", true, "RubyGems"}},
		{"/usr/local/bundle/gems/aws-sdk-core-3.200.0/ca-bundle.crt", nil, want{ClassAppBundle, "ruby", true, "aws-sdk-core"}},
		{"/usr/local/bundle/gems/foo-1.0/lib/cacert.pem", nil, want{ClassAppBundle, "ruby", true, "gem"}},
		{"/app/_build/prod/lib/certifi/priv/cacerts.pem", nil, want{ClassAppBundle, "erlang", true, "certifi"}},
		{"/app/deps/castore/priv/cacerts.pem", nil, want{ClassAppBundle, "erlang", true, "CAStore"}},
		// Mix/OTP releases put every application in lib/<app>-<version>/.
		{"/app/lib/certifi-2.14.0/priv/cacerts.pem", nil, want{ClassAppBundle, "erlang", true, "certifi"}},
		{"/app/lib/castore-1.0.9/priv/cacerts.pem", nil, want{ClassAppBundle, "erlang", true, "CAStore"}},
		{"/app/lib/certifier-1.0/priv/cacerts.pem", nil, want{ClassAppBundle, "other", true, "cacerts.pem"}},

		// Node packages and the Go module cache are not trusted by default.
		{"/app/node_modules/ssl-root-cas/ssl-root-cas.pem", nil, want{ClassAppBundle, "node", false, "Node.js package"}},
		{"/app/node_modules/foo/test/fixtures/ca.crt", nil, want{ClassAppBundle, "node", false, "Node.js package"}},
		{"/root/go/pkg/mod/golang.org/x/crypto@v0.1.0/testdata/x.pem", nil, want{ClassAppBundle, "go", false, "Go module cache"}},

		// Generic application bundles.
		{"/opt/app/curl-ca-bundle.crt", nil, want{ClassAppBundle, "other", true, "curl"}},
		{"/usr/local/share/curl/cacert.pem", nil, want{ClassAppBundle, "other", true, "curl"}},
		{"/opt/app/certs/cacert.pem", nil, want{ClassAppBundle, "other", true, "cacert.pem"}},
		{"/opt/app/ssl/cacert.pem", nil, want{ClassAppBundle, "other", true, "cacert.pem"}},
		{"/opt/app/cacerts.pem", nil, want{ClassAppBundle, "other", true, "cacerts.pem"}},
		{"/opt/app/ca-bundle.crt", nil, want{ClassAppBundle, "other", true, "ca-bundle.crt"}},
		{"/opt/app/ca-bundle.pem", nil, want{ClassAppBundle, "other", true, "ca-bundle.pem"}},
		{"/opt/app/ca-certificates.crt", nil, want{ClassAppBundle, "other", true, "ca-certificates.crt"}},
		{"/opt/app/tls-ca-bundle.pem", nil, want{ClassAppBundle, "other", true, "tls-ca-bundle.pem"}},
		{"/opt/app/roots.pem", nil, want{ClassAppBundle, "other", true, "roots.pem"}},
		{"/opt/app/ca-roots.pem", nil, want{ClassAppBundle, "other", true, "ca-roots.pem"}},
		{"/opt/app/trust.pem", nil, want{ClassAppBundle, "other", true, "trust.pem"}},
		{"/opt/app/truststore.pem", nil, want{ClassAppBundle, "other", true, "truststore.pem"}},

		// Runtimes that embed their root store.
		{"/usr/local/bin/node", elfHeader, want{ClassEmbeddedRuntime, "node", true, "Node.js"}},
		{"/usr/local/bin/node", nil, want{ClassEmbeddedRuntime, "node", true, "Node.js"}},
		{"/usr/bin/nodejs", elfHeader, want{ClassEmbeddedRuntime, "node", true, "Node.js"}},
		{"/usr/lib/x86_64-linux-gnu/libnode.so.115", nil, want{ClassEmbeddedRuntime, "node", true, "libnode"}},
		{"/usr/bin/deno", elfHeader, want{ClassEmbeddedRuntime, "deno", true, "Deno"}},
		{"/usr/local/bin/bun", elfHeader, want{ClassEmbeddedRuntime, "bun", true, "Bun"}},
		{"/opt/app/electron", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "Electron"}},
		{"/opt/google/chrome/chrome", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "Chromium"}},
		{"/usr/bin/google-chrome-stable", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "Chromium"}},
		{"/usr/lib/chromium/chromium", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "Chromium"}},
		{"/opt/microsoft/msedge/msedge", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "Chromium"}},
		{"/opt/cef/libcef.so", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "libcef"}},
		{"/opt/nwjs/nw", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "NW.js"}},
		{"/usr/lib/x86_64-linux-gnu/nss/libnssckbi.so", elfHeader, want{ClassEmbeddedRuntime, "browser", true, "libnssckbi"}},
		{"/usr/lib/firefox/libnssckbi.so", nil, want{ClassEmbeddedRuntime, "browser", true, "libnssckbi"}},
		{"/usr/lib/dart/bin/dart", elfHeader, want{ClassEmbeddedRuntime, "dart", true, "Dart"}},
		{"/usr/local/bin/uv", elfHeader, want{ClassEmbeddedRuntime, "python", true, "uv"}},

		// Other executables and libraries.
		{"/usr/bin/python3.12", elfHeader, want{ClassEmbeddedBinary, "other", false, "Executable"}},
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", nil, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/opt/app/libfoo.dylib", nil, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/opt/app/foo.dll", nil, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/opt/app/app.exe", peHeader, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/opt/app/macbin", machOHeader, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/app/node_modules/foo/build/Release/foo.node", elfHeader, want{ClassEmbeddedBinary, "other", false, ""}},
		{"/usr/local/bin/node", shHeader, want{ClassLooseFile, "other", false, ""}},

		// Loose files.
		{"/opt/app/certs/corp-root.pem", pemHeader, want{ClassLooseFile, "other", false, "outside"}},
		{"/etc/ssl/openssl.cnf", nil, want{ClassLooseFile, "other", false, ""}},
		{"/etc/pki/ca-trust/source/README", nil, want{ClassLooseFile, "other", false, ""}},
		{"/etc/ssl/certs/custom/corp.pem", nil, want{ClassLooseFile, "other", false, ""}},
		{"", nil, want{ClassLooseFile, "other", false, ""}},
		{"/", nil, want{ClassLooseFile, "other", false, ""}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := Classify(tt.path, tt.header)
			if got.Class != tt.want.class {
				t.Errorf("class = %q, want %q (store %+v)", got.Class, tt.want.class, got)
			}
			if got.Ecosystem != tt.want.ecosystem {
				t.Errorf("ecosystem = %q, want %q", got.Ecosystem, tt.want.ecosystem)
			}
			if got.TrustedByDefault != tt.want.trusted {
				t.Errorf("trusted = %v, want %v", got.TrustedByDefault, tt.want.trusted)
			}
			if tt.want.name != "" && !strings.Contains(got.Name, tt.want.name) {
				t.Errorf("name = %q, want it to contain %q", got.Name, tt.want.name)
			}
			if got.Name == "" || got.Remediation == "" || len(got.Consumers) == 0 {
				t.Errorf("incomplete store: %+v", got)
			}
		})
	}
}

func TestClassifyPathForms(t *testing.T) {
	want := Classify("/etc/ssl/certs/ca-certificates.crt", nil)
	for _, p := range []string{
		"./etc/ssl/certs/ca-certificates.crt",
		"etc/ssl/certs/ca-certificates.crt",
		"//etc//ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/../certs/ca-certificates.crt",
		"/etc/ssl/./certs/ca-certificates.crt",
		"  /etc/ssl/certs/ca-certificates.crt",
		"/ETC/SSL/CERTS/CA-CERTIFICATES.CRT",
	} {
		got := Classify(p, nil)
		if got.Class != want.Class || got.Name != want.Name {
			t.Errorf("Classify(%q) = %s %q, want %s %q", p, got.Class, got.Name, want.Class, want.Name)
		}
	}
}

func TestClassifyUsesBlocklistCertificateHeaders(t *testing.T) {
	root := blocklist.Default().ByID("emsign-ecc-root-ca-g3").Certificate
	if root == nil {
		t.Fatal("blocklist has no certificate for emsign-ecc-root-ca-g3")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	name := DebianSourceName(root.Subject.CommonName)
	if name != "mozilla/emSign_ECC_Root_CA_-_G3.crt" {
		t.Fatalf("DebianSourceName = %q", name)
	}
	tests := []struct {
		path   string
		header []byte
		want   Class
	}{
		{debianSourcePrefix + name, pemBytes[:64], ClassSystemSource},
		{"/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem", pemBytes[:64], ClassSystemAnchorDir},
		{"/usr/local/share/ca-certificates/emsign.crt", pemBytes, ClassSystemAnchorDir},
		{"/opt/app/emsign.der", root.Raw[:32], ClassLooseFile},
		// A DER certificate is not an executable, so the runtime name alone
		// does not make it an embedded store.
		{"/usr/local/bin/node", root.Raw[:32], ClassLooseFile},
	}
	for _, tt := range tests {
		if got := Classify(tt.path, tt.header); got.Class != tt.want {
			t.Errorf("Classify(%q, der/pem header) = %s, want %s", tt.path, got.Class, tt.want)
		}
	}
}

func TestClassifyReturnsIndependentCopies(t *testing.T) {
	a := Classify("/etc/ssl/certs/ca-certificates.crt", nil)
	a.Consumers[0] = "mutated"
	b := Classify("/etc/ssl/certs/ca-certificates.crt", nil)
	if b.Consumers[0] == "mutated" {
		t.Fatal("Classify shares its consumer slice with the catalogue")
	}
}

func TestCatalogueIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range catalogue {
		if seen[r.pattern] {
			t.Errorf("duplicate pattern %q", r.pattern)
		}
		seen[r.pattern] = true
		if !strings.HasPrefix(r.pattern, "/") && !strings.HasPrefix(r.pattern, "**/") {
			t.Errorf("pattern %q is neither absolute nor **-anchored", r.pattern)
		}
		for _, seg := range r.segs {
			if seg.kind == segAny {
				continue
			}
			if _, err := path.Match(seg.text, "x"); err != nil {
				t.Errorf("pattern %q: bad segment %q: %v", r.pattern, seg.text, err)
			}
			if seg.kind == segLiteral && strings.ContainsAny(seg.text, "*?[") {
				t.Errorf("pattern %q: segment %q wrongly compiled as literal", r.pattern, seg.text)
			}
		}
		s := r.store
		if s.Class == "" || s.Name == "" || s.Ecosystem == "" || s.Remediation == "" || len(s.Consumers) == 0 {
			t.Errorf("pattern %q: incomplete store %+v", r.pattern, s)
		}
		switch s.Class {
		case ClassSystemBundle, ClassSystemAnchorDir:
			if !s.TrustedByDefault {
				t.Errorf("pattern %q: %s must be trusted by default", r.pattern, s.Class)
			}
		case ClassSystemSource, ClassSystemBlocklist, ClassNSSDB:
			if s.TrustedByDefault {
				t.Errorf("pattern %q: %s must not be trusted by default", r.pattern, s.Class)
			}
		}
		if s.SystemGenerated && s.Class != ClassSystemBundle && s.Class != ClassJavaKeystore {
			t.Errorf("pattern %q: SystemGenerated on a %s store", r.pattern, s.Class)
		}
		switch s.LimitedTo {
		case "":
		case PurposeEmailProtection, PurposeCodeSigning:
			if s.Class != ClassSystemBundle || !s.SystemGenerated {
				t.Errorf("pattern %q: LimitedTo %q on a %s store", r.pattern, s.LimitedTo, s.Class)
			}
		default:
			t.Errorf("pattern %q: unknown LimitedTo %q", r.pattern, s.LimitedTo)
		}
		if s.Class == ClassSystemBundle || s.Class == ClassSystemSource {
			if strings.Contains(s.Remediation, "apt-get") || strings.Contains(s.Remediation, "apk ") || strings.Contains(s.Remediation, "dnf ") {
				t.Errorf("pattern %q: system remediation hard-codes a package-manager command: %q", r.pattern, s.Remediation)
			}
			if n := strings.Count(strings.TrimSuffix(s.Remediation, "."), ". "); n != 0 {
				t.Errorf("pattern %q: system remediation must be one sentence: %q", r.pattern, s.Remediation)
			}
		}
	}
	// Every blocklist rule is part of the catalogue and classified as such.
	for _, r := range blocklistRules {
		if !seen[r.pattern] || r.store.Class != ClassSystemBlocklist {
			t.Errorf("blocklist rule %q not in catalogue as a blocklist", r.pattern)
		}
	}
}

func TestIsBlocklistPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/pki/ca-trust/source/blocklist/emsign.pem", true},
		{"etc/pki/ca-trust/source/blocklist/emsign.pem", true},
		{"./etc/pki/ca-trust/source/blacklist/sub/emsign.pem", true},
		{"/usr/share/pki/ca-trust-source/blocklist/emsign.pem", true},
		{"/usr/share/pki/ca-trust-source/blacklist/emsign.pem", true},
		{"/etc/pki/trust/blocklist/emsign.pem", true},
		{"/etc/pki/trust/blacklist/emsign.pem", true},
		{"/etc/ca-certificates/trust-source/blocklist/emsign.crt", true},
		{"/etc/ca-certificates/trust-source/blacklist/emsign.crt", true},
		{"/usr/share/ca-certificates/trust-source/blocklist/emsign.crt", true},
		{"/usr/share/certs/untrusted/emsign.pem", true},
		{"/etc/ssl/untrusted/emsign.pem", true},
		{"/etc/ssl/blacklist/emsign.pem", true},
		{"/etc/pki/ca-trust/source/anchors/corp.pem", false},
		{"/etc/pki/ca-trust/source/blocklist", true}, // the directory itself
		{"/etc/pki/ca-trust/source/blocklist.pem", false},
		{"/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", false},
		{"/etc/ssl/certs/ca-certificates.crt", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsBlocklistPath(tt.path); got != tt.want {
			t.Errorf("IsBlocklistPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestMatchSegments(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/a/b/c", "/a/b/c", true},
		{"/a/b/c", "/a/b", false},
		{"/a/b", "/a/b/c", false},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/**", "/a/b/c", true},
		{"/a/**", "/a", true},
		{"/a/**", "/b/a", false},
		{"**/c", "/a/b/c", true},
		{"**/c", "/c", true},
		{"**/c", "/a/b/c/d", false},
		{"**/b/**/d", "/a/b/c/d", true},
		{"**/b/**/d", "/a/b/d", true},
		{"**/b/**/d", "/a/d", false},
		{"**/*.jks", "/x/y/z.jks", true},
		{"**/*.jks", "/x/y/z.jksx", false},
		{"**/*conda*/**/ssl/cert.pem", "/opt/miniconda3/ssl/cert.pem", true},
		{"**/*conda*/**/ssl/cert.pem", "/opt/app/ssl/cert.pem", false},
		{"/", "/", true},
		{"**", "/anything/at/all", true},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.pattern, tt.path); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestCompileSegment(t *testing.T) {
	tests := []struct {
		pattern string
		kind    segKind
		matches []string
		misses  []string
	}{
		{"cacert.pem", segLiteral, []string{"cacert.pem"}, []string{"cacert.pemx", "xcacert.pem", "CACERT.PEM"}},
		{"**", segAny, []string{"anything", ""}, nil},
		{"*.jks", segSuffix, []string{"a.jks", ".jks"}, []string{"a.jksx", "ajks"}},
		{"aws-sdk-core-*", segPrefix, []string{"aws-sdk-core-3.1", "aws-sdk-core-"}, []string{"aws-sdk-core", "x-aws-sdk-core-1"}},
		{"*conda*", segContains, []string{"conda", "miniconda3", "anaconda", "xcondax"}, []string{"mamba", "cond"}},
		{"*", segContains, []string{"x", "anything"}, nil},
		{"*truststore*.jks", segGlob, []string{"truststore.jks", "my-truststore-1.jks"}, []string{"truststore.jksx", "keystore.jks", "truststore"}},
		{"ca-cert-?.pem", segGlob, []string{"ca-cert-1.pem"}, []string{"ca-cert-12.pem", "cb-cert-1.pem"}},
	}
	for _, tt := range tests {
		seg := compileSegment(tt.pattern)
		if seg.kind != tt.kind {
			t.Errorf("compileSegment(%q).kind = %d, want %d", tt.pattern, seg.kind, tt.kind)
		}
		for _, name := range tt.matches {
			if !seg.match(name) {
				t.Errorf("%q should match %q", tt.pattern, name)
			}
		}
		for _, name := range tt.misses {
			if seg.match(name) {
				t.Errorf("%q should not match %q", tt.pattern, name)
			}
		}
	}
}

func BenchmarkClassify(b *testing.B) {
	paths := []string{
		"/usr/lib/python3/dist-packages/certifi/cacert.pem",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/share/doc/foo/README.gz",
		"/etc/ssl/certs/ca-certificates.crt",
		"/opt/app/node_modules/foo/lib/index.js",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Classify(paths[i%len(paths)], nil)
	}
}

func TestClassifyStoreFlags(t *testing.T) {
	tests := []struct {
		path      string
		generated bool
		limitedTo string
		javaFix   bool // FixForStore yields the Java/OpenJDK fix
	}{
		{"/etc/ssl/certs/ca-certificates.crt", true, "", false},
		{"/etc/ssl1.1/cert.pem", true, "", false},
		{"/etc/ssl/cert.pem", false, "", false},
		{"/etc/ssl/ca-bundle.pem", true, "", false},
		{"/etc/pki/tls/certs/ca-bundle.crt", true, "", false},
		{"/etc/pki/tls/certs/ca-bundle.trust.crt", true, "", false},
		{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", true, "", false},
		{"/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem", true, PurposeEmailProtection, false},
		{"/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem", true, PurposeCodeSigning, false},
		{"/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", true, "", false},
		{"/etc/pki/ca-trust/extracted/edk2/cacerts.bin", true, "", false},
		{"/etc/pki/ca-trust/extracted/pem/directory-hash/2e5ac55d.0", true, "", false},
		{"/etc/ca-certificates/extracted/tls-ca-bundle.pem", true, "", false},
		{"/etc/ca-certificates/extracted/email-ca-bundle.pem", true, PurposeEmailProtection, false},
		{"/etc/ca-certificates/extracted/objsign-ca-bundle.pem", true, PurposeCodeSigning, false},
		{"/etc/ca-certificates/extracted/cadir/2e5ac55d.0", true, "", false},
		{"/var/lib/ca-certificates/ca-bundle.pem", true, "", false},
		{"/var/lib/ca-certificates/pem/x.pem", true, "", false},
		{"/var/lib/ca-certificates/openssl/x.pem", true, "", false},
		// Java cacerts regenerated from the system store: no JDK fix.
		{"/etc/pki/ca-trust/extracted/java/cacerts", true, "", false},
		{"/etc/pki/java/cacerts", true, "", false},
		{"/etc/ca-certificates/extracted/java-cacerts", true, "", false},
		{"/etc/ca-certificates/extracted/java/cacerts", true, "", false},
		{"/var/lib/ca-certificates/java-cacerts", true, "", false},
		{"/etc/ssl/certs/java/cacerts", true, "", false},
		// The JDK's own cacerts is fixed by a JDK upgrade.
		{"/opt/java/openjdk/lib/security/cacerts", false, "", true},
		{"/usr/lib/jvm/java-17-openjdk-amd64/lib/security/cacerts", false, "", true},
		// jssecacerts is user-supplied: a JDK upgrade does not replace it.
		{"/opt/app/jssecacerts", false, "", false},
		// Not generated.
		{"/usr/share/ca-certificates/mozilla/x.crt", false, "", false},
		{"/usr/local/share/ca-certificates/x.crt", false, "", false},
		{"/etc/ssl/certs/corp.pem", false, "", false},
		{"/etc/pki/ca-trust/source/anchors/x.pem", false, "", false},
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", false, "", false},
		{"/nix/store/abc-cacert/etc/ssl/certs/ca-bundle.crt", false, "", false},
		{"/opt/app/truststore.jks", false, "", false},
	}
	for _, tt := range tests {
		s := Classify(tt.path, nil)
		if s.SystemGenerated != tt.generated {
			t.Errorf("Classify(%q).SystemGenerated = %v, want %v", tt.path, s.SystemGenerated, tt.generated)
		}
		if s.LimitedTo != tt.limitedTo {
			t.Errorf("Classify(%q).LimitedTo = %q, want %q", tt.path, s.LimitedTo, tt.limitedTo)
		}
		fix, ok := FixForStore(s)
		if got := ok && fix.Component == fixJava; got != tt.javaFix {
			t.Errorf("Classify(%q): Java fix = %v, want %v (fix %+v)", tt.path, got, tt.javaFix, fix)
		}
		if s.Class == ClassJavaKeystore && s.SystemGenerated {
			if strings.Contains(s.Remediation, "Upgrade the JDK") || !strings.Contains(s.Remediation, "JDK upgrade") {
				t.Errorf("Classify(%q): generated cacerts remediation must rule the JDK upgrade out: %q", tt.path, s.Remediation)
			}
		}
	}
}

func TestIsDefaultSystemStore(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/ssl/certs/ca-certificates.crt", true},
		{"etc/ssl/certs/ca-certificates.crt", true},
		{"/etc/ssl/cert.pem", true},
		{"/etc/ssl/certs", true},
		{"/etc/ssl/certs/", true},
		{"/ETC/SSL/CERTS", true},
		{"/etc/pki/tls/certs/ca-bundle.crt", true},
		{"/etc/pki/tls/certs", true},
		{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", true},
		{"/etc/pki/ca-trust/extracted/pem/directory-hash", true},
		{"/var/lib/ca-certificates/ca-bundle.pem", true},
		{"/var/lib/ca-certificates/pem", true},
		{"/usr/lib/ssl/certs", true},
		{"/etc/ssl/certs/corp.pem", false},
		{"/opt/corp/bundle.pem", false},
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", false},
		{"/usr/local/share/ca-certificates", false},
		{"/usr/local/share/ca-certificates/corp.crt", false},
		{"/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem", false},
		{"", false},
		{"/", false},
	}
	for _, tt := range tests {
		if got := isDefaultSystemStore(tt.path); got != tt.want {
			t.Errorf("isDefaultSystemStore(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
