package stores

import (
	"reflect"
	"strings"
	"testing"
)

func TestEnvHints(t *testing.T) {
	type h struct {
		variable, path, ecosystem string
		warning                   bool
	}
	tests := []struct {
		name string
		env  []string
		want []h
	}{
		{"empty", nil, nil},
		{"irrelevant", []string{"PATH=/usr/bin", "HOME=/root", "FOO=bar", "NOEQUALS"}, nil},
		{"ssl_cert_file", []string{"SSL_CERT_FILE=/etc/ssl/custom.pem"}, []h{{"SSL_CERT_FILE", "/etc/ssl/custom.pem", "system", false}}},
		{"ssl_cert_file_empty", []string{"SSL_CERT_FILE="}, nil},
		{"ssl_cert_dir_list", []string{"SSL_CERT_DIR=/a:/b::/c"}, []h{{"SSL_CERT_DIR", "/a", "system", false}, {"SSL_CERT_DIR", "/b", "system", false}, {"SSL_CERT_DIR", "/c", "system", false}}},
		{"value_with_equals", []string{"REQUESTS_CA_BUNDLE=/x=y/ca.pem"}, []h{{"REQUESTS_CA_BUNDLE", "/x=y/ca.pem", "python", false}}},
		{"python", []string{"PIP_CERT=/pc", "HTTPLIB2_CA_CERTS=/h", "TWINE_CERT=/t"}, []h{{"PIP_CERT", "/pc", "python", false}, {"HTTPLIB2_CA_CERTS", "/h", "python", false}, {"TWINE_CERT", "/t", "python", false}}},
		{"curl_aws_git", []string{"CURL_CA_BUNDLE=/cu", "AWS_CA_BUNDLE=/a", "GIT_SSL_CAINFO=/g", "GIT_SSL_CAPATH=/gp"}, []h{{"CURL_CA_BUNDLE", "/cu", "system", false}, {"AWS_CA_BUNDLE", "/a", "cloud-cli", false}, {"GIT_SSL_CAINFO", "/g", "other", false}, {"GIT_SSL_CAPATH", "/gp", "other", false}}},
		{"node_extra", []string{"NODE_EXTRA_CA_CERTS=/corp.pem"}, []h{{"NODE_EXTRA_CA_CERTS", "/corp.pem", "node", false}}},
		{"node_options_openssl", []string{"NODE_OPTIONS=--max-old-space-size=4096 --use-openssl-ca"}, []h{{"NODE_OPTIONS", "", "node", false}}},
		{"node_options_bundled", []string{"NODE_OPTIONS=--use-bundled-ca"}, []h{{"NODE_OPTIONS", "", "node", false}}},
		{"node_options_system", []string{"NODE_OPTIONS=--use-system-ca"}, []h{{"NODE_OPTIONS", "", "node", false}}},
		{"node_options_irrelevant", []string{"NODE_OPTIONS=--max-old-space-size=4096"}, nil},
		{"node_use_system_ca", []string{"NODE_USE_SYSTEM_CA=1"}, []h{{"NODE_USE_SYSTEM_CA", "", "node", false}}},
		{"node_use_system_ca_off", []string{"NODE_USE_SYSTEM_CA=0"}, nil},
		{"node_reject_unauthorized", []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}, []h{{"NODE_TLS_REJECT_UNAUTHORIZED", "", "node", true}}},
		{"node_reject_unauthorized_on", []string{"NODE_TLS_REJECT_UNAUTHORIZED=1"}, nil},
		{"deno", []string{"DENO_CERT=/d.pem", "DENO_TLS_CA_STORE=system"}, []h{{"DENO_CERT", "/d.pem", "deno", false}, {"DENO_TLS_CA_STORE", "", "deno", false}}},
		{"deno_store_mozilla_system", []string{"DENO_TLS_CA_STORE=mozilla,system"}, []h{{"DENO_TLS_CA_STORE", "", "deno", false}}},
		{"deno_store_unknown", []string{"DENO_TLS_CA_STORE=bogus"}, nil},
		{"rust_nix_hex_perl_grpc", []string{"CARGO_HTTP_CAINFO=/c", "NIX_SSL_CERT_FILE=/n", "HEX_CACERTS_PATH=/h", "PERL_LWP_SSL_CA_FILE=/p", "PERL_LWP_SSL_CA_PATH=/pp", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/g"},
			[]h{{"CARGO_HTTP_CAINFO", "/c", "rust", false}, {"NIX_SSL_CERT_FILE", "/n", "system", false}, {"HEX_CACERTS_PATH", "/h", "erlang", false}, {"PERL_LWP_SSL_CA_FILE", "/p", "perl", false}, {"PERL_LWP_SSL_CA_PATH", "/pp", "perl", false}, {"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "/g", "other", false}}},
		{"php_ruby", []string{"COMPOSER_CAFILE=/c.pem", "BUNDLE_SSL_CA_CERT=/b.pem"}, []h{{"COMPOSER_CAFILE", "/c.pem", "php", false}, {"BUNDLE_SSL_CA_CERT", "/b.pem", "ruby", false}}},
		{"uv_native_tls", []string{"UV_NATIVE_TLS=true"}, []h{{"UV_NATIVE_TLS", "", "python", false}}},
		{"uv_native_tls_off", []string{"UV_NATIVE_TLS=false"}, nil},
		{"java_tool_options", []string{"JAVA_TOOL_OPTIONS=-Xmx1g -Djavax.net.ssl.trustStore=/opt/ts.p12 -Djavax.net.ssl.trustStorePassword=x"}, []h{{"JAVA_TOOL_OPTIONS", "/opt/ts.p12", "java", false}}},
		{"java_opts_quoted", []string{`JAVA_OPTS=-Djavax.net.ssl.trustStore="/opt/my ts.jks" -Dfoo=bar`}, []h{{"JAVA_OPTS", "/opt/my ts.jks", "java", false}}},
		{"java_opts_single_quoted", []string{`_JAVA_OPTIONS=-Djavax.net.ssl.trustStore='/opt/ts.jks'`}, []h{{"_JAVA_OPTIONS", "/opt/ts.jks", "java", false}}},
		{"jdk_java_options_last", []string{"JDK_JAVA_OPTIONS=-Djavax.net.ssl.trustStore=/opt/ts.jks"}, []h{{"JDK_JAVA_OPTIONS", "/opt/ts.jks", "java", false}}},
		{"java_no_truststore", []string{"JDK_JAVA_OPTIONS=-Xmx1g", "_JAVA_OPTIONS=-Djavax.net.ssl.trustStoreType=PKCS12", "JAVA_OPTS=-Djavax.net.ssl.trustStore="}, nil},
		{"python_verify", []string{"PYTHONHTTPSVERIFY=0"}, []h{{"PYTHONHTTPSVERIFY", "", "python", true}}},
		{"python_verify_on", []string{"PYTHONHTTPSVERIFY=1"}, nil},
		{"git_no_verify_true", []string{"GIT_SSL_NO_VERIFY=true"}, []h{{"GIT_SSL_NO_VERIFY", "", "other", true}}},
		{"git_no_verify_1", []string{"GIT_SSL_NO_VERIFY=1"}, []h{{"GIT_SSL_NO_VERIFY", "", "other", true}}},
		{"git_no_verify_false", []string{"GIT_SSL_NO_VERIFY=false", "GIT_SSL_NO_VERIFY=0", "GIT_SSL_NO_VERIFY=", "GIT_SSL_NO_VERIFY=off"}, nil},
		{"npm_strict_ssl", []string{"NPM_CONFIG_STRICT_SSL=false"}, []h{{"NPM_CONFIG_STRICT_SSL", "", "node", true}}},
		{"npm_strict_ssl_lowercase", []string{"npm_config_strict_ssl=FALSE"}, []h{{"npm_config_strict_ssl", "", "node", true}}},
		{"npm_strict_ssl_true", []string{"NPM_CONFIG_STRICT_SSL=true"}, nil},
		{"npm_cafile", []string{"npm_config_cafile=/npm.pem"}, []h{{"npm_config_cafile", "/npm.pem", "node", false}}},
		{"pip_trusted_host", []string{"PIP_TRUSTED_HOST=pypi.internal"}, []h{{"PIP_TRUSTED_HOST", "", "python", true}}},
		{"pip_trusted_host_empty", []string{"PIP_TRUSTED_HOST="}, nil},
		{"hex_unsafe", []string{"HEX_UNSAFE_HTTPS=1"}, []h{{"HEX_UNSAFE_HTTPS", "", "erlang", true}}},
		{"conda_verify", []string{"CONDA_SSL_VERIFY=false", "CONDA_SSL_VERIFY=/c.pem", "CONDA_SSL_VERIFY=true"}, []h{{"CONDA_SSL_VERIFY", "", "python", true}, {"CONDA_SSL_VERIFY", "/c.pem", "python", false}}},
		{"order_preserved", []string{"NODE_EXTRA_CA_CERTS=/x", "PATH=/bin", "SSL_CERT_FILE=/y", "DENO_CERT=/z", "SSL_CERT_FILE=/y2"},
			[]h{{"NODE_EXTRA_CA_CERTS", "/x", "node", false}, {"SSL_CERT_FILE", "/y", "system", false}, {"DENO_CERT", "/z", "deno", false}, {"SSL_CERT_FILE", "/y2", "system", false}}},
		{"case_sensitive_system_vars", []string{"ssl_cert_file=/x"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hints := EnvHints(tt.env)
			var got []h
			for _, x := range hints {
				if x.Description == "" {
					t.Errorf("hint %+v has no description", x)
				}
				if x.Value == "" && x.Path != "" {
					t.Errorf("hint %+v has a path but no value", x)
				}
				got = append(got, h{x.Variable, x.Path, x.Ecosystem, x.Warning})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EnvHints(%q) =\n  %+v\nwant\n  %+v", tt.env, got, tt.want)
			}
		})
	}
}

func TestEnvHintValuesAreVerbatim(t *testing.T) {
	hints := EnvHints([]string{"SSL_CERT_DIR=/a:/b"})
	if len(hints) != 2 || hints[0].Value != "/a:/b" || hints[1].Value != "/a:/b" {
		t.Fatalf("got %+v", hints)
	}
	hints = EnvHints([]string{"NODE_OPTIONS=--use-openssl-ca --use-bundled-ca"})
	if len(hints) != 2 || hints[0].Value != "--use-openssl-ca --use-bundled-ca" {
		t.Fatalf("got %+v", hints)
	}
}

func TestJavaTrustStore(t *testing.T) {
	tests := []struct {
		opts string
		want string
		ok   bool
	}{
		{"", "", false},
		{"-Xmx1g", "", false},
		{"-Djavax.net.ssl.trustStore=/a.jks", "/a.jks", true},
		{"-Xmx1g -Djavax.net.ssl.trustStore=/a.jks -Dfoo=bar", "/a.jks", true},
		{"-Djavax.net.ssl.trustStore=\"/a b.jks\" -Dfoo", "/a b.jks", true},
		{"-Djavax.net.ssl.trustStore='/a b.jks'", "/a b.jks", true},
		{"-Djavax.net.ssl.trustStore=\"/unterminated", "/unterminated", true},
		{"-Djavax.net.ssl.trustStore=", "", false},
		{"-Djavax.net.ssl.trustStore=\"\"", "", false},
		{"-Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit", "", false},
		{"-Djavax.net.ssl.trustStorePassword=x -Djavax.net.ssl.trustStore=/b.p12", "/b.p12", true},
		{"-Djavax.net.ssl.trustStore=/a.jks\t-Dx=y", "/a.jks", true},
	}
	for _, tt := range tests {
		got, ok := javaTrustStore(tt.opts)
		if got != tt.want || ok != tt.ok {
			t.Errorf("javaTrustStore(%q) = %q, %v; want %q, %v", tt.opts, got, ok, tt.want, tt.ok)
		}
	}
}

// Default is set only when a variable whose consumer reads the system store
// anyway points at that store; the description then stops claiming a
// redirect "instead of the default".
func TestEnvHintDefault(t *testing.T) {
	tests := []struct {
		env     string
		def     bool
		desc    string // substring the description must contain
		notDesc string // substring it must not contain
	}{
		{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", true, "which is the default system bundle", "instead of"},
		{"SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt", true, "default system bundle", "instead of"},
		{"SSL_CERT_FILE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", true, "default system bundle", "instead of"},
		{"SSL_CERT_FILE=/var/lib/ca-certificates/ca-bundle.pem", true, "default system bundle", "instead of"},
		{"SSL_CERT_FILE=/opt/corp/bundle.pem", false, "instead of the default system bundle", ""},
		{"SSL_CERT_FILE=/etc/ssl/certs/corp.pem", false, "instead of the default system bundle", ""},
		{"SSL_CERT_FILE=/usr/lib/python3/dist-packages/certifi/cacert.pem", false, "instead of", ""},
		{"SSL_CERT_DIR=/etc/ssl/certs", true, "which is the default one", "instead of"},
		{"SSL_CERT_DIR=/etc/pki/tls/certs", true, "which is the default one", "instead of"},
		{"SSL_CERT_DIR=/opt/certs", false, "instead of the default one", ""},
		{"CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt", true, "default system bundle", "instead of the system store"},
		{"CURL_CA_BUNDLE=/opt/corp.pem", false, "instead of the system store", ""},
		{"GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt", true, "default system bundle", "instead of"},
		{"GIT_SSL_CAINFO=/opt/corp.pem", false, "instead of the system store", ""},
		{"GIT_SSL_CAPATH=/etc/ssl/certs", true, "the default one", "instead of"},
		{"GIT_SSL_CAPATH=/opt/certs", false, "instead of the default one", ""},
		// Consumers whose own default is not the system store are redirected
		// even when pointed at the system bundle.
		{"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt", false, "instead of certifi", ""},
		{"PIP_CERT=/etc/ssl/certs/ca-certificates.crt", false, "instead of its vendored certifi", ""},
		{"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt", false, "appended", ""},
		{"AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt", false, "instead of", ""},
	}
	for _, tt := range tests {
		hints := EnvHints([]string{tt.env})
		if len(hints) != 1 {
			t.Errorf("EnvHints(%q) = %+v, want one hint", tt.env, hints)
			continue
		}
		h := hints[0]
		if h.Default != tt.def {
			t.Errorf("EnvHints(%q).Default = %v, want %v", tt.env, h.Default, tt.def)
		}
		if !strings.Contains(h.Description, tt.desc) {
			t.Errorf("EnvHints(%q) description %q does not contain %q", tt.env, h.Description, tt.desc)
		}
		if tt.notDesc != "" && strings.Contains(h.Description, tt.notDesc) {
			t.Errorf("EnvHints(%q) description %q must not contain %q", tt.env, h.Description, tt.notDesc)
		}
	}
	// Each directory of a list is judged on its own.
	hints := EnvHints([]string{"SSL_CERT_DIR=/etc/ssl/certs:/opt/certs"})
	if len(hints) != 2 || !hints[0].Default || hints[1].Default {
		t.Errorf("SSL_CERT_DIR list: got %+v", hints)
	}
}
