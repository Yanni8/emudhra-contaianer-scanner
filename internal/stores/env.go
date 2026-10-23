package stores

import "strings"

// envHints implements EnvHints.
func envHints(env []string) []EnvHint {
	var out []EnvHint
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		out = append(out, hintsFor(strings.TrimSpace(key), value)...)
	}
	return out
}

// hintsFor returns the hints one variable yields, in a stable order.
func hintsFor(key, value string) []EnvHint {
	one := func(h EnvHint) []EnvHint { return []EnvHint{h} }
	pathHint := func(ecosystem, desc string) []EnvHint {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return one(EnvHint{Variable: key, Value: value, Path: strings.TrimSpace(value), Ecosystem: ecosystem, Description: desc})
	}
	// systemPathHint is for variables whose consumer reads the system store
	// by default: pointing them at that store changes nothing (Default).
	systemPathHint := func(ecosystem, consumers, defaultDesc, otherDesc string) []EnvHint {
		p := strings.TrimSpace(value)
		if p == "" {
			return nil
		}
		h := EnvHint{Variable: key, Value: value, Path: p, Ecosystem: ecosystem, Default: isDefaultSystemStore(p)}
		if h.Default {
			h.Description = consumers + " " + defaultDesc
		} else {
			h.Description = consumers + " " + otherDesc
		}
		return one(h)
	}
	warn := func(ecosystem, desc string) []EnvHint {
		return one(EnvHint{Variable: key, Value: value, Ecosystem: ecosystem, Description: desc, Warning: true})
	}
	note := func(ecosystem, desc string) []EnvHint {
		return one(EnvHint{Variable: key, Value: value, Ecosystem: ecosystem, Description: desc})
	}

	switch key {
	case "SSL_CERT_FILE":
		return systemPathHint(ecoSystem, "OpenSSL and everything built on it (curl, wget, Python ssl, Ruby, PHP, .NET, Go crypto/x509, Rust rustls-native-certs)",
			"load this file, which is the default system bundle", "load this file instead of the default system bundle")
	case "SSL_CERT_DIR":
		var out []EnvHint
		for _, dir := range strings.Split(value, ":") {
			if dir = strings.TrimSpace(dir); dir != "" {
				h := EnvHint{Variable: key, Value: value, Path: dir, Ecosystem: ecoSystem, Default: isDefaultSystemStore(dir)}
				if h.Default {
					h.Description = "OpenSSL and everything built on it (Go crypto/x509, Python ssl, Ruby) use this hashed certificate directory, which is the default one"
				} else {
					h.Description = "OpenSSL and everything built on it (Go crypto/x509, Python ssl, Ruby) use this hashed certificate directory instead of the default one"
				}
				out = append(out, h)
			}
		}
		return out
	case "REQUESTS_CA_BUNDLE":
		return pathHint(ecoPython, "requests (and libraries built on it, such as boto3 without AWS_CA_BUNDLE) read this bundle instead of certifi")
	case "CURL_CA_BUNDLE":
		return systemPathHint(ecoSystem, "curl",
			"uses this bundle, which is the default system bundle; Python requests also honours it instead of certifi",
			"(and Python requests) use this bundle instead of the system store")
	case "PIP_CERT":
		return pathHint(ecoPython, "pip uses this bundle instead of its vendored certifi")
	case "HTTPLIB2_CA_CERTS":
		return pathHint(ecoPython, "httplib2 uses this bundle instead of its bundled cacerts.txt")
	case "TWINE_CERT":
		return pathHint(ecoPython, "twine uses this bundle for package uploads")
	case "AWS_CA_BUNDLE":
		return pathHint(ecoCloudCLI, "AWS CLI and boto3/botocore use this bundle instead of the bundled botocore/certifi one")
	case "GIT_SSL_CAINFO":
		return systemPathHint(ecoOther, "git", "uses this bundle for HTTPS remotes (the default system bundle)", "uses this bundle for HTTPS remotes instead of the system store")
	case "GIT_SSL_CAPATH":
		return systemPathHint(ecoOther, "git", "uses this certificate directory for HTTPS remotes (the default one)", "uses this certificate directory for HTTPS remotes instead of the default one")
	case "NODE_EXTRA_CA_CERTS":
		return pathHint(ecoNode, "appended to the Node.js bundled root store (the bundled roots stay trusted)")
	case "NODE_OPTIONS":
		var out []EnvHint
		for _, flag := range strings.Fields(value) {
			switch flag {
			case "--use-openssl-ca":
				out = append(out, EnvHint{Variable: key, Value: value, Ecosystem: ecoNode, Description: "Node.js uses the OpenSSL system store instead of its bundled root store (--use-openssl-ca)"})
			case "--use-bundled-ca":
				out = append(out, EnvHint{Variable: key, Value: value, Ecosystem: ecoNode, Description: "Node.js explicitly uses its bundled root store (--use-bundled-ca)"})
			case "--use-system-ca":
				out = append(out, EnvHint{Variable: key, Value: value, Ecosystem: ecoNode, Description: "Node.js additionally trusts the operating system store (--use-system-ca); the bundled roots stay trusted"})
			}
		}
		return out
	case "NODE_USE_SYSTEM_CA":
		if truthy(value) {
			return note(ecoNode, "Node.js additionally trusts the operating system store; the bundled roots stay trusted")
		}
		return nil
	case "NODE_TLS_REJECT_UNAUTHORIZED":
		if strings.TrimSpace(value) == "0" {
			return warn(ecoNode, "Node.js does not verify TLS certificates at all")
		}
		return nil
	case "DENO_CERT":
		return pathHint(ecoDeno, "Deno adds this PEM file to its trust anchors (the compiled-in webpki-roots stay trusted)")
	case "DENO_TLS_CA_STORE":
		v := strings.ToLower(value)
		switch {
		case strings.Contains(v, "system") && strings.Contains(v, "mozilla"):
			return note(ecoDeno, "Deno trusts both its compiled-in webpki-roots and the operating system store")
		case strings.Contains(v, "system"):
			return note(ecoDeno, "Deno uses the operating system store instead of its compiled-in webpki-roots")
		case strings.Contains(v, "mozilla"):
			return note(ecoDeno, "Deno explicitly uses its compiled-in webpki-roots store")
		}
		return nil
	case "CARGO_HTTP_CAINFO":
		return pathHint(ecoRust, "cargo uses this bundle for registry and git HTTPS")
	case "NIX_SSL_CERT_FILE":
		return pathHint(ecoSystem, "Nix and NixOS-built programs (through their SSL_CERT_FILE wrappers) use this bundle")
	case "HEX_CACERTS_PATH":
		return pathHint(ecoErlang, "Hex (Elixir/Erlang package manager) uses this bundle instead of its bundled CA store")
	case "HEX_UNSAFE_HTTPS":
		if truthy(value) {
			return warn(ecoErlang, "Hex does not verify TLS certificates")
		}
		return nil
	case "PERL_LWP_SSL_CA_FILE":
		return pathHint(ecoPerl, "LWP (libwww-perl) uses this bundle instead of Mozilla::CA")
	case "PERL_LWP_SSL_CA_PATH":
		return pathHint(ecoPerl, "LWP (libwww-perl) uses this certificate directory instead of Mozilla::CA")
	case "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH":
		return pathHint(ecoOther, "gRPC (C core: Python, Ruby, PHP, Node grpc) uses this bundle instead of its bundled roots.pem")
	case "COMPOSER_CAFILE":
		return pathHint(ecoPHP, "Composer uses this bundle instead of composer/ca-bundle")
	case "BUNDLE_SSL_CA_CERT":
		return pathHint(ecoRuby, "Bundler uses this bundle for rubygems.org")
	case "UV_NATIVE_TLS":
		if truthy(value) {
			return note(ecoPython, "uv uses the platform trust store instead of its compiled-in webpki-roots")
		}
		return nil
	case "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS", "_JAVA_OPTIONS":
		if p, ok := javaTrustStore(value); ok {
			return one(EnvHint{Variable: key, Value: value, Path: p, Ecosystem: ecoJava, Description: "the JVM uses this truststore instead of cacerts (-Djavax.net.ssl.trustStore)"})
		}
		return nil
	case "PYTHONHTTPSVERIFY":
		if strings.TrimSpace(value) == "0" {
			return warn(ecoPython, "Python's ssl module does not verify HTTPS certificates (legacy PEP 493 switch)")
		}
		return nil
	case "GIT_SSL_NO_VERIFY":
		if truthy(value) {
			return warn(ecoOther, "git does not verify TLS certificates")
		}
		return nil
	case "PIP_TRUSTED_HOST":
		if strings.TrimSpace(value) != "" {
			return warn(ecoPython, "pip skips TLS verification for these hosts")
		}
		return nil
	case "CONDA_SSL_VERIFY":
		if falsy(value) {
			return warn(ecoPython, "conda does not verify TLS certificates")
		}
		if strings.Contains(value, "/") {
			return pathHint(ecoPython, "conda uses this bundle instead of its own")
		}
		return nil
	}
	// npm reads its configuration variables case-insensitively.
	switch strings.ToUpper(key) {
	case "NPM_CONFIG_STRICT_SSL":
		if falsy(value) {
			return warn(ecoNode, "npm does not verify registry TLS certificates")
		}
	case "NPM_CONFIG_CAFILE":
		return pathHint(ecoNode, "npm uses this CA file instead of the Node.js bundled store")
	}
	return nil
}

// javaTrustStore extracts the value of -Djavax.net.ssl.trustStore= from a JVM
// options string, honouring single or double quotes around the value.
func javaTrustStore(opts string) (string, bool) {
	const key = "-Djavax.net.ssl.trustStore="
	i := strings.Index(opts, key)
	if i < 0 {
		return "", false
	}
	rest := opts[i+len(key):]
	if rest == "" {
		return "", false
	}
	if q := rest[0]; q == '"' || q == '\'' {
		rest = rest[1:]
		if j := strings.IndexByte(rest, q); j >= 0 {
			rest = rest[:j]
		}
		return rest, rest != ""
	}
	if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest, rest != ""
}

// falsy recognises the spellings of "false" accepted by npm, git and conda.
func falsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// truthy is any non-empty value that is not falsy (git's and npm's reading).
func truthy(v string) bool {
	return strings.TrimSpace(v) != "" && !falsy(v)
}
