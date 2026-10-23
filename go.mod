module github.com/Yanni8/emudhra-contaianer-scanner

go 1.25.0

// The scanner is a finder, not a verifier: it must see the certificates with
// negative serial numbers (EC-ACC in every RHEL/Fedora store) that OpenSSL
// and NSS accept and Go 1.23+ rejects by default.
godebug x509negativeserial=1

require (
	github.com/google/go-containerregistry v0.22.1
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require (
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)
