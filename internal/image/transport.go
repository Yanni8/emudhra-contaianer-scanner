package image

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// DistrustedKeyError is returned (wrapped) by Open when a certificate in the
// TLS chain presented by a registry carries a public key listed in
// Options.RejectSPKIHashes. The handshake is aborted before any request is
// sent.
type DistrustedKeyError struct {
	// Subject is the distinguished name of the offending certificate.
	Subject string
	// SPKIHash is the SHA-256 of the certificate's DER SubjectPublicKeyInfo.
	SPKIHash [32]byte
}

// Error implements error.
func (e *DistrustedKeyError) Error() string {
	return fmt.Sprintf("refusing TLS connection: certificate %q uses a distrusted public key (SPKI SHA-256 %x)", e.Subject, e.SPKIHash)
}

// newTransport clones go-containerregistry's default transport (which honours
// HTTP(S)_PROXY and NO_PROXY from the environment) and installs the TLS
// policy from opts: optional verification skipping and the SPKI blocklist,
// which is enforced even when verification is skipped.
func newTransport(opts Options) *http.Transport {
	var t *http.Transport
	if base, ok := remote.DefaultTransport.(*http.Transport); ok {
		t = base.Clone()
	} else {
		t = http.DefaultTransport.(*http.Transport).Clone()
	}
	cfg := &tls.Config{}
	if t.TLSClientConfig != nil {
		cfg = t.TLSClientConfig.Clone()
	}
	cfg.InsecureSkipVerify = opts.Insecure
	cfg.VerifyPeerCertificate = spkiRejecter(opts.RejectSPKIHashes)
	t.TLSClientConfig = cfg
	return t
}

// spkiRejecter returns a tls.Config.VerifyPeerCertificate callback that
// refuses the handshake when any presented or verified certificate carries a
// public key whose SPKI SHA-256 is in hashes.
func spkiRejecter(hashes [][32]byte) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	reject := make(map[[32]byte]struct{}, len(hashes))
	for _, h := range hashes {
		reject[h] = struct{}{}
	}
	check := func(cert *x509.Certificate) error {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if _, bad := reject[sum]; bad {
			return &DistrustedKeyError{Subject: cert.Subject.String(), SPKIHash: sum}
		}
		return nil
	}
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(reject) == 0 {
			return nil
		}
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parsing certificate presented by the registry: %w", err)
			}
			if err := check(cert); err != nil {
				return err
			}
		}
		for _, chain := range verifiedChains {
			for _, cert := range chain {
				if cert == nil {
					continue
				}
				if err := check(cert); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
