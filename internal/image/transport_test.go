package image

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestOpenRejectsDistrustedRegistryKey(t *testing.T) {
	srv := httptest.NewUnstartedServer(registry.New(registry.Logger(quietLogger())))
	srv.Config.ErrorLog = quietLogger() // expected handshake failures are not news
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	ref := host + "/tls/app:v1"
	img := fixtureImage(t, linuxAMD64)
	if err := remote.Write(mustRef(t, ref), img, remote.WithTransport(srv.Client().Transport)); err != nil {
		t.Fatalf("pushing to TLS registry: %v", err)
	}
	serverKey := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	otherKey := sha256.Sum256([]byte("some other public key"))

	t.Run("server key on the blocklist", func(t *testing.T) {
		_, err := Open(context.Background(), ref, Options{Insecure: true, RejectSPKIHashes: [][32]byte{otherKey, serverKey}})
		var dke *DistrustedKeyError
		if !errors.As(err, &dke) {
			t.Fatalf("Open error = %v, want *DistrustedKeyError", err)
		}
		if dke.SPKIHash != serverKey {
			t.Errorf("SPKIHash = %x, want %x", dke.SPKIHash, serverKey)
		}
		if !strings.Contains(err.Error(), hex.EncodeToString(serverKey[:])) {
			t.Errorf("error %q does not name the hash %x", err, serverKey)
		}
		if !strings.Contains(err.Error(), "resolving "+ref) {
			t.Errorf("error %q does not name the reference", err)
		}
	})

	t.Run("other key on the blocklist", func(t *testing.T) {
		im, err := Open(context.Background(), ref, Options{Insecure: true, RejectSPKIHashes: [][32]byte{otherKey}, Platform: "linux/amd64"})
		if err != nil {
			var dke *DistrustedKeyError
			if errors.As(err, &dke) {
				t.Fatalf("Open refused the connection although the server key is not listed: %v", err)
			}
			t.Fatalf("Open: %v", err)
		}
		if im.Reference != ref {
			t.Errorf("Reference = %q, want %q", im.Reference, ref)
		}
		assertFS(t, readFS(t, im), wantFS("linux/amd64"))
	})

	t.Run("empty blocklist", func(t *testing.T) {
		if _, err := Open(context.Background(), ref, Options{Insecure: true}); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})

	t.Run("verification is enforced by default", func(t *testing.T) {
		// The test server's certificate is self-signed, so without Insecure
		// the connection must be refused even though the key is not listed.
		if _, err := Open(context.Background(), ref, Options{}); err == nil {
			t.Fatal("Open succeeded against an untrusted certificate")
		}
	})
}

// selfSigned returns a fresh self-signed certificate with the given CN.
func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSPKIRejecter(t *testing.T) {
	certA, certB := selfSigned(t, "a"), selfSigned(t, "b")
	hashA := sha256.Sum256(certA.RawSubjectPublicKeyInfo)
	hashB := sha256.Sum256(certB.RawSubjectPublicKeyInfo)

	tests := []struct {
		name      string
		hashes    [][32]byte
		rawCerts  [][]byte
		chains    [][]*x509.Certificate
		wantHash  *[32]byte // expect a DistrustedKeyError with this hash
		wantError bool      // expect some other error
	}{
		{name: "nothing listed", rawCerts: [][]byte{certA.Raw}},
		{name: "listed key presented", hashes: [][32]byte{hashA}, rawCerts: [][]byte{certA.Raw}, wantHash: &hashA},
		{name: "listed key not presented", hashes: [][32]byte{hashA}, rawCerts: [][]byte{certB.Raw}},
		{name: "listed key deeper in presented chain", hashes: [][32]byte{hashA}, rawCerts: [][]byte{certB.Raw, certA.Raw}, wantHash: &hashA},
		{name: "listed key only in verified chain", hashes: [][32]byte{hashA}, rawCerts: [][]byte{certB.Raw}, chains: [][]*x509.Certificate{{certB, certA}}, wantHash: &hashA},
		{name: "several listed keys", hashes: [][32]byte{hashA, hashB}, rawCerts: [][]byte{certB.Raw}, wantHash: &hashB},
		{name: "nil entries in verified chains are skipped", hashes: [][32]byte{hashA}, rawCerts: [][]byte{certB.Raw}, chains: [][]*x509.Certificate{{nil, certB}}},
		{name: "unparsable certificate", hashes: [][32]byte{hashA}, rawCerts: [][]byte{[]byte("garbage")}, wantError: true},
		{name: "unparsable certificate ignored when nothing listed", rawCerts: [][]byte{[]byte("garbage")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := spkiRejecter(tc.hashes)(tc.rawCerts, tc.chains)
			var dke *DistrustedKeyError
			switch {
			case tc.wantHash != nil:
				if !errors.As(err, &dke) {
					t.Fatalf("error = %v, want *DistrustedKeyError", err)
				}
				if dke.SPKIHash != *tc.wantHash {
					t.Errorf("SPKIHash = %x, want %x", dke.SPKIHash, *tc.wantHash)
				}
				if dke.Subject == "" || !strings.Contains(err.Error(), dke.Subject) {
					t.Errorf("error %q does not name the subject %q", err, dke.Subject)
				}
			case tc.wantError:
				if err == nil || errors.As(err, &dke) {
					t.Fatalf("error = %v, want a non-distrust error", err)
				}
			default:
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			}
		})
	}
}

func TestNewTransport(t *testing.T) {
	base := remote.DefaultTransport.(*http.Transport)
	baseTLS := base.TLSClientConfig // may have been installed lazily by net/http's HTTP/2 setup
	hash := sha256.Sum256([]byte("key"))

	insecure := newTransport(Options{Insecure: true, RejectSPKIHashes: [][32]byte{hash}})
	if insecure == base {
		t.Fatal("newTransport returned the shared default transport instead of a clone")
	}
	if insecure.TLSClientConfig == nil || !insecure.TLSClientConfig.InsecureSkipVerify {
		t.Error("Insecure did not set InsecureSkipVerify")
	}
	if insecure.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is not installed")
	}
	if insecure.Proxy == nil {
		t.Error("proxy from environment is not honoured")
	}
	if insecure.TLSHandshakeTimeout != base.TLSHandshakeTimeout || insecure.MaxIdleConns != base.MaxIdleConns {
		t.Error("transport settings were not cloned from the default transport")
	}

	secure := newTransport(Options{})
	if secure.TLSClientConfig == nil || secure.TLSClientConfig.InsecureSkipVerify {
		t.Error("default options must verify certificates")
	}
	if base.TLSClientConfig != baseTLS {
		t.Error("newTransport replaced the TLS configuration of remote.DefaultTransport")
	}
	if baseTLS != nil && (baseTLS.InsecureSkipVerify || baseTLS.VerifyPeerCertificate != nil) {
		t.Error("newTransport mutated the TLS configuration of remote.DefaultTransport")
	}
	if secure.TLSClientConfig == baseTLS || insecure.TLSClientConfig == baseTLS {
		t.Error("newTransport shares its TLS configuration with remote.DefaultTransport")
	}
}
