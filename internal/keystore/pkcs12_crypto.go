package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"
)

// Password-based encryption schemes found in PKCS#12 files: the PKCS#12 PBE
// family (RFC 7292 appendix C, used by OpenSSL before 3.0 and by Java before
// 20) and PBES2 (RFC 8018, used by OpenSSL 3 and Java 20+).
var (
	oidPBEWithSHAAnd128BitRC4        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
	oidPBEWithSHAAnd40BitRC4         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd2KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}

	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

const (
	// maxKDFIterations bounds the work a hostile file can demand per key
	// derivation. It matches the limit Java's PKCS12KeyStore enforces.
	maxKDFIterations = 5_000_000
	// defaultKDFIterationsPerFile bounds the key-derivation work spent on
	// one file: the iteration counts of every derivation attempted (MAC
	// verification, every SafeContents, every password) are summed against
	// it, and the rest of the file is refused once it is used up.
	defaultKDFIterationsPerFile = 10_000_000
	// maxKDFSaltLen bounds the salt (and therefore the per-iteration hashing
	// cost of the PKCS#12 KDF); real files use 8 to 32 bytes.
	maxKDFSaltLen = 1024
)

var (
	// errIncorrectPassword is returned when decryption with a password yields
	// invalid padding or content that is not a SafeContents.
	errIncorrectPassword = errors.New("incorrect password")
	// errNoPassword is returned when an encrypted part has no password to try.
	errNoPassword = errors.New("no password supplied")
	// errLimits is wrapped by errors about key-derivation parameters that
	// exceed what the package is willing to compute.
	errLimits = errors.New("exceeds the supported maximum")
	// errBudget is wrapped by errors about derivations that no longer fit the
	// per-file budget.
	errBudget = errors.New("key-derivation budget exhausted")
)

// kdfIterationsPerFile is the per-file budget in force; tests lower it.
var kdfIterationsPerFile int64 = defaultKDFIterationsPerFile

// kdfBudget is the key-derivation work one file may still consume, in KDF
// iterations. Every derivation is charged before it runs, so a file that
// asks for too much stops being decrypted rather than being ground through.
type kdfBudget struct {
	left int64
}

func newKDFBudget() *kdfBudget {
	return &kdfBudget{left: kdfIterationsPerFile}
}

// charge reserves iterations for one derivation, or fails with errBudget
// (leaving the budget untouched) when they exceed what is left.
func (b *kdfBudget) charge(iterations int) error {
	if int64(iterations) > b.left {
		return fmt.Errorf("%w: %d iterations requested, %d left for this file", errBudget, iterations, b.left)
	}
	b.left -= int64(iterations)
	return nil
}

// pbeParams are the parameters of the PKCS#12 PBE algorithms.
type pbeParams struct {
	Salt       []byte
	Iterations int
}

// pbes2Params are the parameters of PBES2 (RFC 8018 appendix A.4).
type pbes2Params struct {
	KDF              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

// pbkdf2Params are the parameters of PBKDF2 (RFC 8018 appendix A.2).
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// contentDecryptor decrypts one EncryptedContentInfo with a password.
type contentDecryptor struct {
	// newCipher derives the key and IV from the encoded password.
	newCipher func(password []byte) (cipher.Block, []byte, error)
	// bmp is true when the password is encoded as a NUL-terminated BMPString
	// (PKCS#12 PBE) and false when it is UTF-8 (PBES2).
	bmp bool
	// iterations is the KDF iteration count of one derivation, charged to
	// the budget before each password is tried.
	iterations int
}

// decryptSafeContents decrypts the content with each password in turn,
// starting with passwords[first] when first is not negative, and returns the
// bags of the first result that decodes as a SafeContents together with the
// index of the password that produced it. Every attempt is charged to the
// budget first; when it no longer fits, the remaining passwords are not tried
// and the error wraps errBudget.
func decryptSafeContents(eci encryptedContentInfo, passwords []string, first int, budget *kdfBudget) ([]safeBag, int, error) {
	if len(eci.EncryptedContent) == 0 {
		return nil, -1, errors.New("empty encrypted content")
	}
	dec, err := newContentDecryptor(eci.ContentEncryptionAlgorithm)
	if err != nil {
		return nil, -1, err
	}
	if len(passwords) == 0 {
		return nil, -1, errNoPassword
	}
	var lastErr error
	for _, i := range tryOrder(len(passwords), first) {
		if err := budget.charge(dec.iterations); err != nil {
			return nil, -1, err
		}
		for _, encoded := range dec.encodePassword(passwords[i]) {
			plain, err := dec.decrypt(eci.EncryptedContent, encoded)
			if err != nil {
				lastErr = err
				continue
			}
			bags, err := parseSafeContents(plain)
			if err != nil {
				// Valid padding but garbage content: almost certainly a wrong
				// password (1 in 256 wrong passwords passes the padding check).
				lastErr = errIncorrectPassword
				continue
			}
			return bags, i, nil
		}
	}
	return nil, -1, lastErr
}

// tryOrder lists the indices 0..n-1 with first (when within range) moved to
// the front.
func tryOrder(n, first int) []int {
	order := make([]int, 0, n)
	if first >= 0 && first < n {
		order = append(order, first)
	}
	for i := 0; i < n; i++ {
		if i != first {
			order = append(order, i)
		}
	}
	return order
}

// encodePassword returns the byte encodings of a password to try for this
// scheme. An empty PKCS#12 PBE password is ambiguous: RFC 7292 encodes it as
// the two-byte NUL terminator, some implementations use zero bytes.
func (d *contentDecryptor) encodePassword(password string) [][]byte {
	if !d.bmp {
		return [][]byte{[]byte(password)}
	}
	encoded := bmpStringZeroTerminated(password)
	if password == "" {
		return [][]byte{encoded, nil}
	}
	return [][]byte{encoded}
}

// decrypt runs CBC decryption and removes the PKCS#7 padding.
func (d *contentDecryptor) decrypt(ciphertext, password []byte) ([]byte, error) {
	block, iv, err := d.newCipher(password)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ciphertext)%bs != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of the block size %d", len(ciphertext), bs)
	}
	if len(iv) != bs {
		return nil, fmt.Errorf("IV length %d does not match the block size %d", len(iv), bs)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > bs || pad > len(plain) {
		return nil, errIncorrectPassword
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errIncorrectPassword
		}
	}
	return plain[:len(plain)-pad], nil
}

// newContentDecryptor validates the algorithm identifier and its parameters
// and returns a decryptor for it.
func newContentDecryptor(alg pkix.AlgorithmIdentifier) (*contentDecryptor, error) {
	if alg.Algorithm.Equal(oidPBES2) {
		return newPBES2Decryptor(alg)
	}
	var (
		keyLen  int
		newBlk  func(key []byte) (cipher.Block, error)
		ivLen   = 8
		rc2Bits int
	)
	switch {
	case alg.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		keyLen, newBlk = 24, des.NewTripleDESCipher
	case alg.Algorithm.Equal(oidPBEWithSHAAnd2KeyTripleDESCBC):
		keyLen = 16
		newBlk = func(key []byte) (cipher.Block, error) {
			k := make([]byte, 0, 24)
			k = append(k, key...)
			k = append(k, key[:8]...) // K3 = K1
			return des.NewTripleDESCipher(k)
		}
	case alg.Algorithm.Equal(oidPBEWithSHAAnd128BitRC2CBC):
		keyLen, rc2Bits = 16, 128
	case alg.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		keyLen, rc2Bits = 5, 40
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm %s", oidName(alg.Algorithm))
	}
	if rc2Bits != 0 {
		bits := rc2Bits
		newBlk = func(key []byte) (cipher.Block, error) { return newRC2Cipher(key, bits) }
	}
	var params pbeParams
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("decoding PBE parameters: %w", err)
	}
	if err := checkKDFParams(params.Salt, params.Iterations); err != nil {
		return nil, err
	}
	return &contentDecryptor{
		bmp:        true,
		iterations: params.Iterations,
		newCipher: func(password []byte) (cipher.Block, []byte, error) {
			key := pkcs12KDF(1, params.Salt, password, params.Iterations, keyLen)
			iv := pkcs12KDF(2, params.Salt, password, params.Iterations, ivLen)
			block, err := newBlk(key)
			if err != nil {
				return nil, nil, err
			}
			return block, iv, nil
		},
	}, nil
}

// newPBES2Decryptor handles PBES2 with PBKDF2 and AES-CBC or 3DES-CBC.
func newPBES2Decryptor(alg pkix.AlgorithmIdentifier) (*contentDecryptor, error) {
	var params pbes2Params
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("decoding PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported PBES2 key derivation function %s", params.KDF.Algorithm)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("decoding PBKDF2 parameters: %w", err)
	}
	if kdf.Salt.Class != asn1.ClassUniversal || kdf.Salt.Tag != asn1.TagOctetString {
		return nil, errors.New("unsupported PBKDF2 salt source")
	}
	if err := checkKDFParams(kdf.Salt.Bytes, kdf.Iterations); err != nil {
		return nil, err
	}
	var prf func() hash.Hash
	switch {
	case kdf.PRF.Algorithm == nil, kdf.PRF.Algorithm.Equal(oidHMACWithSHA1):
		prf = sha1.New // the default PRF
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA224):
		prf = sha256.New224
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA256):
		prf = sha256.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA384):
		prf = sha512.New384
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA512):
		prf = sha512.New
	default:
		return nil, fmt.Errorf("unsupported PBKDF2 pseudo-random function %s", kdf.PRF.Algorithm)
	}
	var (
		keyLen int
		newBlk func(key []byte) (cipher.Block, error)
	)
	scheme := params.EncryptionScheme
	switch {
	case scheme.Algorithm.Equal(oidAES128CBC):
		keyLen, newBlk = 16, aes.NewCipher
	case scheme.Algorithm.Equal(oidAES192CBC):
		keyLen, newBlk = 24, aes.NewCipher
	case scheme.Algorithm.Equal(oidAES256CBC):
		keyLen, newBlk = 32, aes.NewCipher
	case scheme.Algorithm.Equal(oidDESEDE3CBC):
		keyLen, newBlk = 24, des.NewTripleDESCipher
	default:
		return nil, fmt.Errorf("unsupported PBES2 encryption scheme %s", oidName(scheme.Algorithm))
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLen {
		return nil, fmt.Errorf("PBKDF2 key length %d does not match the %d-byte key of %s", kdf.KeyLength, keyLen, oidName(scheme.Algorithm))
	}
	var iv []byte
	if _, err := asn1.Unmarshal(scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("decoding encryption scheme IV: %w", err)
	}
	return &contentDecryptor{
		bmp:        false,
		iterations: kdf.Iterations,
		newCipher: func(password []byte) (cipher.Block, []byte, error) {
			key, err := pbkdf2.Key(prf, string(password), kdf.Salt.Bytes, kdf.Iterations, keyLen)
			if err != nil {
				return nil, nil, err
			}
			block, err := newBlk(key)
			if err != nil {
				return nil, nil, err
			}
			return block, iv, nil
		},
	}, nil
}

func checkKDFParams(salt []byte, iterations int) error {
	if iterations < 1 {
		return fmt.Errorf("invalid iteration count %d", iterations)
	}
	if iterations > maxKDFIterations {
		return fmt.Errorf("iteration count %d %w of %d", iterations, errLimits, maxKDFIterations)
	}
	if len(salt) > maxKDFSaltLen {
		return fmt.Errorf("salt length %d %w of %d", len(salt), errLimits, maxKDFSaltLen)
	}
	return nil
}

// bmpStringZeroTerminated encodes a password as PKCS#12 wants it: UTF-16BE
// followed by a two-byte NUL terminator (RFC 7292 appendix B.1).
func bmpStringZeroTerminated(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return append(out, 0, 0)
}

// pkcs12KDF implements the key derivation of RFC 7292 appendix B.2 with SHA-1.
// id selects the purpose (1 key, 2 IV, 3 MAC key) and n is the number of
// bytes wanted.
func pkcs12KDF(id byte, salt, password []byte, iterations, n int) []byte {
	const (
		u = sha1.Size // hash output size
		v = 64        // hash block size
	)
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	i := append(repeatToMultiple(salt, v), repeatToMultiple(password, v)...)
	out := make([]byte, 0, n+u)
	for {
		h := sha1.New()
		h.Write(d)
		h.Write(i)
		a := h.Sum(nil)
		for j := 1; j < iterations; j++ {
			s := sha1.Sum(a)
			a = s[:]
		}
		out = append(out, a...)
		if len(out) >= n {
			return out[:n]
		}
		b := repeatToMultiple(a, v)
		for j := 0; j+v <= len(i); j += v {
			addBlock(i[j:j+v], b)
		}
	}
}

// repeatToMultiple concatenates copies of b to the smallest multiple of v
// bytes that holds at least one copy (the last copy may be truncated).
func repeatToMultiple(b []byte, v int) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, v*((len(b)+v-1)/v))
	for i := 0; i < len(out); i += len(b) {
		copy(out[i:], b)
	}
	return out
}

// addBlock sets x = (x + b + 1) mod 2^(8*len(x)), big-endian.
func addBlock(x, b []byte) {
	carry := 1
	for k := len(x) - 1; k >= 0; k-- {
		s := int(x[k]) + int(b[k]) + carry
		x[k] = byte(s)
		carry = s >> 8
	}
}
