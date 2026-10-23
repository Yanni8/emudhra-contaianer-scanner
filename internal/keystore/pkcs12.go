package keystore

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

// Object identifiers from RFC 7292 (PKCS#12), RFC 2315 (PKCS#7) and RFC 2985
// (PKCS#9).
var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedDataContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}

	oidCertTypeX509 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

const (
	// maxSafeContentsNesting bounds the recursion into SafeContents bags.
	maxSafeContentsNesting = 4
	// maxEncryptedSafeContents bounds the number of encrypted SafeContents a
	// file may hold; real files have one or two.
	maxEncryptedSafeContents = 64
	// maxProblemsListed bounds how many unreadable parts an error names.
	maxProblemsListed = 3
)

// pfxPDU is the outer PFX structure (RFC 7292 section 4).
type pfxPDU struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

// contentInfo is a PKCS#7 ContentInfo.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// encryptedData is a PKCS#7 EncryptedData.
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

// safeBag is a PKCS#12 SafeBag.
type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// certBag is the value of a CertBag SafeBag.
type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

// encryptedPrivateKeyInfo is the value of a PKCS8ShroudedKeyBag (RFC 5208).
type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// macData is the MacData of a PFX (RFC 7292 section 4).
type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// pbmac1Params are the parameters of PBMAC1 (RFC 8018 appendix A.5), whose
// iteration count lives in its PBKDF2 parameters rather than in MacData.
type pbmac1Params struct {
	KDF    pkix.AlgorithmIdentifier
	MacAlg pkix.AlgorithmIdentifier
}

var oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

// pfxFile is the decoded outer structure of a PKCS#12 file: the list of
// ContentInfo values of its AuthenticatedSafe.
type pfxFile struct {
	hasMAC        bool
	macIterations int // 0 when there is no MAC or its parameters are unreadable
	contents      []contentInfo
}

// parsePFX decodes the outer PFX structure down to the AuthenticatedSafe
// without decrypting anything.
func parsePFX(data []byte) (*pfxFile, error) {
	var pfx pfxPDU
	if _, err := asn1.Unmarshal(data, &pfx); err != nil { // trailing bytes are tolerated
		return nil, asn1Error("decoding PFX", err)
	}
	if pfx.Version != 3 {
		return nil, fmt.Errorf("unsupported PFX version %d", pfx.Version)
	}
	switch {
	case pfx.AuthSafe.ContentType.Equal(oidDataContentType):
	case pfx.AuthSafe.ContentType.Equal(oidSignedDataContentType):
		return nil, errors.New("public-key integrity mode (signedData) is not supported")
	default:
		return nil, fmt.Errorf("unsupported authSafe content type %s", pfx.AuthSafe.ContentType)
	}
	var authSafeDER []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeDER); err != nil {
		return nil, asn1Error("decoding authSafe", err)
	}
	var contents []contentInfo
	if _, err := asn1.Unmarshal(authSafeDER, &contents); err != nil {
		return nil, asn1Error("decoding AuthenticatedSafe", err)
	}
	return &pfxFile{
		hasMAC:        len(pfx.MacData.FullBytes) > 0,
		macIterations: macIterations(pfx.MacData),
		contents:      contents,
	}, nil
}

// macIterations extracts the key-derivation iteration count of the MAC.
func macIterations(raw asn1.RawValue) int {
	if len(raw.FullBytes) == 0 {
		return 0
	}
	var md macData
	if _, err := asn1.Unmarshal(raw.FullBytes, &md); err != nil {
		return 0
	}
	if !md.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
		return md.Iterations
	}
	var params pbmac1Params
	if _, err := asn1.Unmarshal(md.Mac.Algorithm.Parameters.FullBytes, &params); err != nil {
		return 0
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return 0
	}
	return kdf.Iterations
}

// kdfIterations reads the iteration count out of the parameters of a
// password-based encryption algorithm (PBES2 with PBKDF2, or the PKCS#12 PBE
// family) without deriving anything. ok is false for other algorithms and
// unreadable parameters.
func kdfIterations(alg pkix.AlgorithmIdentifier) (iterations int, ok bool) {
	if alg.Algorithm.Equal(oidPBES2) {
		var params pbes2Params
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil || !params.KDF.Algorithm.Equal(oidPBKDF2) {
			return 0, false
		}
		var kdf pbkdf2Params
		if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
			return 0, false
		}
		return kdf.Iterations, true
	}
	if !isPKCS12PBE(alg.Algorithm) {
		return 0, false
	}
	var params pbeParams
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		return 0, false
	}
	return params.Iterations, true
}

// decodeEncryptedData decodes the content of an encryptedData ContentInfo.
func decodeEncryptedData(ci contentInfo) (*encryptedData, error) {
	var ed encryptedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, asn1Error("decoding encryptedData", err)
	}
	return &ed, nil
}

// demand is the key-derivation work a file asks for with one password.
type demand struct {
	encrypted int   // number of encrypted SafeContents
	requested int64 // MAC iterations plus those of every encrypted SafeContents
	feasible  int64 // the part of requested below the per-derivation maximum
}

// demands reads the iteration counts of the MAC and of every encrypted
// SafeContents whose parameters can be read, without deriving anything. A
// count above the per-derivation maximum is reported but never worked on,
// so it does not count as feasible.
func (p *pfxFile) demands() demand {
	var d demand
	add := func(n int) {
		if n <= 0 {
			return
		}
		d.requested += int64(n)
		if n <= maxKDFIterations {
			d.feasible += int64(n)
		}
	}
	add(p.macIterations)
	for _, ci := range p.contents {
		if !ci.ContentType.Equal(oidEncryptedDataContentType) {
			continue
		}
		d.encrypted++
		if ed, err := decodeEncryptedData(ci); err == nil {
			if n, ok := kdfIterations(ed.EncryptedContentInfo.ContentEncryptionAlgorithm); ok {
				add(n)
			}
		}
	}
	return d
}

// budget returns the key-derivation budget for reading the file. A file
// that asks for more than the budget even for a single password, or holds
// more encrypted SafeContents than supported, gets an exhausted budget and
// the reason, so that no derivation at all is attempted for it.
func (p *pfxFile) budget() (*kdfBudget, error) {
	d := p.demands()
	switch {
	case d.encrypted > maxEncryptedSafeContents:
		return &kdfBudget{}, fmt.Errorf("%w (%d iterations requested, %d encrypted SafeContents)", ErrTooExpensive, d.requested, d.encrypted)
	case d.feasible > kdfIterationsPerFile:
		return &kdfBudget{}, fmt.Errorf("%w (%d iterations requested)", ErrTooExpensive, d.requested)
	}
	return newKDFBudget(), nil
}

// libraryCost is the key-derivation work one go-pkcs12 decode of the file
// costs: base covers the MAC and every encrypted SafeContents, shrouded the
// private keys a chain decode additionally unwraps. bounded is false when
// any single derivation exceeds the per-derivation maximum, which the
// library would not refuse.
func (p *pfxFile) libraryCost(results []safeContentsResult) (base, shrouded int, bounded bool) {
	if p.macIterations > maxKDFIterations {
		return 0, 0, false
	}
	base = p.macIterations
	for i := range results {
		res := &results[i]
		if res.encrypted {
			base += res.iterations
		}
		if res.shrouded > maxKDFIterations {
			return 0, 0, false
		}
		shrouded += res.shrouded
	}
	return base, shrouded, true
}

// bagCert is a certificate found in a SafeContents together with the bag
// attributes the scanner cares about.
type bagCert struct {
	raw        []byte
	alias      string
	localKeyID []byte
	fromKey    bool
}

// safeContentsResult is what could be read from one SafeContents of the
// AuthenticatedSafe.
type safeContentsResult struct {
	index      int
	encrypted  bool   // encryptedData (or envelopedData) rather than plain data
	algorithm  string // encryption algorithm, for messages
	iterations int    // KDF iterations of the encryption, 0 when unknown
	password   int    // index of the password that decrypted it, -1 otherwise
	shrouded   int    // KDF iterations of the shrouded private keys it holds
	err        error  // why the SafeContents could not be read, nil when it was
	certs      []bagCert
	problems   []error // certificates that could not be parsed
	bags       []safeBag
}

// describe names the SafeContents for error messages.
func (r *safeContentsResult) describe() string {
	switch {
	case r.encrypted && r.algorithm != "":
		return fmt.Sprintf("SafeContents #%d (encrypted, %s)", r.index, r.algorithm)
	case r.encrypted:
		return fmt.Sprintf("SafeContents #%d (encrypted)", r.index)
	}
	return fmt.Sprintf("SafeContents #%d", r.index)
}

// extract reads every SafeContents of the file, decrypting encrypted ones
// with the first password that works and charging every derivation to the
// budget. The password that opened one SafeContents is tried first on the
// next. It never fails as a whole: each result records its own error.
// opened is the index of the password that decrypted every encrypted
// SafeContents, or -1 when there is none or they could not all be opened
// with one password.
func (p *pfxFile) extract(passwords []string, budget *kdfBudget) (results []safeContentsResult, opened int) {
	results = make([]safeContentsResult, len(p.contents))
	preferred := -1
	for i, ci := range p.contents {
		res := &results[i]
		res.index, res.password = i, -1
		var plain []byte
		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &plain); err != nil {
				res.err = asn1Error("decoding data content", err)
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			res.encrypted = true
			ed, err := decodeEncryptedData(ci)
			if err != nil {
				res.err = err
				break
			}
			alg := ed.EncryptedContentInfo.ContentEncryptionAlgorithm
			res.algorithm = describeAlgorithm(alg)
			res.iterations, _ = kdfIterations(alg)
			if ed.Version != 0 {
				res.err = fmt.Errorf("unsupported EncryptedData version %d", ed.Version)
				break
			}
			res.bags, res.password, res.err = decryptSafeContents(ed.EncryptedContentInfo, passwords, preferred, budget)
			if res.err == nil {
				preferred = res.password
			}
			continue
		case ci.ContentType.Equal(oidEnvelopedDataContentType):
			res.encrypted = true
			res.algorithm = "envelopedData"
			res.err = errors.New("public-key privacy mode is not supported")
		default:
			res.err = fmt.Errorf("unsupported content type %s", ci.ContentType)
		}
		if res.err == nil {
			res.bags, res.err = parseSafeContents(plain)
		}
	}

	// Certificates that share a localKeyId with a key bag belong to that key's
	// entry; the attribute sits outside the (possibly shrouded) key, so it is
	// readable without a password.
	var keyIDs [][]byte
	for i := range results {
		res := &results[i]
		for _, bag := range res.bags {
			switch {
			case bag.ID.Equal(oidKeyBag):
			case bag.ID.Equal(oidPKCS8ShroudedKeyBag):
				res.shrouded += shroudedKeyIterations(bag.Value.Bytes)
			default:
				continue
			}
			if id := attributeOctets(bag.Attributes, oidLocalKeyID); id != nil {
				keyIDs = append(keyIDs, id)
			}
		}
	}
	for i := range results {
		res := &results[i]
		for j, bag := range res.bags {
			if !bag.ID.Equal(oidCertBag) {
				continue
			}
			raw, err := certBagDER(bag.Value.Bytes)
			if err != nil {
				res.problems = append(res.problems, fmt.Errorf("certificate bag %d: %w", j, err))
				continue
			}
			if raw == nil {
				continue // not an X.509 certificate
			}
			if _, err := x509.ParseCertificate(raw); err != nil {
				res.problems = append(res.problems, fmt.Errorf("certificate bag %d: %w", j, err))
				continue
			}
			c := bagCert{
				raw:        raw,
				alias:      attributeString(bag.Attributes, oidFriendlyName),
				localKeyID: attributeOctets(bag.Attributes, oidLocalKeyID),
			}
			for _, id := range keyIDs {
				if bytes.Equal(id, c.localKeyID) {
					c.fromKey = true
					break
				}
			}
			res.certs = append(res.certs, c)
		}
		res.bags = nil // no longer needed
	}

	opened = -1
	for i := range results {
		res := &results[i]
		switch {
		case !res.encrypted:
		case res.err != nil, opened >= 0 && res.password != opened:
			return results, -1
		default:
			opened = res.password
		}
	}
	return results, opened
}

// shroudedKeyIterations is the key-derivation work decrypting a shrouded
// private key would take, 0 when its parameters cannot be read.
func shroudedKeyIterations(value []byte) int {
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(value, &info); err != nil {
		return 0
	}
	n, _ := kdfIterations(info.Algorithm)
	return max(n, 0)
}

// parseSafeContents decodes a SafeContents (SEQUENCE OF SafeBag), flattening
// nested SafeContents bags.
func parseSafeContents(der []byte) ([]safeBag, error) {
	var bags []safeBag
	if _, err := asn1.Unmarshal(der, &bags); err != nil {
		return nil, asn1Error("decoding SafeContents", err)
	}
	return flattenBags(bags, 1), nil
}

func flattenBags(bags []safeBag, depth int) []safeBag {
	out := make([]safeBag, 0, len(bags))
	for _, bag := range bags {
		if !bag.ID.Equal(oidSafeContentsBag) {
			out = append(out, bag)
			continue
		}
		if depth >= maxSafeContentsNesting {
			continue
		}
		var nested []safeBag
		if _, err := asn1.Unmarshal(bag.Value.Bytes, &nested); err != nil {
			continue // a broken nested bag is skipped; its siblings are still read
		}
		out = append(out, flattenBags(nested, depth+1)...)
	}
	return out
}

// certBagDER returns the DER certificate held by a CertBag value, or nil when
// the bag holds a certificate of another type (e.g. SDSI).
func certBagDER(value []byte) ([]byte, error) {
	var bag certBag
	if _, err := asn1.Unmarshal(value, &bag); err != nil {
		return nil, asn1Error("decoding CertBag", err)
	}
	if !bag.ID.Equal(oidCertTypeX509) {
		return nil, nil
	}
	return bag.Data, nil
}

// attributeString returns the first value of a string-valued bag attribute
// (friendlyName is a BMPString; other string types are accepted leniently).
func attributeString(attrs []pkcs12Attribute, id asn1.ObjectIdentifier) string {
	for _, a := range attrs {
		if !a.ID.Equal(id) {
			continue
		}
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(a.Value.Bytes, &v); err != nil || v.Class != asn1.ClassUniversal {
			return ""
		}
		switch v.Tag {
		case asn1.TagBMPString:
			return decodeBMPString(v.Bytes)
		case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
			return string(v.Bytes)
		}
		return ""
	}
	return ""
}

// attributeOctets returns the first value of an OCTET STRING bag attribute.
func attributeOctets(attrs []pkcs12Attribute, id asn1.ObjectIdentifier) []byte {
	for _, a := range attrs {
		if !a.ID.Equal(id) {
			continue
		}
		var v []byte
		if _, err := asn1.Unmarshal(a.Value.Bytes, &v); err != nil {
			return nil
		}
		return v
	}
	return nil
}

// decodeBMPString decodes a UCS-2/UTF-16BE string; an odd trailing byte is
// dropped.
func decodeBMPString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return string(utf16.Decode(u))
}

// certInfo is what the structural walk learnt about one certificate.
type certInfo struct {
	alias     string
	encrypted bool
}

// catalogue indexes the certificates found by extract by their DER bytes. A
// certificate present both in an unencrypted and in an encrypted SafeContents
// counts as unencrypted, since it can be read without a password.
func catalogue(results []safeContentsResult) map[string]certInfo {
	out := make(map[string]certInfo)
	for _, res := range results {
		for _, c := range res.certs {
			key := string(c.raw)
			if prev, ok := out[key]; ok && !prev.encrypted {
				continue
			}
			out[key] = certInfo{alias: c.alias, encrypted: res.encrypted}
		}
	}
	return out
}

// entries turns the structural walk's results into entries and one error
// line describing the parts that could not be read: a budget or limit
// refusal (ErrTooExpensive), a password failure, or a structural problem.
// refused is the reason the budget was withheld up front, if it was.
func (p *pfxFile) entries(results []safeContentsResult, passwords int, refused error) ([]Entry, error) {
	var (
		entries   []Entry
		expensive []string // parts refused for their key-derivation cost
		locked    []string // parts no password opened
		broken    []string // parts and certificates with structural problems
	)
	for i := range results {
		res := &results[i]
		for _, c := range res.certs {
			entries = append(entries, Entry{
				Alias:        c.alias,
				Raw:          bytes.Clone(c.raw),
				FromKeyEntry: c.fromKey,
				Encrypted:    res.encrypted,
			})
		}
		if err := res.err; err != nil {
			msg := res.describe() + " could not be read: " + err.Error()
			switch {
			case errors.Is(err, errBudget), errors.Is(err, errLimits):
				expensive = append(expensive, msg)
			case errors.Is(err, errIncorrectPassword), errors.Is(err, errNoPassword):
				locked = append(locked, msg)
			default:
				broken = append(broken, msg)
			}
		}
		for _, perr := range res.problems {
			broken = append(broken, res.describe()+": "+perr.Error())
		}
	}
	var head error
	switch {
	case refused != nil:
		head = refused
	case len(expensive) > 0:
		head = fmt.Errorf("%w (%d iterations requested)", ErrTooExpensive, p.demands().requested)
	case len(locked) > 0 && passwords == 0:
		head = errors.New("keystore: pkcs12: no passwords were supplied for the encrypted parts")
	case len(locked) > 0:
		head = fmt.Errorf("keystore: pkcs12: none of the %d supplied passwords opened the file", passwords)
	case len(broken) > 0:
		head = errors.New("keystore: pkcs12: parts of the file could not be read")
	default:
		return entries, nil
	}
	details := append(append(expensive, locked...), broken...)
	return entries, fmt.Errorf("%w: %s", head, listProblems(details))
}

// listProblems joins problem descriptions into one line, naming at most
// maxProblemsListed of them.
func listProblems(problems []string) string {
	if len(problems) <= maxProblemsListed {
		return strings.Join(problems, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(problems[:maxProblemsListed], "; "), len(problems)-maxProblemsListed)
}

// The structural errors of encoding/asn1 embed the raw field description
// ("{class:0 tag:16 length:1530 isCompound:true}") and the whole parameter
// dump of the field ("{optional:false explicit:false ...}").
var (
	asn1FieldDump = regexp.MustCompile(`\{class:(\d+) tag:(\d+) [^}]*\}`)
	asn1ParamDump = regexp.MustCompile(`\s*\{optional:[^}]*\}`)
)

// asn1Error wraps an encoding/asn1 error for a message, reducing the
// structural errors' field dumps to the class and tag they name.
func asn1Error(context string, err error) error {
	var structural asn1.StructuralError
	if errors.As(err, &structural) {
		msg := asn1ParamDump.ReplaceAllString(structural.Msg, "")
		msg = asn1FieldDump.ReplaceAllString(msg, "class $1 tag $2")
		return fmt.Errorf("%s: asn1: structure error: %s", context, strings.Join(strings.Fields(msg), " "))
	}
	return fmt.Errorf("%s: %w", context, err)
}

// describeAlgorithm names a content-encryption algorithm for messages.
func describeAlgorithm(alg pkix.AlgorithmIdentifier) string {
	if alg.Algorithm.Equal(oidPBES2) {
		var params pbes2Params
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err == nil {
			return "PBES2 with " + oidName(params.EncryptionScheme.Algorithm)
		}
		return "PBES2"
	}
	return oidName(alg.Algorithm)
}

var oidNames = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{oidPBEWithSHAAnd3KeyTripleDESCBC, "pbeWithSHA1And3-KeyTripleDES-CBC"},
	{oidPBEWithSHAAnd2KeyTripleDESCBC, "pbeWithSHA1And2-KeyTripleDES-CBC"},
	{oidPBEWithSHAAnd128BitRC2CBC, "pbeWithSHA1And128BitRC2-CBC"},
	{oidPBEWithSHAAnd40BitRC2CBC, "pbeWithSHA1And40BitRC2-CBC"},
	{oidPBEWithSHAAnd128BitRC4, "pbeWithSHA1And128BitRC4"},
	{oidPBEWithSHAAnd40BitRC4, "pbeWithSHA1And40BitRC4"},
	{oidAES128CBC, "AES-128-CBC"},
	{oidAES192CBC, "AES-192-CBC"},
	{oidAES256CBC, "AES-256-CBC"},
	{oidDESEDE3CBC, "DES-EDE3-CBC"},
}

func oidName(oid asn1.ObjectIdentifier) string {
	for _, n := range oidNames {
		if n.oid.Equal(oid) {
			return n.name
		}
	}
	return oid.String()
}

// isPKCS12PBE reports whether oid is one of the RFC 7292 appendix C
// password-based encryption schemes.
func isPKCS12PBE(oid asn1.ObjectIdentifier) bool {
	for _, o := range []asn1.ObjectIdentifier{
		oidPBEWithSHAAnd128BitRC4, oidPBEWithSHAAnd40BitRC4,
		oidPBEWithSHAAnd3KeyTripleDESCBC, oidPBEWithSHAAnd2KeyTripleDESCBC,
		oidPBEWithSHAAnd128BitRC2CBC, oidPBEWithSHAAnd40BitRC2CBC,
	} {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}
