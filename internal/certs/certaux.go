package certs

import (
	"sort"
	"strings"
)

// oidAnyExtendedKeyUsage is 2.5.29.37.0; rejecting it distrusts a
// certificate for every purpose, trusting it anchors every purpose.
const oidAnyExtendedKeyUsage = "2.5.29.37.0"

// purposeNames maps the OIDs OpenSSL and p11-kit use in trust settings to
// the names printed by "openssl x509 -text".
var purposeNames = map[string]string{
	"1.3.6.1.5.5.7.3.1":      "serverAuth",
	"1.3.6.1.5.5.7.3.2":      "clientAuth",
	"1.3.6.1.5.5.7.3.3":      "codeSigning",
	"1.3.6.1.5.5.7.3.4":      "emailProtection",
	"1.3.6.1.5.5.7.3.5":      "ipsecEndSystem",
	"1.3.6.1.5.5.7.3.6":      "ipsecTunnel",
	"1.3.6.1.5.5.7.3.7":      "ipsecUser",
	"1.3.6.1.5.5.7.3.8":      "timeStamping",
	"1.3.6.1.5.5.7.3.9":      "OCSPSigning",
	"1.3.6.1.5.5.7.3.17":     "ipsecIKE",
	"1.3.6.1.5.5.8.2.2":      "ipsecIKEIntermediate",
	"1.3.6.1.4.1.311.10.3.3": "msSGC",
	"2.16.840.1.113730.4.1":  "nsSGC",
	"1.3.6.1.5.5.7.3.0":      "anyPurpose",
	oidAnyExtendedKeyUsage:   "anyExtendedKeyUsage",
}

func purposeName(oid string) string {
	if n, ok := purposeNames[oid]; ok {
		return n
	}
	return oid
}

// CertAux is the decoded trust trailer of an OpenSSL TRUSTED CERTIFICATE.
type CertAux struct {
	// Trust summarises Purposes the way Found.Trust does; TrustUnknown when
	// the trailer carries neither trust nor reject settings.
	Trust TrustState
	// Purposes is the outcome of OpenSSL's trust evaluation for each standard
	// purpose; nil when the trailer carries no settings.
	Purposes map[Purpose]TrustState
	// Detail lists the trust and reject settings by name, for example
	// "trust: serverAuth; reject: emailProtection".
	Detail string
	// Alias is the trailer's alias, if any.
	Alias string
}

// DecodeCertAux parses the OpenSSL CertAux structure that follows the
// certificate inside a TRUSTED CERTIFICATE block:
//
//	CertAux ::= SEQUENCE {
//	    trust   SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//	    reject  [0] SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//	    alias   UTF8String OPTIONAL,
//	    keyid   OCTET STRING OPTIONAL,
//	    other   [1] SEQUENCE OF AlgorithmIdentifier OPTIONAL }
//
// Purposes follow OpenSSL's obj_trust: the reject list is consulted first, and
// a rejected purpose (or anyExtendedKeyUsage) is distrusted; with an explicit
// trust list, listed purposes (or every purpose, for anyExtendedKeyUsage) are
// anchors and unlisted ones are distrusted; without a trust list the
// remaining purposes are neutral. ok is false when aux is not a CertAux.
func DecodeCertAux(aux []byte) (CertAux, bool) {
	outer, _, good := readTLV(aux)
	if !good || !outer.isSequence() {
		return CertAux{}, false
	}
	rest := outer.value
	var trusted, rejected []string
	var alias string
	seen := map[string]bool{}
	for len(rest) > 0 {
		t, after, good := readTLV(rest)
		if !good {
			return CertAux{}, false
		}
		rest = after
		switch {
		case t.class == 0 && t.isSequence() && !seen["trust"]:
			seen["trust"] = true
			oids, good := oidList(t.value)
			if !good {
				return CertAux{}, false
			}
			trusted = oids
		case t.class == 2 && t.tag == 0 && t.compound && !seen["reject"]:
			seen["reject"] = true
			oids, good := oidList(t.value)
			if !good {
				return CertAux{}, false
			}
			rejected = oids
		case t.class == 0 && t.tag == 12 && !t.compound && !seen["alias"]: // UTF8String
			seen["alias"] = true
			alias = string(t.value)
		case t.class == 0 && t.tag == 4 && !t.compound && !seen["keyid"]: // OCTET STRING
			seen["keyid"] = true
		case t.class == 2 && t.tag == 1 && t.compound && !seen["other"]:
			seen["other"] = true
		default:
			return CertAux{}, false
		}
	}
	ca := CertAux{Alias: alias}
	if len(trusted) == 0 && len(rejected) == 0 {
		ca.Detail = "no trust settings (treated like a plain certificate)"
		return ca, true
	}
	var parts []string
	if len(trusted) > 0 {
		parts = append(parts, "trust: "+strings.Join(names(trusted), ", "))
	}
	if len(rejected) > 0 {
		parts = append(parts, "reject: "+strings.Join(names(rejected), ", "))
	}
	ca.Detail = strings.Join(parts, "; ")
	ca.Purposes = certAuxPurposes(trusted, rejected)
	ca.Trust = summariseTrust(ca.Purposes, contains(rejected, oidAnyExtendedKeyUsage) || rejectsAllStandard(rejected))
	return ca, true
}

// ParseCertAux is DecodeCertAux reduced to the overall verdict, its
// description and the alias.
func ParseCertAux(aux []byte) (trust TrustState, detail string, alias string, ok bool) {
	ca, ok := DecodeCertAux(aux)
	return ca.Trust, ca.Detail, ca.Alias, ok
}

// certAuxPurposes evaluates trust and reject lists per standard purpose the
// way OpenSSL's obj_trust does.
func certAuxPurposes(trusted, rejected []string) map[Purpose]TrustState {
	rejectAll := contains(rejected, oidAnyExtendedKeyUsage)
	trustAll := contains(trusted, oidAnyExtendedKeyUsage)
	out := make(map[Purpose]TrustState, len(standardPurposes))
	for oid, p := range purposeOIDs {
		switch {
		case rejectAll, contains(rejected, oid):
			out[p] = TrustDistrusted
		case trustAll, contains(trusted, oid):
			out[p] = TrustAnchor
		case len(trusted) > 0:
			out[p] = TrustDistrusted // absent from an explicit trust list
		default:
			out[p] = TrustNeutral
		}
	}
	return out
}

// rejectsAllStandard reports whether a reject list names every standard
// purpose, which is how p11-kit's bundle writer distrusts a certificate.
func rejectsAllStandard(rejected []string) bool {
	for oid := range purposeOIDs {
		if !contains(rejected, oid) {
			return false
		}
	}
	return true
}

// oidList decodes a SEQUENCE OF OBJECT IDENTIFIER body.
func oidList(b []byte) ([]string, bool) {
	var out []string
	for len(b) > 0 {
		t, rest, ok := readTLV(b)
		if !ok || t.class != 0 || t.tag != 6 || t.compound {
			return nil, false
		}
		s := oidString(t.value)
		if s == "" {
			return nil, false
		}
		out = append(out, s)
		b = rest
	}
	return out, true
}

func names(oids []string) []string {
	out := make([]string, 0, len(oids))
	for _, o := range oids {
		out = append(out, purposeName(o))
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
