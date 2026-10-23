package certs

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/keystore"
)

// Scan window geometry. A file is read in windows of windowSize bytes that
// overlap by overlap bytes, so any object shorter than overlap-labelContext
// bytes is seen whole exactly once, whichever window boundary it straddles.
// A longer object is completed by restarting the next window at its start
// and growing the window: up to Options.MaxBuffer for a DER certificate
// candidate, up to maxPEMBlock for a PEM block. Tests shrink these to
// exercise the boundary logic.
var (
	windowSize = 1 << 20
	overlap    = 64 << 10
)

// maxPEMBlock bounds the growth of the window around a PEM block whose END
// marker lies beyond the buffer, whatever Options.MaxBuffer allows. No real
// PEM object comes near it (a PKCS7 bundle of a whole root store is a few
// hundred KiB), so a block still unfinished at this size is a stray marker
// that happens to begin like a block; it is skipped with a warning rather
// than buffered up to MaxBuffer for nothing.
const maxPEMBlock = 8 << 20

// sniffSize is how much of a file's head is examined for the markers of the
// whole-file text formats; a marker deeper inside a file is a mention, not a
// format.
const sniffSize = 8 << 10

// windowPool recycles full-size scan windows.
var windowPool = sync.Pool{New: func() any { b := make([]byte, windowSize); return &b }}

// pkcs7SignedData is the OID 1.2.840.113549.1.7.2 that opens a DER PKCS#7
// bundle (.p7b/.p7c).
var pkcs7SignedData = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}

// certdataMarkers are the first attribute line of every certdata.txt object,
// with its fields separated by a space or a tab.
var certdataMarkers = [][]byte{[]byte("CKA_CLASS CK_OBJECT_CLASS"), []byte("CKA_CLASS\tCK_OBJECT_CLASS")}

// isCertdata reports whether head holds the first line of a certdata.txt object.
func isCertdata(head []byte) bool {
	for _, m := range certdataMarkers {
		if bytes.Contains(head, m) {
			return true
		}
	}
	return false
}

// scanner holds the state of one Scan call.
type scanner struct {
	path     string
	opts     Options
	patterns *patternSet
	derKind  Kind
	// coveredUntil is the absolute end offset of the last object reported,
	// so that nothing is reported from inside it in a later window.
	coveredUntil int64
}

func (s *scanner) maxBuffer() int64 {
	if s.opts.MaxBuffer > 0 {
		return s.opts.MaxBuffer
	}
	return DefaultMaxBuffer
}

func (s *scanner) warn(msg string) {
	if s.opts.Warn != nil {
		s.opts.Warn(msg)
	}
}

// wholeKind is a format that must be parsed from the complete file.
type wholeKind int

const (
	wholeNone wholeKind = iota
	wholeJKS
	wholePKCS12
	wholeCertdata
	wholeP11Kit
)

// sniff decides from the first bytes of a file whether it needs whole-file
// parsing, and which carving kind applies to DER certificates in it. Only
// the first sniffSize bytes are examined.
func sniff(head []byte) (wholeKind, Kind) {
	head = head[:min(len(head), sniffSize)]
	switch {
	case keystore.IsJKS(head):
		return wholeJKS, KindDER
	case keystore.LooksLikePKCS12(head):
		return wholePKCS12, KindDER
	case bytes.Contains(head, p11kitHeader):
		return wholeP11Kit, KindDER
	case isCertdata(head):
		return wholeCertdata, KindDER
	}
	if len(head) > 2 && head[0] == 0x30 && bytes.Index(head[:min(len(head), 24)], pkcs7SignedData) > 0 {
		return wholeNone, KindPKCS7
	}
	return wholeNone, KindDER
}

// getWindow returns a pooled buffer of exactly windowSize bytes and the
// function that returns it to the pool. The capacity is cut to windowSize
// as well: the window slide reads up to cap(buf), and a pooled buffer that
// is larger (after a test shrank windowSize) must not widen the window.
func getWindow() ([]byte, func()) {
	pooled := windowPool.Get().(*[]byte)
	if cap(*pooled) < windowSize {
		b := make([]byte, windowSize)
		pooled = &b
	}
	return (*pooled)[:windowSize:windowSize], func() { windowPool.Put(pooled) }
}

// fill reads as much of buf as the reader provides and reports whether the
// end of the data was reached.
func fill(r io.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(r, buf)
	switch err {
	case nil:
		return n, false, nil
	case io.EOF, io.ErrUnexpectedEOF:
		return n, true, nil
	}
	return n, false, err
}

// run reads the file and dispatches to the whole-file or streaming scanner.
func (s *scanner) run(r io.Reader, size int64) ([]Found, error) {
	// First window. Small files get an exact-size buffer (one byte longer
	// than their declared size, so that a longer file is noticed);
	// everything else uses a pooled full-size window.
	var buf []byte
	if size >= 0 && size+1 < int64(windowSize) {
		buf = make([]byte, size+1)
	} else {
		var release func()
		buf, release = getWindow()
		defer release()
	}
	n, eof, err := fill(r, buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	if n == 0 {
		return nil, nil
	}

	kind, derKind := sniff(buf)
	s.derKind = derKind
	if kind != wholeNone {
		data, err := s.readWhole(buf, eof, r, size)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > s.maxBuffer() {
			s.warn("file is larger than the whole-file parser limit; only carving it for DER certificates")
			return s.streamAll(io.MultiReader(bytes.NewReader(data), r))
		}
		found := s.whole(kind, data)
		if len(found) == 0 && (kind == wholeCertdata || kind == wholeP11Kit) {
			// A file that merely mentions the marker: scan it like any other.
			return s.stream(data, true, nil)
		}
		return found, nil
	}
	if !eof && cap(buf) < windowSize {
		// Longer than its declared size: start over with a full window.
		return s.streamAll(io.MultiReader(bytes.NewReader(buf), r))
	}
	return s.stream(buf, eof, r)
}

// readWhole returns the complete file for a whole-file parser: the first
// window when it already holds everything, otherwise one buffer allocated
// for the declared size and bounded by MaxBuffer+1, so that a larger file is
// recognised (by its length) without being read in full.
func (s *scanner) readWhole(buf []byte, eof bool, r io.Reader, size int64) ([]byte, error) {
	if eof {
		return buf, nil
	}
	limit := s.maxBuffer() + 1
	capacity := limit
	if size >= 0 && size+1 < limit {
		capacity = size + 1
	}
	capacity = max(capacity, int64(len(buf))+1)
	data := make([]byte, len(buf), capacity)
	copy(data, buf)
	for {
		n, err := io.ReadFull(r, data[len(data):cap(data)])
		data = data[:len(data)+n]
		switch err {
		case io.EOF, io.ErrUnexpectedEOF:
			return data, nil
		case nil:
		default:
			return nil, err
		}
		if int64(len(data)) >= limit {
			return data, nil
		}
		// Longer than declared: read on, up to the limit.
		grown := make([]byte, len(data), limit)
		copy(grown, data)
		data = grown
	}
}

// streamAll runs the streaming scanner over r from its beginning.
func (s *scanner) streamAll(r io.Reader) ([]Found, error) {
	buf, release := getWindow()
	defer release()
	n, eof, err := fill(r, buf)
	if err != nil {
		return nil, err
	}
	return s.stream(buf[:n], eof, r)
}

// whole parses a complete file of a known container format.
func (s *scanner) whole(kind wholeKind, data []byte) []Found {
	switch kind {
	case wholeJKS:
		return scanJKS(data, s.warn)
	case wholePKCS12:
		return scanPKCS12(data, s.opts.KeystorePasswords, s.warn)
	case wholeCertdata:
		return ParseCertdata(data)
	case wholeP11Kit:
		sections := parseP11Kit(data)
		found := p11Found(sections)
		if s.patterns != nil {
			// x-certificate-extension objects repeat the public key of the
			// certificate they belong to; such keys are reported once, as
			// the certificate.
			var keys [][]byte
			for _, f := range found {
				keys = append(keys, f.Certificate.RawSubjectPublicKeyInfo)
			}
			for _, sec := range sections {
				for _, b := range sec.blocks {
					if isCertificateType(b.block.Type) {
						continue
					}
					for _, hit := range s.patternsInBlock(b, sec.attrs["label"], 0) {
						if !keyPresent(keys, hit.Raw) {
							found = append(found, hit)
						}
					}
				}
			}
		}
		sort.SliceStable(found, func(i, j int) bool { return found[i].Offset < found[j].Offset })
		return found
	}
	return nil
}

// stream scans the file window by window. buf holds the first window; it is
// reused (and must be at least windowSize long when eof is false).
func (s *scanner) stream(buf []byte, eof bool, r io.Reader) ([]Found, error) {
	var out []Found
	var base, searchFrom int64 // absolute offsets of buf[0] and of the next search
	for {
		limit := len(buf)
		if !eof {
			limit = max(len(buf)-overlap+labelContext, 0)
		}
		found, p := s.window(buf, base, int(searchFrom-base), limit)
		out = append(out, found...)
		if eof {
			return out, nil
		}

		// The next window starts at the limit, behind anything already
		// reported. An object that starts before the limit but runs past the
		// buffer is retried from its start: the window is moved up to it
		// and grown, up to the object's limit, so that the object fits.
		next, ceiling := base+int64(limit), int64(cap(buf))
		if p.offset >= 0 && p.offset < next {
			if ceiling < p.limit || p.offset-base > labelContext {
				next, ceiling = p.offset, max(ceiling, p.limit)
			} else {
				s.warn(p.skipped())
			}
		}
		searchFrom = max(next, s.coveredUntil)

		// Slide: keep everything from labelContext before the next search
		// on, then read the next chunk after it.
		keepFrom := min(max(int(searchFrom-base)-labelContext, 0), len(buf))
		keep := len(buf) - keepFrom
		copy(buf, buf[keepFrom:])
		buf = buf[:keep]
		base += int64(keepFrom)
		if room := windowSize - overlap; keep+room > cap(buf) {
			if newCap := min(max(2*cap(buf), keep+room), int(ceiling)); newCap > cap(buf) {
				grown := make([]byte, keep, newCap)
				copy(grown, buf)
				buf = grown
			}
		}
		full := buf[:cap(buf)]
		n, err := io.ReadFull(r, full[keep:])
		buf = full[:keep+n]
		switch err {
		case nil:
		case io.EOF, io.ErrUnexpectedEOF:
			eof = true
		default:
			return out, err
		}
	}
}

// pending is an object that starts in the scanned range of a window but
// runs past the end of its buffer: it may be completed by moving the window
// to its start and growing the buffer, up to limit.
type pending struct {
	offset int64  // absolute offset of the object, or -1 for none
	limit  int64  // how large the buffer may become to hold it
	label  string // the PEM block type; empty for a DER candidate
}

// skipped is the warning for an object that did not fit within its limit.
func (p pending) skipped() string {
	if p.label != "" {
		return fmt.Sprintf("PEM %s block at offset %d has no END marker within %s and was skipped", p.label, p.offset, sizeString(p.limit))
	}
	return fmt.Sprintf("object at offset %d is longer than the buffer limit of %d bytes and was skipped", p.offset, p.limit)
}

// sizeString formats a byte count in whole MiB or KiB when it is one.
func sizeString(n int64) string {
	switch {
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// window scans one window: PEM blocks and DER certificates whose first byte
// lies in [from, limit), and public-key patterns that are not inside a
// certificate. The pending result is the first object that starts in the
// window but runs past the end of buf: a PEM block that begins like a real
// one (which may grow the window up to maxPEMBlock) or a DER certificate
// candidate (up to MaxBuffer; its length field bounds it anyway).
func (s *scanner) window(buf []byte, base int64, from, limit int) ([]Found, pending) {
	var out []Found
	if from < 0 {
		from = 0
	}
	pemPending, pemLabel := eachPEM(buf, from, limit, func(b pemBlock) bool {
		found := pemFound(buf, b, base, s.warn)
		if len(found) == 0 && s.patterns != nil && !isCertificateType(b.block.Type) {
			found = s.patternsInBlock(b, "", base)
		}
		out = append(out, found...)
		s.cover(base + int64(b.end))
		return true
	})

	type span struct{ lo, hi int64 }
	var certSpans []span
	carved, derPending := carveDER(buf, from, limit, base, s.derKind)
	for _, f := range carved {
		certSpans = append(certSpans, span{f.Offset, f.Offset + int64(len(f.Raw))})
		s.cover(f.Offset + int64(len(f.Raw)))
		out = append(out, f)
	}

	if s.patterns != nil {
		s.patterns.find(buf, from, limit, func(off int, p SPKIPattern) {
			abs := base + int64(off)
			for _, sp := range certSpans {
				if abs >= sp.lo && abs < sp.hi {
					return
				}
			}
			out = append(out, Found{Raw: bytes.Clone(p.Pattern), Kind: KindSPKI, Offset: abs, PatternID: p.ID})
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })

	p := pending{offset: -1}
	if derPending >= 0 {
		p = pending{offset: base + int64(derPending), limit: s.maxBuffer()}
	}
	if pemPending >= 0 && (p.offset < 0 || base+int64(pemPending) < p.offset) {
		p = pending{offset: base + int64(pemPending), limit: min(s.maxBuffer(), maxPEMBlock), label: pemLabel}
	}
	return out, p
}

// keyPresent reports whether pattern occurs inside one of the keys.
func keyPresent(keys [][]byte, pattern []byte) bool {
	for _, k := range keys {
		if bytes.Contains(k, pattern) {
			return true
		}
	}
	return false
}

func (s *scanner) cover(end int64) {
	if end > s.coveredUntil {
		s.coveredUntil = end
	}
}

// patternsInBlock matches the decoded bytes of a non-certificate PEM block
// (PUBLIC KEY and friends) against the patterns.
func (s *scanner) patternsInBlock(b pemBlock, label string, base int64) []Found {
	var out []Found
	s.patterns.find(b.block.Bytes, 0, len(b.block.Bytes), func(_ int, p SPKIPattern) {
		out = append(out, Found{Raw: bytes.Clone(p.Pattern), Kind: KindSPKI, Offset: base + int64(b.start), Label: label, PatternID: p.ID})
	})
	return out
}

// patternSet groups patterns by a common prefix so that one index search per
// group finds the candidates for all of them.
type patternSet struct {
	groups []patternGroup
}

type patternGroup struct {
	prefix []byte
	pats   []SPKIPattern
}

const patternPrefixLen = 16

func newPatternSet(pats []SPKIPattern) *patternSet {
	var ps patternSet
	index := map[string]int{}
	for _, p := range pats {
		if len(p.Pattern) == 0 {
			continue
		}
		n := min(patternPrefixLen, len(p.Pattern))
		key := string(p.Pattern[:n])
		i, ok := index[key]
		if !ok {
			i = len(ps.groups)
			index[key] = i
			ps.groups = append(ps.groups, patternGroup{prefix: bytes.Clone(p.Pattern[:n])})
		}
		ps.groups[i].pats = append(ps.groups[i].pats, p)
	}
	if len(ps.groups) == 0 {
		return nil
	}
	return &ps
}

// find reports every pattern occurrence starting in [from, limit).
func (ps *patternSet) find(data []byte, from, limit int, fn func(off int, p SPKIPattern)) {
	if from < 0 {
		from = 0
	}
	if limit > len(data) {
		limit = len(data)
	}
	for _, g := range ps.groups {
		for i := from; i < limit; {
			j := bytes.Index(data[i:], g.prefix)
			if j < 0 {
				break
			}
			i += j
			if i >= limit {
				break
			}
			for _, p := range g.pats {
				if bytes.HasPrefix(data[i:], p.Pattern) {
					fn(i, p)
					break
				}
			}
			i++
		}
	}
}
