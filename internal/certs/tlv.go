package certs

// tlv is one BER/DER tag-length-value element.
type tlv struct {
	class    byte // 0 universal, 1 application, 2 context-specific, 3 private
	tag      int
	compound bool
	value    []byte
	raw      []byte // header and value
}

// readTLV parses the element at the start of b and returns it together with
// the bytes that follow it. Only definite lengths of up to four bytes are
// accepted (DER); indefinite lengths yield ok=false.
func readTLV(b []byte) (t tlv, rest []byte, ok bool) {
	if len(b) < 2 {
		return t, nil, false
	}
	t.class = b[0] >> 6
	t.compound = b[0]&0x20 != 0
	t.tag = int(b[0] & 0x1f)
	p := 1
	if t.tag == 0x1f {
		t.tag = 0
		for {
			if p >= len(b) || p > 5 {
				return t, nil, false
			}
			c := b[p]
			p++
			t.tag = t.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if p >= len(b) {
		return t, nil, false
	}
	n := int(b[p])
	p++
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < p+k {
			return t, nil, false
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(b[p+i])
		}
		p += k
	}
	if n < 0 || len(b)-p < n {
		return t, nil, false
	}
	t.value = b[p : p+n]
	t.raw = b[:p+n]
	return t, b[p+n:], true
}

// isSequence reports whether t is a universal SEQUENCE.
func (t tlv) isSequence() bool { return t.class == 0 && t.compound && t.tag == 16 }

// derTotalLength returns the length, header included, of the first DER
// element in b.
func derTotalLength(b []byte) (int, bool) {
	t, _, ok := readTLV(b)
	if !ok {
		return 0, false
	}
	return len(t.raw), true
}

// oidString formats the contents of an OBJECT IDENTIFIER as dotted decimal.
func oidString(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	var out []byte
	var acc uint64
	first := true
	for _, c := range v {
		acc = acc<<7 | uint64(c&0x7f)
		if acc > 1<<56 {
			return ""
		}
		if c&0x80 != 0 {
			continue
		}
		if first {
			first = false
			a, b := acc/40, acc%40
			if acc >= 80 {
				a, b = 2, acc-80
			}
			out = appendUint(out, a)
			out = append(out, '.')
			out = appendUint(out, b)
		} else {
			out = append(out, '.')
			out = appendUint(out, acc)
		}
		acc = 0
	}
	if acc != 0 {
		return "" // truncated sub-identifier
	}
	return string(out)
}

func appendUint(b []byte, v uint64) []byte {
	if v == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(b, tmp[i:]...)
}
