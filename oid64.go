package asn1oid64

import (
	encoding_asn1 "encoding/asn1"
	"math"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ReadASN1ObjectIdentifier decodes an ASN.1 OBJECT IDENTIFIER into out and
// advances. It reports whether the read was successful.
func ReadASN1ObjectIdentifier(s *cryptobyte.String, out *encoding_asn1.ObjectIdentifier) bool {
	var bytes cryptobyte.String
	if !s.ReadASN1(&bytes, asn1.OBJECT_IDENTIFIER) || len(bytes) == 0 {
		return false
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	components := make([]int, len(bytes)+1)

	// The first varint is 40*value1 + value2:
	// According to this packing, value1 can take the values 0, 1 and 2 only.
	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
	// then there are no restrictions on value2.
	var v int
	if !readBase128Int(&bytes, &v) {
		return false
	}
	if v < 80 {
		components[0] = v / 40
		components[1] = v % 40
	} else {
		components[0] = 2
		components[1] = v - 80
	}

	i := 2
	for ; len(bytes) > 0; i++ {
		if !readBase128Int(&bytes, &v) {
			return false
		}
		components[i] = v
	}
	*out = components[:i]
	return true
}

func readBase128Int(s *cryptobyte.String, out *int) bool {
	ret := 0
	for i := 0; len(*s) > 0; i++ {
		if ret > math.MaxInt>>7 {
			return false
		}
		// if i == 5 {
		// 	return false
		// }
		// // Avoid overflowing int on a 32-bit platform.
		// // We don't want different behavior based on the architecture.
		// if ret >= 1<<(31-7) {
		// 	return false
		// }
		ret <<= 7
		b := read(s, 1)[0]
		ret |= int(b & 0x7f)
		if b&0x80 == 0 {
			*out = ret
			return true
		}
	}
	return false // truncated
}

func read(s *cryptobyte.String, n int) []byte {
	if len(*s) < n || n < 0 {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}
