package asn1oid64_test

import (
	"bytes"
	encoding_asn1 "encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/AlexanderYastrebov/asn1oid64"
)

func TestASN1ObjectIdentifier(t *testing.T) {
	testData := []struct {
		in  []byte
		ok  bool
		out []int
	}{
		{[]byte{}, false, []int{}},
		{[]byte{6, 0}, false, []int{}},
		{[]byte{5, 1, 85}, false, []int{2, 5}},
		{[]byte{6, 1, 85}, true, []int{2, 5}},
		{[]byte{6, 2, 85, 0x02}, true, []int{2, 5, 2}},
		{[]byte{6, 4, 85, 0x02, 0xc0, 0x00}, true, []int{2, 5, 2, 0x2000}},
		{[]byte{6, 3, 0x81, 0x34, 0x03}, true, []int{2, 100, 3}},
		{[]byte{6, 7, 85, 0x02, 0xc0, 0x80, 0x80, 0x80, 0x80}, false, []int{}},
		{[]byte{6, 7, 85, 0x02, 0x85, 0xc7, 0xcc, 0xfb, 0x01}, true, []int{2, 5, 2, 1492336001}},
		{[]byte{6, 7, 0x55, 0x02, 0x87, 0xff, 0xff, 0xff, 0x7f}, true, []int{2, 5, 2, 2147483647}},                                        // 2**31-1
		{[]byte{6, 7, 0x55, 0x02, 0x88, 0x80, 0x80, 0x80, 0x00}, true, []int{2, 5, 2, 2147483648}},                                        // 2**31
		{[]byte{6, 11, 0x2a, 0x24, 0xcb, 0x89, 0x90, 0x82, 0x1e, 0x03, 0x01, 0x01, 0x01}, true, []int{1, 2, 36, 20151795998, 3, 1, 1, 1}}, // https://github.com/golang/go/issues/58821
		{[]byte{6, 11, 0x55, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, true, []int{2, 5, 2, 9223372036854775807}},      // 2**63-1
		{[]byte{0, 12, 0x55, 0x02, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, false, []int{}},                           // 2**63
	}

	for i, test := range testData {
		in := cryptobyte.String(test.in)
		var out encoding_asn1.ObjectIdentifier
		ok := asn1oid64.ReadASN1ObjectIdentifier(&in, &out)
		if ok != test.ok || ok && !out.Equal(test.out) {
			t.Errorf("#%d: in.ReadASN1ObjectIdentifier() = %v, want %v; out = %v, want %v", i, ok, test.ok, out, test.out)
			continue
		}

		var b cryptobyte.Builder
		b.AddASN1ObjectIdentifier(out)
		result, err := b.Bytes()
		if builderOk := err == nil; test.ok != builderOk {
			t.Errorf("#%d: error from Builder.Bytes: %s", i, err)
			continue
		}
		if test.ok && !bytes.Equal(result, test.in) {
			t.Errorf("#%d: reserialisation didn't match, got %x, want %x", i, result, test.in)
			continue
		}
	}
}
