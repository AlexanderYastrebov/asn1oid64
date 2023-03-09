package asn1oid64_test

import (
	encoding_asn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/AlexanderYastrebov/asn1oid64"
)

func ExampleReadASN1ObjectIdentifier() {
	encoded, err := encoding_asn1.Marshal(encoding_asn1.ObjectIdentifier([]int{2, 5, 2, 9223372036854775807}))
	if err != nil {
		panic(err)
	}

	in := cryptobyte.String(encoded)

	var out encoding_asn1.ObjectIdentifier
	ok := asn1oid64.ReadASN1ObjectIdentifier(&in, &out)

	fmt.Printf("%s %t", out, ok)

	// Output:
	// 2.5.2.9223372036854775807 true
}
