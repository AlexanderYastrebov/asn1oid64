# Read 64bit ASN1 ObjectIdentifier

This is a fork of `golang.org/x/crypto/cryptobyte` [String.ReadASN1ObjectIdentifier](https://pkg.go.dev/golang.org/x/crypto/cryptobyte#String.ReadASN1ObjectIdentifier) that supports 64 bit identifiers.

See
* [example_test.go](example_test.go)
* https://github.com/golang/go/issues/58821

```sh
# supported
~$ echo '2^63-1' | bc
9223372036854775807

~$ openssl asn1parse -genstr 'OID:2.5.2.9223372036854775807' -out - | hexdump -C
00000000  06 0b 55 02 ff ff ff ff  ff ff ff ff 7f 20 20 20  |..U..........   |
00000010  20 30 3a 64 3d 30 20 20  68 6c 3d 32 20 6c 3d 20  | 0:d=0  hl=2 l= |
00000020  20 31 31 20 70 72 69 6d  3a 20 4f 42 4a 45 43 54  | 11 prim: OBJECT|
00000030  20 20 20 20 20 20 20 20  20 20 20 20 3a 32 2e 35  |            :2.5|
00000040  2e 32 2e 39 32 32 33 33  37 32 30 33 36 38 35 34  |.2.9223372036854|
00000050  37 37 35 38 30 37 0a                              |775807.|
00000057

# unsupported
~$ echo '2^63' | bc
9223372036854775808

~$ openssl asn1parse -genstr 'OID:2.5.2.9223372036854775808' -out - | hexdump -C
00000000  06 0c 55 02 81 80 80 80  80 80 80 80 80 00 20 20  |..U...........  |
00000010  20 20 30 3a 64 3d 30 20  20 68 6c 3d 32 20 6c 3d  |  0:d=0  hl=2 l=|
00000020  20 20 31 32 20 70 72 69  6d 3a 20 4f 42 4a 45 43  |  12 prim: OBJEC|
00000030  54 20 20 20 20 20 20 20  20 20 20 20 20 3a 32 2e  |T            :2.|
00000040  35 2e 32 2e 39 32 32 33  33 37 32 30 33 36 38 35  |5.2.922337203685|
00000050  34 37 37 35 38 30 38 0a                           |4775808.|
00000058
```