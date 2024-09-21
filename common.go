package keystore

import (
	"encoding/binary"
)

const (
	version01 uint32 = 1
	version02 uint32 = 2

	privateKeyTag         uint32 = 1
	trustedCertificateTag uint32 = 2
)

var jksMagicBytes = []byte{0xfe, 0xed, 0xfe, 0xed}

var byteOrder = binary.BigEndian

var whitenerMessage = []byte("Mighty Aphrodite")

func passwordBytes(password []byte) []byte {
	result := make([]byte, 0, len(password)*2)
	for _, b := range password {
		result = append(result, 0, b)
	}

	return result
}

func zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
