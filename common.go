package keystore

import (
	"encoding/binary"
	"time"
)

const (
	magic uint32 = 0xfeedfeed

	version01 uint32 = 1
	version02 uint32 = 2

	privateKeyTag         uint32 = 1
	trustedCertificateTag uint32 = 2
)

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

func millisecondsToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}

func timeToMilliseconds(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}
