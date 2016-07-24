package keystore

import "encoding/binary"

const magic uint32 = 0xfeedfeed
const (
	version01 uint32 = 1
	version02 uint32 = 2
)
const (
	privateKeyTag         uint32 = 1
	trustedCertificateTag uint32 = 2
)
const defaultCertificateType = "X509"
const bufSize = 4096

var order = binary.BigEndian

func passwordBytes(password string) []byte {
	passwdBytes := make([]byte, 0, len(password)*2)
	for _, c := range password {
		passwdBytes = append(passwdBytes, 0, byte(c))
	}
	return passwdBytes
}
