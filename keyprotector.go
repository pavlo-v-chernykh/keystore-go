package keystore

import (
	"errors"
	"hash"
	"crypto/sha1"
	"crypto/x509/pkix"
)

const supportedPrivateKeyAlgorithmOid = "1.3.6.1.4.1.42.2.17.1.1"

const saltLen = 20

const reasonUnsupportedPrivateKeyAlgorithm = "Unsupported private key algorithm"
const reasonUnrecoverablePrivateKey = "Unrecoverable private key"

var ErrUnsupportedPrivateKeyAlgorithm = errors.New(reasonUnsupportedPrivateKeyAlgorithm)
var ErrUnrecoverablePrivateKey = errors.New(reasonUnrecoverablePrivateKey)

type keyInfo struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type keyProtector struct {
	md          hash.Hash
	passwdBytes []byte
}

func newKeyProtector(password string) keyProtector {
	var passwdBytes []byte
	for _, c := range password {
		passwdBytes = append(passwdBytes, 0, byte(c))
	}
	return keyProtector{sha1.New(), passwdBytes}
}

func (kp *keyProtector) recover(keyInfo keyInfo) ([]byte, error) {
	if keyInfo.Algo.Algorithm.String() != supportedPrivateKeyAlgorithmOid {
		return nil, ErrUnsupportedPrivateKeyAlgorithm
	}

	salt := make([]byte, saltLen)
	copy(salt, keyInfo.PrivateKey)
	encrKeyLen := len(keyInfo.PrivateKey) - saltLen - kp.md.Size()
	numRounds := encrKeyLen / kp.md.Size()

	if encrKeyLen % kp.md.Size() != 0 {
		numRounds++
	}

	encrKey := make([]byte, encrKeyLen)
	copy(encrKey, keyInfo.PrivateKey[saltLen:])

	xorKey := make([]byte, encrKeyLen)

	digest := salt
	for i, xorOffset := 0, 0; i < numRounds; i++ {
		kp.md.Write(kp.passwdBytes)
		kp.md.Write(digest)
		digest = kp.md.Sum(nil)
		kp.md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += kp.md.Size()
	}

	plainKey := make([]byte, encrKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encrKey[i] ^ xorKey[i]
	}

	kp.md.Write(kp.passwdBytes)
	kp.md.Write(plainKey)
	digest = kp.md.Sum(nil)
	kp.md.Reset()

	digestOffset := saltLen + encrKeyLen
	for i := 0; i < len(digest); i++ {
		if digest[i] != keyInfo.PrivateKey[digestOffset + i] {
			return nil, ErrUnrecoverablePrivateKey
		}
	}

	return plainKey, nil
}
