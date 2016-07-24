package keystore

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
)

const saltLen = 20

var supportedPrivateKeyAlgorithmOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1})

// ErrUnsupportedPrivateKeyAlgorithm indicates unsupported private key algorithm
var ErrUnsupportedPrivateKeyAlgorithm = errors.New("Unsupported private key algorithm")

// ErrUnrecoverablePrivateKey indicates unrecoverable private key content (often means wrong password usage)
var ErrUnrecoverablePrivateKey = errors.New("Unrecoverable private key")

type keyInfo struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type keyProtector struct {
	md          hash.Hash
	passwdBytes []byte
}

func newKeyProtector(password string) keyProtector {
	return keyProtector{
		md:          sha1.New(),
		passwdBytes: passwordBytes(password),
	}
}

func (kp *keyProtector) recover(keyInfo keyInfo) ([]byte, error) {
	if !keyInfo.Algo.Algorithm.Equal(supportedPrivateKeyAlgorithmOid) {
		return nil, ErrUnsupportedPrivateKeyAlgorithm
	}

	salt := make([]byte, saltLen)
	copy(salt, keyInfo.PrivateKey)
	encrKeyLen := len(keyInfo.PrivateKey) - saltLen - kp.md.Size()
	numRounds := encrKeyLen / kp.md.Size()

	if encrKeyLen%kp.md.Size() != 0 {
		numRounds++
	}

	encrKey := make([]byte, encrKeyLen)
	copy(encrKey, keyInfo.PrivateKey[saltLen:])

	xorKey := make([]byte, encrKeyLen)

	digest := salt
	for i, xorOffset := 0, 0; i < numRounds; i++ {
		_, err := kp.md.Write(kp.passwdBytes)
		if err != nil {
			return nil, ErrUnrecoverablePrivateKey
		}
		_, err = kp.md.Write(digest)
		if err != nil {
			return nil, ErrUnrecoverablePrivateKey
		}
		digest = kp.md.Sum(nil)
		kp.md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += kp.md.Size()
	}

	plainKey := make([]byte, encrKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encrKey[i] ^ xorKey[i]
	}

	_, err := kp.md.Write(kp.passwdBytes)
	if err != nil {
		return nil, ErrUnrecoverablePrivateKey
	}
	_, err = kp.md.Write(plainKey)
	if err != nil {
		return nil, ErrUnrecoverablePrivateKey
	}
	digest = kp.md.Sum(nil)
	kp.md.Reset()

	digestOffset := saltLen + encrKeyLen
	for i := 0; i < len(digest); i++ {
		if digest[i] != keyInfo.PrivateKey[digestOffset+i] {
			return nil, ErrUnrecoverablePrivateKey
		}
	}

	return plainKey, nil
}

func (kp *keyProtector) protect(plainKey []byte) (*keyInfo, error) {
	plainKeyLen := len(plainKey)
	numRounds := plainKeyLen / kp.md.Size()

	if plainKeyLen%kp.md.Size() != 0 {
		numRounds++
	}

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	xorKey := make([]byte, plainKeyLen)

	digest := salt
	for i, xorOffset := 0, 0; i < numRounds; i++ {
		_, err = kp.md.Write(kp.passwdBytes)
		if err != nil {
			return nil, err
		}
		_, err = kp.md.Write(digest)
		if err != nil {
			return nil, err
		}
		digest = kp.md.Sum(nil)
		kp.md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += kp.md.Size()
	}

	tmpKey := make([]byte, plainKeyLen)
	for i := 0; i < plainKeyLen; i++ {
		tmpKey[i] = plainKey[i] ^ xorKey[i]
	}

	encrKey := make([]byte, saltLen+plainKeyLen+kp.md.Size())
	encrKeyOffset := 0
	copy(encrKey[encrKeyOffset:], salt)
	encrKeyOffset += saltLen
	copy(encrKey[encrKeyOffset:], tmpKey)
	encrKeyOffset += plainKeyLen

	_, err = kp.md.Write(kp.passwdBytes)
	if err != nil {
		return nil, err
	}
	_, err = kp.md.Write(plainKey)
	if err != nil {
		return nil, err
	}
	digest = kp.md.Sum(nil)
	kp.md.Reset()
	copy(encrKey[encrKeyOffset:], digest)
	keyInfo := keyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: supportedPrivateKeyAlgorithmOid,
		},
		PrivateKey: encrKey,
	}
	return &keyInfo, nil
}
