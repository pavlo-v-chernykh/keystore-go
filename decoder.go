package keystore

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
)

const defaultCertificateType = "X509"

type keyStoreDecoder struct {
	r  io.Reader
	b  [bufSize]byte
	md hash.Hash
}

func (ksd *keyStoreDecoder) readUint16() (uint16, error) {
	const blockSize = 2

	if _, err := io.ReadFull(ksd.r, ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("read uint16: %w", err)
	}

	if _, err := ksd.md.Write(ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("update digest: %w", err)
	}

	return byteOrder.Uint16(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readUint32() (uint32, error) {
	const blockSize = 4

	if _, err := io.ReadFull(ksd.r, ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("read uint32: %w", err)
	}

	if _, err := ksd.md.Write(ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("update digest: %w", err)
	}

	return byteOrder.Uint32(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readUint64() (uint64, error) {
	const blockSize = 8

	if _, err := io.ReadFull(ksd.r, ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("read uint64: %w", err)
	}

	if _, err := ksd.md.Write(ksd.b[:blockSize]); err != nil {
		return 0, fmt.Errorf("update digest: %w", err)
	}

	return byteOrder.Uint64(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readBytes(num uint32) ([]byte, error) {
	var result []byte

	for lenToRead := num; lenToRead > 0; {
		blockSize := lenToRead
		if blockSize > bufSize {
			blockSize = bufSize
		}

		if _, err := io.ReadFull(ksd.r, ksd.b[:blockSize]); err != nil {
			return result, fmt.Errorf("read %d bytes: %w", num, err)
		}

		result = append(result, ksd.b[:blockSize]...)
		lenToRead -= blockSize
	}

	if _, err := ksd.md.Write(result); err != nil {
		return nil, fmt.Errorf("update digest: %w", err)
	}

	return result, nil
}

func (ksd *keyStoreDecoder) readString() (string, error) {
	strLen, err := ksd.readUint16()
	if err != nil {
		return "", fmt.Errorf("read length: %w", err)
	}

	strBody, err := ksd.readBytes(uint32(strLen))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(strBody), nil
}

func (ksd *keyStoreDecoder) readCertificate(version uint32) (*Certificate, error) {
	var certType string

	switch version {
	case version01:
		certType = defaultCertificateType
	case version02:
		readCertType, err := ksd.readString()
		if err != nil {
			return nil, fmt.Errorf("read type: %w", err)
		}

		certType = readCertType
	default:
		return nil, errors.New("got unknown version")
	}

	certLen, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	certContent, err := ksd.readBytes(certLen)
	if err != nil {
		return nil, fmt.Errorf("read content: %w", err)
	}

	certificate := Certificate{
		Type:    certType,
		Content: certContent,
	}

	return &certificate, nil
}

func (ksd *keyStoreDecoder) readPrivateKeyEntry(version uint32, password []byte) (*PrivateKeyEntry, error) {
	creationTimeStamp, err := ksd.readUint64()
	if err != nil {
		return nil, fmt.Errorf("read creation timestamp: %w", err)
	}

	length, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	encryptedPrivateKey, err := ksd.readBytes(length)
	if err != nil {
		return nil, fmt.Errorf("read encrypted private key: %w", err)
	}

	certNum, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read number of certificates: %w", err)
	}

	chain := make([]Certificate, 0, certNum)

	for i := uint32(0); i < certNum; i++ {
		cert, err := ksd.readCertificate(version)
		if err != nil {
			return nil, fmt.Errorf("read %d certificate: %w", i, err)
		}

		chain = append(chain, *cert)
	}

	decryptedPrivateKey, err := decrypt(encryptedPrivateKey, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt content: %w", err)
	}

	creationDateTime := millisecondsToTime(int64(creationTimeStamp))
	privateKeyEntry := PrivateKeyEntry{
		Entry: Entry{
			CreationTime: creationDateTime,
		},
		PrivateKey:       decryptedPrivateKey,
		CertificateChain: chain,
	}

	return &privateKeyEntry, nil
}

func (ksd *keyStoreDecoder) readTrustedCertificateEntry(version uint32) (*TrustedCertificateEntry, error) {
	creationTimeStamp, err := ksd.readUint64()
	if err != nil {
		return nil, fmt.Errorf("read creation timestamp: %w", err)
	}

	certificate, err := ksd.readCertificate(version)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	creationDateTime := millisecondsToTime(int64(creationTimeStamp))
	trustedCertificateEntry := TrustedCertificateEntry{
		Entry: Entry{
			CreationTime: creationDateTime,
		},
		Certificate: *certificate,
	}

	return &trustedCertificateEntry, nil
}

func (ksd *keyStoreDecoder) readEntry(version uint32, password []byte) (string, interface{}, error) {
	tag, err := ksd.readUint32()
	if err != nil {
		return "", nil, fmt.Errorf("read tag: %w", err)
	}

	alias, err := ksd.readString()
	if err != nil {
		return "", nil, fmt.Errorf("read alias: %w", err)
	}

	switch tag {
	case privateKeyTag:
		entry, err := ksd.readPrivateKeyEntry(version, password)
		if err != nil {
			return "", nil, fmt.Errorf("read private key entry: %w", err)
		}

		return alias, entry, nil
	case trustedCertificateTag:
		entry, err := ksd.readTrustedCertificateEntry(version)
		if err != nil {
			return "", nil, fmt.Errorf("read trusted certificate entry: %w", err)
		}

		return alias, entry, nil
	default:
		return "", nil, errors.New("got unknown entry tag")
	}
}

// Decode reads keystore representation from r then decrypts and check signature using password
// It is strongly recommended to fill password slice with zero after usage.
func Decode(r io.Reader, password []byte) (KeyStore, error) {
	ksd := keyStoreDecoder{
		r:  r,
		md: sha1.New(),
	}

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	if _, err := ksd.md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := ksd.md.Write(whitenerMessage); err != nil {
		return nil, fmt.Errorf("update digest with whitener message: %w", err)
	}

	readMagic, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	if readMagic != magic {
		return nil, errors.New("got invalid magic")
	}

	version, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}

	entryNum, err := ksd.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read number of entries: %w", err)
	}

	keyStore := make(KeyStore, entryNum)

	for i := uint32(0); i < entryNum; i++ {
		alias, entry, err := ksd.readEntry(version, password)
		if err != nil {
			return nil, fmt.Errorf("read %d entry: %w", i, err)
		}

		keyStore[alias] = entry
	}

	actualDigest, err := ksd.readBytes(uint32(ksd.md.Size()))
	if err != nil {
		return nil, fmt.Errorf("read digest: %w", err)
	}

	computedDigest := ksd.md.Sum(nil)
	if !bytes.Equal(actualDigest, computedDigest) {
		return nil, errors.New("got invalid digest")
	}

	return keyStore, nil
}
