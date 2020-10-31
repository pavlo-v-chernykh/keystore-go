package keystore

import (
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

func (ksd *keyStoreDecoder) readCertificate(version uint32) (Certificate, error) {
	var certType string

	switch version {
	case version01:
		certType = defaultCertificateType
	case version02:
		readCertType, err := ksd.readString()
		if err != nil {
			return Certificate{}, fmt.Errorf("read type: %w", err)
		}

		certType = readCertType
	default:
		return Certificate{}, errors.New("got unknown version")
	}

	certLen, err := ksd.readUint32()
	if err != nil {
		return Certificate{}, fmt.Errorf("read length: %w", err)
	}

	certContent, err := ksd.readBytes(certLen)
	if err != nil {
		return Certificate{}, fmt.Errorf("read content: %w", err)
	}

	certificate := Certificate{
		Type:    certType,
		Content: certContent,
	}

	return certificate, nil
}

func (ksd *keyStoreDecoder) readPrivateKeyEntry(version uint32) (PrivateKeyEntry, error) {
	creationTimeStamp, err := ksd.readUint64()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read creation timestamp: %w", err)
	}

	length, err := ksd.readUint32()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read length: %w", err)
	}

	encryptedPrivateKey, err := ksd.readBytes(length)
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read encrypted private key: %w", err)
	}

	certNum, err := ksd.readUint32()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read number of certificates: %w", err)
	}

	chain := make([]Certificate, 0, certNum)

	for i := uint32(0); i < certNum; i++ {
		cert, err := ksd.readCertificate(version)
		if err != nil {
			return PrivateKeyEntry{}, fmt.Errorf("read %d certificate: %w", i, err)
		}

		chain = append(chain, cert)
	}

	creationDateTime := millisecondsToTime(int64(creationTimeStamp))
	privateKeyEntry := PrivateKeyEntry{
		encryptedPrivateKey: encryptedPrivateKey,
		CreationTime:        creationDateTime,
		CertificateChain:    chain,
	}

	return privateKeyEntry, nil
}

func (ksd *keyStoreDecoder) readTrustedCertificateEntry(version uint32) (TrustedCertificateEntry, error) {
	creationTimeStamp, err := ksd.readUint64()
	if err != nil {
		return TrustedCertificateEntry{}, fmt.Errorf("read creation timestamp: %w", err)
	}

	certificate, err := ksd.readCertificate(version)
	if err != nil {
		return TrustedCertificateEntry{}, fmt.Errorf("read certificate: %w", err)
	}

	creationDateTime := millisecondsToTime(int64(creationTimeStamp))
	trustedCertificateEntry := TrustedCertificateEntry{
		CreationTime: creationDateTime,
		Certificate:  certificate,
	}

	return trustedCertificateEntry, nil
}

func (ksd *keyStoreDecoder) readEntry(version uint32) (string, interface{}, error) {
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
		entry, err := ksd.readPrivateKeyEntry(version)
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
