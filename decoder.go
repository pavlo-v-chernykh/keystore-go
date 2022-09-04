package keystore

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"time"
)

const defaultCertificateType = "X509"

type decoder struct {
	r io.Reader
	h hash.Hash
}

func (d decoder) readUint16() (uint16, error) {
	b, err := d.readBytes(2)

	return byteOrder.Uint16(b), err
}

func (d decoder) readUint32() (uint32, error) {
	b, err := d.readBytes(4)

	return byteOrder.Uint32(b), err
}

func (d decoder) readUint64() (uint64, error) {
	b, err := d.readBytes(8)

	return byteOrder.Uint64(b), err
}

func (d decoder) readBytes(num uint32) ([]byte, error) {
	result := make([]byte, num)

	if _, err := io.ReadFull(d.r, result); err != nil {
		return result, fmt.Errorf("read %d bytes: %w", num, err)
	}

	if _, err := d.h.Write(result); err != nil {
		return nil, fmt.Errorf("update digest: %w", err)
	}

	return result, nil
}

func (d decoder) readString() (string, error) {
	strLen, err := d.readUint16()
	if err != nil {
		return "", fmt.Errorf("read length: %w", err)
	}

	strBody, err := d.readBytes(uint32(strLen))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(strBody), nil
}

func (d decoder) readCertificate(version uint32) (Certificate, error) {
	var certType string

	switch version {
	case version01:
		certType = defaultCertificateType
	case version02:
		readCertType, err := d.readString()
		if err != nil {
			return Certificate{}, fmt.Errorf("read type: %w", err)
		}

		certType = readCertType
	default:
		return Certificate{}, errors.New("got unknown version")
	}

	certLen, err := d.readUint32()
	if err != nil {
		return Certificate{}, fmt.Errorf("read length: %w", err)
	}

	certContent, err := d.readBytes(certLen)
	if err != nil {
		return Certificate{}, fmt.Errorf("read content: %w", err)
	}

	certificate := Certificate{
		Type:    certType,
		Content: certContent,
	}

	return certificate, nil
}

func (d decoder) readPrivateKeyEntry(version uint32) (PrivateKeyEntry, error) {
	creationTimeStamp, err := d.readUint64()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read creation timestamp: %w", err)
	}

	length, err := d.readUint32()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read length: %w", err)
	}

	encryptedPrivateKey, err := d.readBytes(length)
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read encrypted private key: %w", err)
	}

	certNum, err := d.readUint32()
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("read number of certificates: %w", err)
	}

	chain := make([]Certificate, 0, certNum)

	for i := uint32(0); i < certNum; i++ {
		cert, err := d.readCertificate(version)
		if err != nil {
			return PrivateKeyEntry{}, fmt.Errorf("read %d certificate: %w", i, err)
		}

		chain = append(chain, cert)
	}

	creationDateTime := time.UnixMilli(int64(creationTimeStamp))
	privateKeyEntry := PrivateKeyEntry{
		PrivateKey:       encryptedPrivateKey,
		CreationTime:     creationDateTime,
		CertificateChain: chain,
	}

	return privateKeyEntry, nil
}

func (d decoder) readTrustedCertificateEntry(version uint32) (TrustedCertificateEntry, error) {
	creationTimeStamp, err := d.readUint64()
	if err != nil {
		return TrustedCertificateEntry{}, fmt.Errorf("read creation timestamp: %w", err)
	}

	certificate, err := d.readCertificate(version)
	if err != nil {
		return TrustedCertificateEntry{}, fmt.Errorf("read certificate: %w", err)
	}

	creationDateTime := time.UnixMilli(int64(creationTimeStamp))
	trustedCertificateEntry := TrustedCertificateEntry{
		CreationTime: creationDateTime,
		Certificate:  certificate,
	}

	return trustedCertificateEntry, nil
}

func (d decoder) readEntry(version uint32) (string, interface{}, error) {
	tag, err := d.readUint32()
	if err != nil {
		return "", nil, fmt.Errorf("read tag: %w", err)
	}

	alias, err := d.readString()
	if err != nil {
		return "", nil, fmt.Errorf("read alias: %w", err)
	}

	switch tag {
	case privateKeyTag:
		entry, err := d.readPrivateKeyEntry(version)
		if err != nil {
			return "", nil, fmt.Errorf("read private key entry: %w", err)
		}

		return alias, entry, nil
	case trustedCertificateTag:
		entry, err := d.readTrustedCertificateEntry(version)
		if err != nil {
			return "", nil, fmt.Errorf("read trusted certificate entry: %w", err)
		}

		return alias, entry, nil
	default:
		return "", nil, errors.New("got unknown entry tag")
	}
}
