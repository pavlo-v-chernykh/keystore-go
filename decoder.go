package keystore

import (
	"errors"
	"encoding/binary"
	"io"
	"time"
	"encoding/asn1"
)

const magic uint32 = 0xfeedfeed
const (
	version01 uint32 = 1
	version02 uint32 = 2
)
const (
	privateKeyTag uint32 = 1
	trustedCertificateTag uint32 = 2
)
const defaultCertificateType = "X509"
const bufSize = 4096

const (
	reasonInvalidKeystoreFormat = "Invalid keystore format"
	reasonInvalidPrivateKeyFormat = "Invalid private key format"
)

var order = binary.BigEndian

var ErrIo = errors.New(reasonInvalidKeystoreFormat)
var ErrIncorrectMagic = errors.New(reasonInvalidKeystoreFormat)
var ErrIncorrectVersion = errors.New(reasonInvalidKeystoreFormat)
var ErrIncorrectTag = errors.New(reasonInvalidKeystoreFormat)
var ErrIncorrectPrivateKey = errors.New(reasonInvalidPrivateKeyFormat)

type keyStoreDecoder struct {
	r io.Reader
	b [bufSize]byte
}

func (ksd *keyStoreDecoder) readUint16() (uint16, error) {
	const blockSize = 2
	_, err := io.ReadFull(ksd.r, ksd.b[:blockSize])
	if err != nil {
		return 0, ErrIo
	}
	return order.Uint16(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readUint32() (uint32, error) {
	const blockSize = 4
	_, err := io.ReadFull(ksd.r, ksd.b[:blockSize])
	if err != nil {
		return 0, ErrIo
	}
	return order.Uint32(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readUint64() (uint64, error) {
	const blockSize = 8
	_, err := io.ReadFull(ksd.r, ksd.b[:blockSize])
	if err != nil {
		return 0, ErrIo
	}
	return order.Uint64(ksd.b[:blockSize]), nil
}

func (ksd *keyStoreDecoder) readBytes(num uint32) ([]byte, error) {
	var result []byte
	for lenToRead := num; lenToRead > 0; {
		blockSize := lenToRead
		if blockSize > bufSize {
			blockSize = bufSize
		}
		_, err := io.ReadFull(ksd.r, ksd.b[:blockSize])
		if err != nil {
			return result, ErrIo
		}
		result = append(result, ksd.b[:blockSize]...)
		lenToRead -= blockSize
	}
	return result, nil
}

func (ksd *keyStoreDecoder) readString() (string, error) {
	strLen, err := ksd.readUint16()
	if err != nil {
		return "", err
	}
	bytes, err := ksd.readBytes(uint32(strLen))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (ksd *keyStoreDecoder) readCertificate(version uint32) (*Certificate, error) {
	var certType string
	switch version {
	case version01:
		certType = defaultCertificateType
	case version02:
		readCertType, err := ksd.readString()
		if err != nil {
			return nil, err
		}
		certType = readCertType
	default:
		return nil, ErrIncorrectVersion
	}
	certLen, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	certContent, err := ksd.readBytes(certLen)
	if err != nil {
		return nil, err
	}
	return &Certificate{certType, certContent}, nil
}

func (ksd *keyStoreDecoder) readPrivateKeyEntry(version uint32, password string) (*PrivateKeyEntry, error) {
	creationDateTimeStamp, err := ksd.readUint64()
	if err != nil {
		return nil, err
	}
	privateKeyLen, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	encodedPrivateKeyContent, err := ksd.readBytes(privateKeyLen)
	if err != nil {
		return nil, err
	}
	certificatesCount, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	var chain []Certificate
	for i := certificatesCount; i > 0; i-- {
		cert, err := ksd.readCertificate(version)
		if err != nil {
			return nil, err
		}
		chain = append(chain, *cert)
	}
	var keyInfo keyInfo
	asn1Rest, err := asn1.Unmarshal(encodedPrivateKeyContent, &keyInfo)
	if err != nil || len(asn1Rest) > 0 {
		return nil, ErrIncorrectPrivateKey
	}
	keyProtector := newKeyProtector(password)
	plainPrivateKeyContent, err := keyProtector.recover(keyInfo)
	if err != nil {
		return nil, err
	}
	creationDateTime := time.Unix(int64(creationDateTimeStamp), 0)
	return &PrivateKeyEntry{Entry{creationDateTime}, plainPrivateKeyContent, chain}, nil
}

func (ksd *keyStoreDecoder) readTrustedCertificateEntry(version uint32) (*TrustedCertificateEntry, error) {
	creationDateTimeStamp, err := ksd.readUint64()
	if err != nil {
		return nil, err
	}
	cert, err := ksd.readCertificate(version)
	if err != nil {
		return nil, err
	}
	creationDateTime := time.Unix(int64(creationDateTimeStamp), 0)
	return &TrustedCertificateEntry{Entry{creationDateTime}, *cert}, nil
}

func (ksd *keyStoreDecoder) readEntry(version uint32, password string) (string, interface{}, error) {
	tag, err := ksd.readUint32()
	if err != nil {
		return "", nil, err
	}
	alias, err := ksd.readString()
	if err != nil {
		return "", nil, err
	}
	switch tag {
	case privateKeyTag:
		entry, err := ksd.readPrivateKeyEntry(version, password)
		if err != nil {
			return "", nil, err
		}
		return alias, entry, nil
	case trustedCertificateTag:
		entry, err := ksd.readTrustedCertificateEntry(version)
		if err != nil {
			return "", nil, err
		}
		return alias, entry, nil
	}
	return "", nil, ErrIncorrectTag
}

func Decode(r io.Reader, password string) (*KeyStore, error) {
	ksd := keyStoreDecoder{r: r}
	readMagic, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	if readMagic != magic {
		return nil, ErrIncorrectMagic
	}
	version, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	count, err := ksd.readUint32()
	if err != nil {
		return nil, err
	}
	keyStore := make(KeyStore)
	for entitiesCount := count; entitiesCount > 0; entitiesCount-- {
		alias, entry, err := ksd.readEntry(version, password)
		if err != nil {
			return nil, err
		}
		keyStore[alias] = entry
	}
	return &keyStore, nil
}
