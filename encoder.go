package keystore

import (
	"crypto/sha1"
	"errors"
	"hash"
	"io"
	"math"
)

// ErrEncodedSequenceTooLong indicates that size of string or bytes trying to encode too big
var ErrEncodedSequenceTooLong = errors.New("keystore: encoded sequence too long")

// ErrIncorrectEntryType indicates incorrect entry type addressing
var ErrIncorrectEntryType = errors.New("keystore: incorrect entry type")

type keyStoreEncoder struct {
	w  io.Writer
	b  [bufSize]byte
	md hash.Hash
}

func (kse *keyStoreEncoder) writeUint16(value uint16) error {
	const blockSize = 2
	order.PutUint16(kse.b[:blockSize], value)
	_, err := kse.w.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	_, err = kse.md.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeUint32(value uint32) error {
	const blockSize = 4
	order.PutUint32(kse.b[:blockSize], value)
	_, err := kse.w.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	_, err = kse.md.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeUint64(value uint64) error {
	const blockSize = 8
	order.PutUint64(kse.b[:blockSize], value)
	_, err := kse.w.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	_, err = kse.md.Write(kse.b[:blockSize])
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeBytes(value []byte) error {
	_, err := kse.w.Write(value)
	if err != nil {
		return err
	}
	_, err = kse.md.Write(value)
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeString(value string) error {
	strLen := len(value)
	if strLen > math.MaxUint16 {
		return ErrEncodedSequenceTooLong
	}
	err := kse.writeUint16(uint16(strLen))
	if err != nil {
		return err
	}
	err = kse.writeBytes([]byte(value))
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeCertificate(cert *Certificate) error {
	err := kse.writeString(cert.Type)
	if err != nil {
		return err
	}
	certLen := len(cert.Content)
	if certLen > math.MaxUint32 {
		return ErrEncodedSequenceTooLong
	}
	err = kse.writeUint32(uint32(certLen))
	if err != nil {
		return err
	}
	err = kse.writeBytes(cert.Content)
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writeTrustedCertificateEntry(alias string, tce *TrustedCertificateEntry) error {
	err := kse.writeUint32(trustedCertificateTag)
	if err != nil {
		return err
	}
	err = kse.writeString(alias)
	if err != nil {
		return err
	}
	err = kse.writeUint64(uint64(tce.CreationDate.Unix()))
	if err != nil {
		return err
	}
	err = kse.writeCertificate(&tce.Certificate)
	if err != nil {
		return err
	}
	return nil
}

func (kse *keyStoreEncoder) writePrivateKeyEntry(alias string, pke *PrivateKeyEntry, password []byte) error {
	err := kse.writeUint32(privateKeyTag)
	if err != nil {
		return err
	}
	err = kse.writeString(alias)
	if err != nil {
		return err
	}
	err = kse.writeUint64(uint64(pke.CreationDate.Unix()))
	if err != nil {
		return err
	}
	encodedPrivKeyContent, err := protectKey(pke.PrivKey, password)
	if err != nil {
		return err
	}
	privKeyLen := len(encodedPrivKeyContent)
	if privKeyLen > math.MaxUint32 {
		return ErrEncodedSequenceTooLong
	}
	err = kse.writeUint32(uint32(privKeyLen))
	if err != nil {
		return err
	}
	err = kse.writeBytes(encodedPrivKeyContent)
	if err != nil {
		return err
	}
	certCount := len(pke.CertChain)
	if certCount > math.MaxUint32 {
		return ErrEncodedSequenceTooLong
	}
	err = kse.writeUint32(uint32(certCount))
	if err != nil {
		return err
	}
	for _, cert := range pke.CertChain {
		err = kse.writeCertificate(&cert)
		if err != nil {
			return err
		}
	}
	return nil
}

func Encode(w io.Writer, ks KeyStore, password []byte) error {
	kse := keyStoreEncoder{
		w:  w,
		md: sha1.New(),
	}
	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)
	_, err := kse.md.Write(passwordBytes)
	if err != nil {
		return err
	}
	_, err = kse.md.Write(whitenerMessage)
	if err != nil {
		return err
	}

	err = kse.writeUint32(magic)
	if err != nil {
		return err
	}
	// always write latest version
	err = kse.writeUint32(version02)
	if err != nil {
		return err
	}
	err = kse.writeUint32(uint32(len(ks)))
	if err != nil {
		return err
	}
	for alias, entry := range ks {
		switch typedEntry := entry.(type) {
		case *PrivateKeyEntry:
			err = kse.writePrivateKeyEntry(alias, typedEntry, password)
			if err != nil {
				return err
			}
		case *TrustedCertificateEntry:
			err = kse.writeTrustedCertificateEntry(alias, typedEntry)
			if err != nil {
				return err
			}
		default:
			return ErrIncorrectEntryType
		}
	}
	err = kse.writeBytes(kse.md.Sum(nil))
	if err != nil {
		return err
	}
	return nil
}
