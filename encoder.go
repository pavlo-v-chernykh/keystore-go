package keystore

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

type keyStoreEncoder struct {
	w    io.Writer
	b    [bufSize]byte
	md   hash.Hash
	rand io.Reader
}

func (kse *keyStoreEncoder) writeUint16(value uint16) error {
	const blockSize = 2
	byteOrder.PutUint16(kse.b[:blockSize], value)
	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to write uint16: %w", err)
	}
	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to update digest: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writeUint32(value uint32) error {
	const blockSize = 4
	byteOrder.PutUint32(kse.b[:blockSize], value)
	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to write uint32: %w", err)
	}
	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to update digest: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writeUint64(value uint64) error {
	const blockSize = 8
	byteOrder.PutUint64(kse.b[:blockSize], value)
	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to write uint64: %w", err)
	}
	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("failed to update digest: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writeBytes(value []byte) error {
	if _, err := kse.w.Write(value); err != nil {
		return fmt.Errorf("failed to write %d bytes: %w", len(value), err)
	}
	if _, err := kse.md.Write(value); err != nil {
		return fmt.Errorf("failed to update digest: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writeString(value string) error {
	strLen := len(value)
	if strLen > math.MaxUint16 {
		return fmt.Errorf("got string %d bytes long, max length is %d", strLen, math.MaxUint16)
	}
	if err := kse.writeUint16(uint16(strLen)); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	if err := kse.writeBytes([]byte(value)); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writeCertificate(cert Certificate) error {
	if err := kse.writeString(cert.Type); err != nil {
		return fmt.Errorf("failed to write type: %w", err)
	}
	certLen := uint64(len(cert.Content))
	if certLen > math.MaxUint32 {
		return fmt.Errorf("got certificate %d bytes long, max length is %d", certLen, math.MaxUint32)
	}
	if err := kse.writeUint32(uint32(certLen)); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	if err := kse.writeBytes(cert.Content); err != nil {
		return fmt.Errorf("failed to write content: %w", err)
	}
	return nil
}

func (kse *keyStoreEncoder) writePrivateKeyEntry(alias string, pke *PrivateKeyEntry, password []byte) error {
	if err := kse.writeUint32(privateKeyTag); err != nil {
		return fmt.Errorf("failed to write tag: %w", err)
	}
	if err := kse.writeString(alias); err != nil {
		return fmt.Errorf("failed to write alias: %w", err)
	}
	if err := kse.writeUint64(uint64(timeToMilliseconds(pke.CreationTime))); err != nil {
		return fmt.Errorf("failed to write creation timestamp: %w", err)
	}
	encryptedContent, err := encrypt(kse.rand, pke.PrivateKey, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt content: %w", err)
	}
	length := uint64(len(encryptedContent))
	if length > math.MaxUint32 {
		return fmt.Errorf("got encrypted content %d bytes long, max length is %d", length, math.MaxUint32)
	}
	if err := kse.writeUint32(uint32(length)); err != nil {
		return fmt.Errorf("filed to write length: %w", err)
	}
	if err := kse.writeBytes(encryptedContent); err != nil {
		return fmt.Errorf("failed to write content: %w", err)
	}
	certNum := uint64(len(pke.CertificateChain))
	if certNum > math.MaxUint32 {
		return fmt.Errorf("got certificate chain %d entries long, max number of entries is %d", certNum, math.MaxUint32)
	}
	if err := kse.writeUint32(uint32(certNum)); err != nil {
		return fmt.Errorf("failed to write number of certificates: %w", err)
	}
	for i, cert := range pke.CertificateChain {
		if err := kse.writeCertificate(cert); err != nil {
			return fmt.Errorf("failed to write %d certificate: %w", i, err)
		}
	}
	return nil
}

func (kse *keyStoreEncoder) writeTrustedCertificateEntry(alias string, tce *TrustedCertificateEntry) error {
	if err := kse.writeUint32(trustedCertificateTag); err != nil {
		return fmt.Errorf("failed to write tag: %w", err)
	}
	if err := kse.writeString(alias); err != nil {
		return fmt.Errorf("failed to write alias: %w", err)
	}
	if err := kse.writeUint64(uint64(timeToMilliseconds(tce.CreationTime))); err != nil {
		return fmt.Errorf("failed to write creation timestamp: %w", err)
	}
	if err := kse.writeCertificate(tce.Certificate); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

// Encode encrypts and signs keystore using password and writes its representation into w
// It is strongly recommended to fill password slice with zero after usage
func Encode(w io.Writer, ks KeyStore, password []byte) error {
	return EncodeWithRand(rand.Reader, w, ks, password)
}

// Encode encrypts and signs keystore using password and writes its representation into w
// Random bytes are read from rand, which must be a cryptographically secure source of randomness
// It is strongly recommended to fill password slice with zero after usage
func EncodeWithRand(rand io.Reader, w io.Writer, ks KeyStore, password []byte) error {
	kse := keyStoreEncoder{
		w:    w,
		md:   sha1.New(),
		rand: rand,
	}
	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)
	if _, err := kse.md.Write(passwordBytes); err != nil {
		return fmt.Errorf("failed to update digest with password: %w", err)
	}
	if _, err := kse.md.Write(whitenerMessage); err != nil {
		return fmt.Errorf("failed to update digest with whitener message: %w", err)
	}
	if err := kse.writeUint32(magic); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	// always write latest version
	if err := kse.writeUint32(version02); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}
	if err := kse.writeUint32(uint32(len(ks))); err != nil {
		return fmt.Errorf("failed to write number of entries: %w", err)
	}
	for alias, entry := range ks {
		switch typedEntry := entry.(type) {
		case *PrivateKeyEntry:
			if err := kse.writePrivateKeyEntry(alias, typedEntry, password); err != nil {
				return fmt.Errorf("failed to write private key entry: %w", err)
			}
		case *TrustedCertificateEntry:
			if err := kse.writeTrustedCertificateEntry(alias, typedEntry); err != nil {
				return fmt.Errorf("failed to write trusted certificate entry: %w", err)
			}
		default:
			return errors.New("got invalid entry")
		}
	}
	if err := kse.writeBytes(kse.md.Sum(nil)); err != nil {
		return fmt.Errorf("failed to write digest")
	}
	return nil
}
