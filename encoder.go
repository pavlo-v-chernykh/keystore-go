package keystore

import (
	"fmt"
	"hash"
	"io"
	"math"
)

type keyStoreEncoder struct {
	w  io.Writer
	b  [bufSize]byte
	md hash.Hash
}

func (kse *keyStoreEncoder) writeUint16(value uint16) error {
	const blockSize = 2

	byteOrder.PutUint16(kse.b[:blockSize], value)

	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("write uint16: %w", err)
	}

	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("update digest: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writeUint32(value uint32) error {
	const blockSize = 4

	byteOrder.PutUint32(kse.b[:blockSize], value)

	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("write uint32: %w", err)
	}

	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("update digest: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writeUint64(value uint64) error {
	const blockSize = 8

	byteOrder.PutUint64(kse.b[:blockSize], value)

	if _, err := kse.w.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("write uint64: %w", err)
	}

	if _, err := kse.md.Write(kse.b[:blockSize]); err != nil {
		return fmt.Errorf("update digest: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writeBytes(value []byte) error {
	if _, err := kse.w.Write(value); err != nil {
		return fmt.Errorf("write %d bytes: %w", len(value), err)
	}

	if _, err := kse.md.Write(value); err != nil {
		return fmt.Errorf("update digest: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writeString(value string) error {
	strLen := len(value)
	if strLen > math.MaxUint16 {
		return fmt.Errorf("got string %d bytes long, max length is %d", strLen, math.MaxUint16)
	}

	if err := kse.writeUint16(uint16(strLen)); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	if err := kse.writeBytes([]byte(value)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writeCertificate(cert Certificate) error {
	if err := kse.writeString(cert.Type); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	certLen := uint64(len(cert.Content))
	if certLen > math.MaxUint32 {
		return fmt.Errorf("got certificate %d bytes long, max length is %d", certLen, uint64(math.MaxUint32))
	}

	if err := kse.writeUint32(uint32(certLen)); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	if err := kse.writeBytes(cert.Content); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	return nil
}

func (kse *keyStoreEncoder) writePrivateKeyEntry(alias string, pke PrivateKeyEntry) error {
	if err := kse.writeUint32(privateKeyTag); err != nil {
		return fmt.Errorf("write tag: %w", err)
	}

	if err := kse.writeString(alias); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	if err := kse.writeUint64(uint64(timeToMilliseconds(pke.CreationTime))); err != nil {
		return fmt.Errorf("write creation timestamp: %w", err)
	}

	length := uint64(len(pke.encryptedPrivateKey))
	if length > math.MaxUint32 {
		return fmt.Errorf("got encrypted content %d bytes long, max length is %d", length, uint64(math.MaxUint32))
	}

	if err := kse.writeUint32(uint32(length)); err != nil {
		return fmt.Errorf("filed to write length: %w", err)
	}

	if err := kse.writeBytes(pke.encryptedPrivateKey); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	certNum := uint64(len(pke.CertificateChain))
	if certNum > math.MaxUint32 {
		return fmt.Errorf("got certificate chain %d entries long, max number of entries is %d",
			certNum, uint64(math.MaxUint32))
	}

	if err := kse.writeUint32(uint32(certNum)); err != nil {
		return fmt.Errorf("write number of certificates: %w", err)
	}

	for i, cert := range pke.CertificateChain {
		if err := kse.writeCertificate(cert); err != nil {
			return fmt.Errorf("write %d certificate: %w", i, err)
		}
	}

	return nil
}

func (kse *keyStoreEncoder) writeTrustedCertificateEntry(alias string, tce TrustedCertificateEntry) error {
	if err := kse.writeUint32(trustedCertificateTag); err != nil {
		return fmt.Errorf("write tag: %w", err)
	}

	if err := kse.writeString(alias); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	if err := kse.writeUint64(uint64(timeToMilliseconds(tce.CreationTime))); err != nil {
		return fmt.Errorf("write creation timestamp: %w", err)
	}

	if err := kse.writeCertificate(tce.Certificate); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}
