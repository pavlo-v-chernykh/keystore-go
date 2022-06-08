package keystore

import (
	"fmt"
	"hash"
	"io"
	"math"
)

type encoder struct {
	w io.Writer
	h hash.Hash
}

func (e encoder) writeUint16(value uint16) error {
	var b [2]byte

	byteOrder.PutUint16(b[:], value)

	return e.writeBytes(b[:])
}

func (e encoder) writeUint32(value uint32) error {
	var b [4]byte

	byteOrder.PutUint32(b[:], value)

	return e.writeBytes(b[:])
}

func (e encoder) writeUint64(value uint64) error {
	var b [8]byte

	byteOrder.PutUint64(b[:], value)

	return e.writeBytes(b[:])
}

func (e encoder) writeBytes(value []byte) error {
	if _, err := e.w.Write(value); err != nil {
		return fmt.Errorf("write %d bytes: %w", len(value), err)
	}

	if _, err := e.h.Write(value); err != nil {
		return fmt.Errorf("update digest: %w", err)
	}

	return nil
}

func (e encoder) writeString(value string) error {
	strLen := len(value)
	if strLen > math.MaxUint16 {
		return fmt.Errorf("got string %d bytes long, max length is %d", strLen, math.MaxUint16)
	}

	if err := e.writeUint16(uint16(strLen)); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	if err := e.writeBytes([]byte(value)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

func (e encoder) writeCertificate(cert Certificate) error {
	if err := e.writeString(cert.Type); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	certLen := uint64(len(cert.Content))
	if certLen > math.MaxUint32 {
		return fmt.Errorf("got certificate %d bytes long, max length is %d", certLen, uint64(math.MaxUint32))
	}

	if err := e.writeUint32(uint32(certLen)); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	if err := e.writeBytes(cert.Content); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	return nil
}

func (e encoder) writePrivateKeyEntry(alias string, pke PrivateKeyEntry) error {
	if err := e.writeUint32(privateKeyTag); err != nil {
		return fmt.Errorf("write tag: %w", err)
	}

	if err := e.writeString(alias); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	if err := e.writeUint64(uint64(pke.CreationTime.UnixMilli())); err != nil {
		return fmt.Errorf("write creation timestamp: %w", err)
	}

	length := uint64(len(pke.encryptedPrivateKey))
	if length > math.MaxUint32 {
		return fmt.Errorf("got encrypted content %d bytes long, max length is %d", length, uint64(math.MaxUint32))
	}

	if err := e.writeUint32(uint32(length)); err != nil {
		return fmt.Errorf("filed to write length: %w", err)
	}

	if err := e.writeBytes(pke.encryptedPrivateKey); err != nil {
		return fmt.Errorf("write content: %w", err)
	}

	certNum := uint64(len(pke.CertificateChain))
	if certNum > math.MaxUint32 {
		return fmt.Errorf("got certificate chain %d entries long, max number of entries is %d",
			certNum, uint64(math.MaxUint32))
	}

	if err := e.writeUint32(uint32(certNum)); err != nil {
		return fmt.Errorf("write number of certificates: %w", err)
	}

	for i, cert := range pke.CertificateChain {
		if err := e.writeCertificate(cert); err != nil {
			return fmt.Errorf("write %d certificate: %w", i, err)
		}
	}

	return nil
}

func (e encoder) writeTrustedCertificateEntry(alias string, tce TrustedCertificateEntry) error {
	if err := e.writeUint32(trustedCertificateTag); err != nil {
		return fmt.Errorf("write tag: %w", err)
	}

	if err := e.writeString(alias); err != nil {
		return fmt.Errorf("write alias: %w", err)
	}

	if err := e.writeUint64(uint64(tce.CreationTime.UnixMilli())); err != nil {
		return fmt.Errorf("write creation timestamp: %w", err)
	}

	if err := e.writeCertificate(tce.Certificate); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}
