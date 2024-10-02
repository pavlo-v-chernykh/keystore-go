package keystore

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"

	"software.sslmate.com/src/go-pkcs12"
)

// Load reads keystore representation from r and checks its signature.
// It is strongly recommended to fill password slice with zero after usage.
func (ks KeyStore) Load(r io.Reader, password []byte) error {
	d := decoder{
		r: r,
		h: sha1.New(),
	}

	fourBytes, err := d.readBytes(4) //nolint:gomnd,mnd
	if err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	magicBytesReader := bytes.NewReader(fourBytes)
	fullReader := io.MultiReader(magicBytesReader, r)

	if bytes.Equal(fourBytes, jksMagicBytes) {
		return ks.loadJks(fullReader, password)
	}

	return ks.loadPkcs12(fullReader, password)
}

// loads the old JKS format.
func (ks KeyStore) loadJks(r io.Reader, password []byte) error {
	d := decoder{
		r: r,
		h: sha1.New(),
	}

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	if _, err := d.h.Write(passwordBytes); err != nil {
		return fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := d.h.Write(whitenerMessage); err != nil {
		return fmt.Errorf("update digest with whitener message: %w", err)
	}

	fourBytes, err := d.readBytes(4) //nolint:gomnd,mnd
	if err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	if !bytes.Equal(fourBytes, jksMagicBytes) {
		return errors.New("got invalid magic bytes from the file, this is no JKS format")
	}

	version, err := d.readUint32()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}

	entryNum, err := d.readUint32()
	if err != nil {
		return fmt.Errorf("read number of entries: %w", err)
	}

	for i := range entryNum {
		alias, entry, err := d.readEntry(version)
		if err != nil {
			return fmt.Errorf("read %d entry: %w", i, err)
		}

		ks.m[alias] = entry
	}

	computedDigest := d.h.Sum(nil)

	actualDigest, err := d.readBytes(uint32(d.h.Size())) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read digest: %w", err)
	}

	if !bytes.Equal(actualDigest, computedDigest) {
		return errors.New("got invalid digest")
	}

	return nil
}

// loads the newer PKCS12 format.
func (ks KeyStore) loadPkcs12(r io.Reader, password []byte) error {
	allData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("can't read pkcs12 data: %w", err)
	}

	certs, err := pkcs12.DecodeTrustStore(allData, string(password))
	if err != nil {
		return fmt.Errorf("can't decode pkcs12 trust strore: %w", err)
	}

	for _, cert := range certs {
		certificate := Certificate{
			Type:    "X509",
			Content: nil,
		}

		tce := TrustedCertificateEntry{}
		tce.CreationTime = cert.NotBefore // there is no better timestamp provided by pkcs12 file
		tce.Certificate = certificate
		alias := fmt.Sprintf("c_%s,o_%s,ou_%s,cn_%s,s_%s",
			cert.Subject.Country,
			cert.Subject.Organization,
			cert.Subject.OrganizationalUnit,
			cert.Subject.CommonName,
			cert.Subject.SerialNumber,
		)
		// Country, Organization, OrganizationalUnit []string
		// Locality, Province                        []string
		// StreetAddress, PostalCode                 []string
		// SerialNumber, CommonName                  string
		ks.m[ks.convertAlias(alias)] = tce
	}

	return nil
}
