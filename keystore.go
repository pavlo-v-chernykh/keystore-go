package keystore

import (
	"errors"
	"time"
)

const (
	reasonNoSuchEntry        = "No such entry"
	reasonIncorrectEntryType = "Incorrect entry type"
)

// ErrNoSuchEntry indicates absence of entry in the keystore
var ErrNoSuchEntry = errors.New(reasonNoSuchEntry)

// ErrIncorrectEntryType indicates incorrect entry type addressing
var ErrIncorrectEntryType = errors.New(reasonIncorrectEntryType)

// KeyStore is a map alias to entry
type KeyStore map[string]interface{}

// Certificate describes type of certificate
type Certificate struct {
	Type    string
	Content []byte
}

// Entry is a basis of entries types supported by keystore
type Entry struct {
	CreationDate time.Time
}

// PrivateKeyEntry is an entry for private keys and associated certificates
type PrivateKeyEntry struct {
	Entry
	PrivKey   []byte
	CertChain []Certificate
}

// TrustedCertificateEntry is an entry for certificates only
type TrustedCertificateEntry struct {
	Entry
	Certificate Certificate
}

// GetEntry allows to get entry from KeyStore
func (ks KeyStore) GetEntry(alias string) (interface{}, error) {
	entry, ok := ks[alias]
	if !ok {
		return nil, ErrNoSuchEntry
	}
	return entry, nil
}

// GetPrivateKeyEntry allows to get private key entry from KeyStore
func (ks KeyStore) GetPrivateKeyEntry(alias string) (*PrivateKeyEntry, error) {
	entry, err := ks.GetEntry(alias)
	if err != nil {
		return nil, err
	}
	privKeyEntry, ok := entry.(*PrivateKeyEntry)
	if !ok {
		return nil, ErrIncorrectEntryType
	}
	return privKeyEntry, nil
}

// GetTrustedCertificateEntry allows to get TrustedCertificateEntry from KeyStore
func (ks KeyStore) GetTrustedCertificateEntry(alias string) (*TrustedCertificateEntry, error) {
	entry, err := ks.GetEntry(alias)
	if err != nil {
		return nil, err
	}
	trustedCertEntry, ok := entry.(*TrustedCertificateEntry)
	if !ok {
		return nil, ErrIncorrectEntryType
	}
	return trustedCertEntry, nil
}
