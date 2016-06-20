package keystore

import (
	"time"
	"errors"
)

const (
	reasonNoSuchEntry = "No such entry"
	reasonIncorrectEntryType = "Incorrect entry type"
)

var ErrNoSuchEntry = errors.New(reasonNoSuchEntry)
var ErrIncorrectEntryType = errors.New(reasonIncorrectEntryType)

type KeyStore map[string]interface{}

type Certificate struct {
	Type    string
	Content []byte
}

type Entry struct {
	CreationDate time.Time
}

type PrivateKeyEntry struct {
	Entry
	PrivKey   []byte
	CertChain []Certificate
}

type TrustedCertificateEntry struct {
	Entry
	Certificate Certificate
}

func (ks KeyStore) GetEntry(alias string) (interface{}, error) {
	entry, ok := ks[alias]
	if !ok {
		return nil, ErrNoSuchEntry
	}
	return entry, nil
}

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

func (ks KeyStore) GetTrustedCertificateKeyEntry(alias string) (*TrustedCertificateEntry, error) {
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
