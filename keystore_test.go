package keystore

import (
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestSetGetMethods(t *testing.T) {
	ks := New()
	pke := PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   readPrivateKey(t),
		CertificateChain: []Certificate{
			{
				Type:    "X509",
				Content: readCertificate(t),
			},
		},
	}
	tce := TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: Certificate{
			Type:    "X509",
			Content: readCertificate(t),
		},
	}

	const (
		pkeAlias         = "pkeAlias"
		tceAlias         = "tceAlias"
		nonExistentAlias = "nonExistentAlias"
	)

	password := []byte("password")

	if err := ks.SetPrivateKeyEntry(pkeAlias, pke, password); err != nil {
		t.Fatal(err)
	}

	if err := ks.SetTrustedCertificateEntry(tceAlias, tce); err != nil {
		t.Fatal(err)
	}

	pkeGet, err := ks.GetPrivateKeyEntry(pkeAlias, password)
	if err != nil {
		t.Fatal(err)
	}

	chainGet, err := ks.GetPrivateKeyEntryCertificateChain(pkeAlias)
	if err != nil {
		t.Fatal(err)
	}

	tceGet, err := ks.GetTrustedCertificateEntry(tceAlias)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pke, pkeGet) {
		t.Fatal("private key entries not equal")
	}

	if !reflect.DeepEqual(pke.CertificateChain, chainGet) {
		t.Fatal("certificate chains of private key entries are not equal")
	}

	if !reflect.DeepEqual(tce, tceGet) {
		t.Fatal("private key entries not equal")
	}

	if _, err := ks.GetPrivateKeyEntry(nonExistentAlias, password); !errors.Is(err, ErrEntryNotFound) {
		t.Fatal(err)
	}

	if _, err := ks.GetTrustedCertificateEntry(nonExistentAlias); !errors.Is(err, ErrEntryNotFound) {
		t.Fatal(err)
	}
}

func TestIsMethods(t *testing.T) {
	ks := New()
	pke := PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   readPrivateKey(t),
		CertificateChain: []Certificate{
			{
				Type:    "X509",
				Content: readCertificate(t),
			},
		},
	}
	tce := TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: Certificate{
			Type:    "X509",
			Content: readCertificate(t),
		},
	}

	const (
		pkeAlias         = "pkeAlias"
		tceAlias         = "tceAlias"
		nonExistentAlias = "nonExistentAlias"
	)

	if err := ks.SetPrivateKeyEntry(pkeAlias, pke, []byte("password")); err != nil {
		t.Fatal(err)
	}

	if err := ks.SetTrustedCertificateEntry(tceAlias, tce); err != nil {
		t.Fatal(err)
	}

	if !ks.IsPrivateKeyEntry(pkeAlias) {
		t.Fatal("must be a private key entry")
	}

	if ks.IsPrivateKeyEntry(tceAlias) {
		t.Fatal("trusted certificate entry must be skipped")
	}

	if ks.IsPrivateKeyEntry(nonExistentAlias) {
		t.Fatal("non existent alias must be skipped")
	}

	if !ks.IsTrustedCertificateEntry(tceAlias) {
		t.Fatal("must be a trusted certificate entry")
	}

	if ks.IsTrustedCertificateEntry(pkeAlias) {
		t.Fatal("private key entry must be skipped")
	}

	if ks.IsTrustedCertificateEntry(nonExistentAlias) {
		t.Fatal("non existent alias must be skipped")
	}
}

func TestAliases(t *testing.T) {
	ks := New()
	pke := PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   readPrivateKey(t),
		CertificateChain: []Certificate{
			{
				Type:    "X509",
				Content: readCertificate(t),
			},
		},
	}
	tce := TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: Certificate{
			Type:    "X509",
			Content: readCertificate(t),
		},
	}

	const (
		pkeAlias = "pke-alias"
		tceAlias = "tce-alias"
	)

	if err := ks.SetPrivateKeyEntry(pkeAlias, pke, []byte("password")); err != nil {
		t.Fatal(err)
	}

	if err := ks.SetTrustedCertificateEntry(tceAlias, tce); err != nil {
		t.Fatal(err)
	}

	expectedAliases := []string{pkeAlias, tceAlias}

	sort.Strings(expectedAliases)

	actualAliases := ks.Aliases()

	sort.Strings(actualAliases)

	if !reflect.DeepEqual(expectedAliases, actualAliases) {
		t.Fatal("aliases must be equal")
	}
}

func readPrivateKey(t *testing.T) []byte {
	t.Helper()

	pkPEM, err := os.ReadFile("./testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	b, _ := pem.Decode(pkPEM)
	if b == nil {
		t.Fatal("should have at least one pem block")
	}

	if b.Type != "PRIVATE KEY" {
		t.Fatal("should be a private key")
	}

	return b.Bytes
}

func readCertificate(t *testing.T) []byte {
	t.Helper()

	pkPEM, err := os.ReadFile("./testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	b, _ := pem.Decode(pkPEM)
	if b == nil {
		t.Fatal("should have at least one pem block")
	}

	if b.Type != "CERTIFICATE" {
		t.Fatal("should be a certificate")
	}

	return b.Bytes
}
