package keystore

import (
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	err := ks.SetPrivateKeyEntry(pkeAlias, pke, password)
	require.NoError(t, err)

	err = ks.SetTrustedCertificateEntry(tceAlias, tce)
	require.NoError(t, err)

	pkeGet, err := ks.GetPrivateKeyEntry(pkeAlias, password)
	require.NoError(t, err)

	chainGet, err := ks.GetPrivateKeyEntryCertificateChain(pkeAlias)
	require.NoError(t, err)

	tceGet, err := ks.GetTrustedCertificateEntry(tceAlias)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(pke, pkeGet), "private key entries not equal")
	assert.True(t, reflect.DeepEqual(pke.CertificateChain, chainGet), "certificate chains of private key entries are not equal")
	assert.True(t, reflect.DeepEqual(tce, tceGet), "private key entries not equal")

	_, err = ks.GetPrivateKeyEntry(nonExistentAlias, password)
	require.ErrorIs(t, err, ErrEntryNotFound)

	_, err = ks.GetTrustedCertificateEntry(nonExistentAlias)
	require.ErrorIs(t, err, ErrEntryNotFound)
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

	err := ks.SetPrivateKeyEntry(pkeAlias, pke, []byte("password"))
	require.NoError(t, err)

	err = ks.SetTrustedCertificateEntry(tceAlias, tce)
	require.NoError(t, err)

	assert.True(t, ks.IsPrivateKeyEntry(pkeAlias), "must be a private key entry")
	assert.False(t, ks.IsPrivateKeyEntry(tceAlias), "trusted certificate entry must be skipped")
	assert.False(t, ks.IsPrivateKeyEntry(nonExistentAlias), "non existent alias must be skipped")
	assert.True(t, ks.IsTrustedCertificateEntry(tceAlias), "must be a trusted certificate entry")
	assert.False(t, ks.IsTrustedCertificateEntry(pkeAlias), "private key entry must be skipped")
	assert.False(t, ks.IsTrustedCertificateEntry(nonExistentAlias), "non existent alias must be skipped")
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

	err := ks.SetPrivateKeyEntry(pkeAlias, pke, []byte("password"))
	require.NoError(t, err)

	err = ks.SetTrustedCertificateEntry(tceAlias, tce)
	require.NoError(t, err)

	expectedAliases := []string{pkeAlias, tceAlias}

	sort.Strings(expectedAliases)

	actualAliases := ks.Aliases()

	sort.Strings(actualAliases)

	assert.True(t, reflect.DeepEqual(expectedAliases, actualAliases), "aliases must be equal")
}

func TestLoad(t *testing.T) {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	f, err := os.Open("./testdata/keystore.jks")
	require.NoError(t, err)

	defer func() {
		err := f.Close()
		require.NoError(t, err)
	}()

	keyStore := New()

	err = keyStore.Load(f, password)
	require.NoError(t, err)

	actualPKE, err := keyStore.GetPrivateKeyEntry("alias", password)
	require.NoError(t, err)

	expectedCT, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2017-09-19 17:41:00.016 +0300 EEST")
	require.NoError(t, err)

	assert.Truef(t, actualPKE.CreationTime.Equal(expectedCT), "unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)

	assert.Lenf(t, actualPKE.CertificateChain, 0, "unexpected private key entry certificate chain length: '%d' '%d'", len(actualPKE.CertificateChain), 0)

	pkPEM, err := os.ReadFile("./testdata/key.pem")
	require.NoError(t, err)

	decodedPK, _ := pem.Decode(pkPEM)

	assert.True(t, reflect.DeepEqual(actualPKE.PrivateKey, decodedPK.Bytes), "unexpected private key")
}

func TestLoadKeyPassword(t *testing.T) {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	keyPassword := []byte{'k', 'e', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(keyPassword)

	f, err := os.Open("./testdata/keystore_keypass.jks")
	require.NoError(t, err)

	defer func() {
		err := f.Close()
		require.NoError(t, err)
	}()

	keyStore := New()

	err = keyStore.Load(f, password)
	require.NoError(t, err)

	actualPKE, err := keyStore.GetPrivateKeyEntry("alias", keyPassword)
	require.NoError(t, err)

	expectedCT, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2020-10-26 12:01:38.387 +0200 EET")
	require.NoError(t, err)

	assert.Truef(t, actualPKE.CreationTime.Equal(expectedCT), "unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)

	assert.Lenf(t, actualPKE.CertificateChain, 1, "unexpected private key entry certificate chain length: '%d' '%d'", len(actualPKE.CertificateChain), 0)

	pkPEM, err := os.ReadFile("./testdata/key_keypass.pem")
	require.NoError(t, err)

	decodedPK, _ := pem.Decode(pkPEM)

	assert.Truef(t, reflect.DeepEqual(actualPKE.PrivateKey, decodedPK.Bytes), "unexpected private key %v \n %v", actualPKE.PrivateKey, decodedPK.Bytes)
}

func readPrivateKey(t *testing.T) []byte {
	t.Helper()

	pkPEM, err := os.ReadFile("./testdata/key.pem")
	require.NoError(t, err)

	b, _ := pem.Decode(pkPEM)
	assert.NotNil(t, b, "should have at least one pem block")
	assert.Equal(t, "PRIVATE KEY", b.Type, "should be a private key")

	return b.Bytes
}

func readCertificate(t *testing.T) []byte {
	t.Helper()

	pkPEM, err := os.ReadFile("./testdata/cert.pem")
	require.NoError(t, err)

	b, _ := pem.Decode(pkPEM)
	assert.NotNil(t, b, "should have at least one pem block")
	assert.Equal(t, "CERTIFICATE", b.Type, "should be a certificate")

	return b.Bytes
}
