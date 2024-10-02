package keystore

import (
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	assert.Truef(t, actualPKE.CreationTime.Equal(expectedCT),
		"unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)

	assert.Empty(t, actualPKE.CertificateChain, "unexpected private key entry certificate chain length")

	pkPEM, err := os.ReadFile("./testdata/key.pem")
	require.NoError(t, err)

	decodedPK, _ := pem.Decode(pkPEM)

	assert.Equal(t, decodedPK.Bytes, actualPKE.PrivateKey, "unexpected private key")
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

	assert.Truef(t, actualPKE.CreationTime.Equal(expectedCT),
		"unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)

	assert.Lenf(t, actualPKE.CertificateChain, 1,
		"unexpected private key entry certificate chain length: '%d' '%d'", len(actualPKE.CertificateChain), 0)

	pkPEM, err := os.ReadFile("./testdata/key_keypass.pem")
	require.NoError(t, err)

	decodedPK, _ := pem.Decode(pkPEM)

	assert.Equal(t, decodedPK.Bytes, actualPKE.PrivateKey, "unexpected private key")
}

func TestLoadPkcs12(t *testing.T) {
	password := []byte("")

	f, err := os.Open("./testdata/keystore_temurin_openjdk_21.0.4_lts.p12")
	require.NoError(t, err)

	defer func() {
		err := f.Close()
		require.NoError(t, err)
	}()

	keyStore := New()

	err = keyStore.Load(f, password)
	require.NoError(t, err)

	assert.Len(t, keyStore.Aliases(), 148)
}
