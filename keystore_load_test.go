package keystore

import (
	"bytes"
	_ "embed"
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

//go:embed testdata/java/adoptium_openjdk_21.0.4_lts/cacerts
var fileJavaTemurinOpenJdk21Cacerts []byte

//go:embed testdata/java/adoptium_openjdk_23.0.1.11/cacerts
var fileJavaTemurinOpenJdk23Cacerts []byte

//go:embed testdata/java/corretto-8.432.06.1/cacerts
var fileJavaCorretto8Cacerts []byte

//go:embed testdata/java/corretto-11.0.25.9.1/cacerts
var fileJavaCorretto11Cacerts []byte

//go:embed testdata/java/oracle_openjdk_17.0.6/cacerts
var fileJavaOracleOpenJdk17Cacerts []byte

func TestLoadVariousJdkTruststores(t *testing.T) {

	tests := []struct {
		name                 string
		certData             []byte
		numberOfCertificates int
		password             string
	}{
		{
			name:                 "adoptium_openjdk_21.0.4_lts",
			certData:             fileJavaTemurinOpenJdk21Cacerts,
			password:             "",
			numberOfCertificates: 148,
		},
		{
			name:                 "adoptium_openjdk_23.0.1.11",
			certData:             fileJavaTemurinOpenJdk23Cacerts,
			password:             "",
			numberOfCertificates: 152,
		},
		{
			name:                 "corretto-8.432.06.1",
			certData:             fileJavaCorretto8Cacerts,
			password:             "changeit",
			numberOfCertificates: 161,
		},
		{
			name:                 "corretto-11.0.25.9.1",
			certData:             fileJavaCorretto11Cacerts,
			password:             "changeit",
			numberOfCertificates: 161,
		},
		{
			name:                 "oracle_openjdk_17.0.6",
			certData:             fileJavaOracleOpenJdk17Cacerts,
			password:             "changeit",
			numberOfCertificates: 90,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := []byte(tt.password)
			adoptiumOpenJdkKeystore := bytes.NewReader(tt.certData)

			keyStore := New()
			err := keyStore.Load(adoptiumOpenJdkKeystore, password)
			require.NoError(t, err)

			assert.Len(t, keyStore.Aliases(), tt.numberOfCertificates)
		})
	}
}

////go:embed testdata/certificate_chain/truststore.p12
//var fileCertificateChainTruststoreP12 []byte
//
//func TestLoadPkcs12WithPassword(t *testing.T) {
//	password := []byte("password")
//	selfSignedCert := bytes.NewReader(fileCertificateChainTruststoreP12)
//
//	keyStore := New()
//	err := keyStore.Load(selfSignedCert, password)
//	require.NoError(t, err)
//
//	assert.Len(t, keyStore.Aliases(), 1)
//}

//go:embed testdata/certificate_chain/example_signed_certificates_chain.p12
var fileCertificateChainExampleSignedCertificateChainP12 []byte

func TestLoadPkcs12WithCertficateChain(t *testing.T) {
	password := []byte("password")
	selfSignedCert := bytes.NewReader(fileCertificateChainExampleSignedCertificateChainP12)

	keyStore := New()
	err := keyStore.Load(selfSignedCert, password)
	require.NoError(t, err)

	assert.Len(t, keyStore.Aliases(), 2)

	for _, alias := range keyStore.Aliases() {
		chain, err := keyStore.GetPrivateKeyEntryCertificateChain(alias)
		require.NoError(t, err)

		assert.NotNil(t, chain)
	}
}

////go:embed testdata/x.p12
//var x []byte

//func TestX(t *testing.T) {
//	password := []byte("password")
//	selfSignedCert := bytes.NewReader(x)
//
//	keyStore := New()
//	err := keyStore.Load(selfSignedCert, password)
//	require.NoError(t, err)
//
//	//assert.Len(t, keyStore.Aliases(), 2)
//
//	for _, alias := range keyStore.Aliases() {
//		chain, err := keyStore.GetPrivateKeyEntryCertificateChain(alias)
//		require.NoError(t, err)
//
//		assert.NotNil(t, chain)
//	}
//}
