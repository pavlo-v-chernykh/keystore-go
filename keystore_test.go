package keystore

import (
	"encoding/pem"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, pke, pkeGet)

	chainGet, err := ks.GetPrivateKeyEntryCertificateChain(pkeAlias)
	require.NoError(t, err)
	assert.Equal(t, pke.CertificateChain, chainGet)

	tceGet, err := ks.GetTrustedCertificateEntry(tceAlias)
	require.NoError(t, err)
	assert.Equal(t, tce, tceGet)

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

	assert.Equal(t, expectedAliases, actualAliases)
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
