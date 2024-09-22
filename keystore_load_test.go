package keystore

import (
	"encoding/pem"
	"github.com/corbym/gocrest/has"
	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	f, err := os.Open("./testdata/keystore.jks")
	then.AssertThat(t, err, is.Nil())

	defer func() {
		err := f.Close()
		then.AssertThat(t, err, is.Nil())
	}()

	keyStore := New()

	err = keyStore.Load(f, password)
	then.AssertThat(t, err, is.Nil())

	actualPKE, err := keyStore.GetPrivateKeyEntry("alias", password)
	then.AssertThat(t, err, is.Nil())

	expectedCT, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2017-09-19 17:41:00.016 +0300 EEST")
	then.AssertThat(t, err, is.Nil())

	if !actualPKE.CreationTime.Equal(expectedCT) {
		t.Errorf("unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)
	}

	if len(actualPKE.CertificateChain) != 0 {
		t.Errorf("unexpected private key entry certificate chain length: '%d' '%d'", len(actualPKE.CertificateChain), 0)
	}

	pkPEM, err := os.ReadFile("./testdata/key.pem")
	then.AssertThat(t, err, is.Nil())

	decodedPK, _ := pem.Decode(pkPEM)

	if !reflect.DeepEqual(actualPKE.PrivateKey, decodedPK.Bytes) {
		t.Errorf("unexpected private key")
	}
}

func TestLoadPkcs12_openjdk(t *testing.T) {
	password := []byte("")

	f, err := os.Open("./testdata/openjdk_temurin_21_cacerts.p12")
	then.AssertThat(t, err, is.Nil())

	defer func() {
		err := f.Close()
		then.AssertThat(t, err, is.Nil())
	}()

	keyStore := New()
	err = keyStore.Load(f, password)
	then.AssertThat(t, err, is.Nil())

	then.AssertThat(t, keyStore.Aliases(), has.Length(148))
}

func TestLoadKeyPassword(t *testing.T) {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	keyPassword := []byte{'k', 'e', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(keyPassword)

	f, err := os.Open("./testdata/keystore_keypass.jks")
	if err != nil {
		t.Fatalf("open test data keystore file: %s", err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close test data keystore file: %s", err)
		}
	}()

	keyStore := New()

	if err := keyStore.Load(f, password); err != nil {
		t.Fatalf("decode test data keystore: %s", err)
	}

	actualPKE, err := keyStore.GetPrivateKeyEntry("alias", keyPassword)
	if err != nil {
		t.Fatalf("get private key entry: %s", err)
	}

	expectedCT, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2020-10-26 12:01:38.387 +0200 EET")
	if err != nil {
		t.Fatalf("parse creation time: %s", err)
	}

	if !actualPKE.CreationTime.Equal(expectedCT) {
		t.Errorf("unexpected private key entry creation time: '%v' '%v'", actualPKE.CreationTime, expectedCT)
	}

	if len(actualPKE.CertificateChain) != 1 {
		t.Errorf("unexpected private key entry certificate chain length: '%d' '%d'", len(actualPKE.CertificateChain), 0)
	}

	pkPEM, err := os.ReadFile("./testdata/key_keypass.pem")
	if err != nil {
		t.Fatalf("read expected private key file: %s", err)
	}

	decodedPK, _ := pem.Decode(pkPEM)

	if !reflect.DeepEqual(actualPKE.PrivateKey, decodedPK.Bytes) {
		t.Errorf("unexpected private key %v \n %v", actualPKE.PrivateKey, decodedPK.Bytes)
	}
}
