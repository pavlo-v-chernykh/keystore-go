package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/pavel-v-chernykh/keystore-go/v3"
)

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	keyStore := keystore.New()
	if err := keyStore.Load(f, password); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = keyStore.Store(f, password)
	if err != nil {
		log.Fatal(err) // nolint: gocritic
	}
}

func readPrivateKey() []byte {
	pkPEM, err := ioutil.ReadFile("./key.pem")
	if err != nil {
		log.Fatal(err)
	}

	b, _ := pem.Decode(pkPEM)
	if b == nil {
		log.Fatal("should have at least one pem block")
	}

	if b.Type != "PRIVATE KEY" {
		log.Fatal("should be a private key")
	}

	return b.Bytes
}

func readCertificate() []byte {
	pkPEM, err := ioutil.ReadFile("./cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	b, _ := pem.Decode(pkPEM)
	if b == nil {
		log.Fatal("should have at least one pem block")
	}

	if b.Type != "CERTIFICATE" {
		log.Fatal("should be a certificate")
	}

	return b.Bytes
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

// nolint: godot, lll
// openssl req -x509 -sha256 -nodes -days 365 -subj '/CN=localhost' -newkey rsa:2048 -outform pem -keyout key.pem -out cert.pem
func main() {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	keyStore := keystore.New()

	pkeIn := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   readPrivateKey(),
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: readCertificate(),
			},
		},
	}

	if err := keyStore.SetPrivateKeyEntry("alias", pkeIn, password); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	writeKeyStore(keyStore, "keystore.jks", password)

	ks := readKeyStore("keystore.jks", password)

	pkeOut, err := ks.GetPrivateKeyEntry("alias", password)
	if err != nil {
		log.Fatal(err)
	}

	key, err := x509.ParsePKCS8PrivateKey(pkeOut.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%v", key)
}
