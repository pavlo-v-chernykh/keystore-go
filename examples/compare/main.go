package main

import (
	"encoding/pem"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

type nonRand struct {
}

func (r nonRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 1
	}

	return len(p), nil
}

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		panic(err)
	}

	return ks
}

func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		panic(err)
	}
}

func readPrivateKey() []byte {
	pkPEM, err := os.ReadFile("./key.pem")
	if err != nil {
		panic(err)
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
	pkPEM, err := os.ReadFile("./cert.pem")
	if err != nil {
		panic(err)
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

func zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func main() {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	ks1 := keystore.New(
		keystore.WithOrderedAliases(),
		keystore.WithCustomRandomNumberGenerator(nonRand{}),
	)

	ks2 := keystore.New(
		keystore.WithOrderedAliases(),
		keystore.WithCustomRandomNumberGenerator(nonRand{}),
	)

	ct := time.Now()

	pke1 := keystore.PrivateKeyEntry{
		CreationTime: ct,
		PrivateKey:   readPrivateKey(),
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: readCertificate(),
			},
		},
	}

	pke2 := keystore.PrivateKeyEntry{
		CreationTime: ct,
		PrivateKey:   readPrivateKey(),
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: readCertificate(),
			},
		},
	}

	if err := ks1.SetPrivateKeyEntry("pke1", pke1, password); err != nil {
		panic(err)
	}

	if err := ks1.SetPrivateKeyEntry("pke2", pke2, password); err != nil {
		panic(err)
	}

	if err := ks2.SetPrivateKeyEntry("pke1", pke1, password); err != nil {
		panic(err)
	}

	if err := ks2.SetPrivateKeyEntry("pke2", pke2, password); err != nil {
		panic(err)
	}

	writeKeyStore(ks1, "keystore1.jks", password)
	writeKeyStore(ks2, "keystore2.jks", password)

	ks1 = readKeyStore("keystore1.jks", password)

	ks2 = readKeyStore("keystore2.jks", password)

	log.Printf("is equal: %v\n", reflect.DeepEqual(ks1, ks2))
}
