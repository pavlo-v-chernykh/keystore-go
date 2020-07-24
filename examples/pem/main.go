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
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
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
	err = keystore.Encode(f, keyStore, password)
	if err != nil {
		log.Fatal(err)
	}
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

func main() {
	// openssl genrsa 1024 | openssl pkcs8 -topk8 -inform pem -outform pem -nocrypt -out privkey.pem
	pke, err := ioutil.ReadFile("./privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	p, _ := pem.Decode(pke)
	if p == nil {
		log.Fatal("Should have at least one pem block")
	}
	if p.Type != "PRIVATE KEY" {
		log.Fatal("Should be a rsa private key")
	}

	keyStore := keystore.KeyStore{
		"alias": &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationTime: time.Now(),
			},
			PrivateKey: p.Bytes,
		},
	}

	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)
	writeKeyStore(keyStore, "keystore.jks", password)

	ks := readKeyStore("keystore.jks", password)

	entry := ks["alias"]
	privKeyEntry := entry.(*keystore.PrivateKeyEntry)
	key, err := x509.ParsePKCS8PrivateKey(privKeyEntry.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%v", key)
}
