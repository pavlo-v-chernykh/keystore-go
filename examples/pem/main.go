// +build ignore

package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/pavel-v-chernykh/keystore-go"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func readKeyStore(filename, password string) keystore.KeyStore {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename, password string) {
	o, err := os.Create(filename)
	defer o.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// openssl genrsa -out privkey.pem 1024
	pke, err := ioutil.ReadFile("./privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	p, _ := pem.Decode(pke)
	if p == nil {
		log.Fatal("Should have at least one pem block")
	}
	if p.Type != "RSA PRIVATE KEY" {
		log.Fatal("Should be a rsa private key")
	}

	keyStore := keystore.KeyStore{
		"alias": &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			PrivKey: p.Bytes,
		},
	}

	writeKeyStore(keyStore, "keystore.jks", "password")

	ks := readKeyStore("keystore.jks", "password")

	entry := ks["alias"]
	privKeyEntry := entry.(*keystore.PrivateKeyEntry)
	key, err := x509.ParsePKCS1PrivateKey(privKeyEntry.PrivKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%v", key)
}
