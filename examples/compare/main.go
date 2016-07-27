// +build ignore

package main

import (
	"github.com/pavel-v-chernykh/keystore-go"
	"log"
	"os"
	"reflect"
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
	ks1 := readKeyStore("keystore.jks", "password")

	writeKeyStore(ks1, "keystore2.jks", "password")

	ks2 := readKeyStore("keystore2.jks", "password")

	log.Printf("Is equal: %v\n", reflect.DeepEqual(ks1, ks2))
}
