package main

import (
	"log"
	"os"
	"reflect"

	"github.com/pavel-v-chernykh/keystore-go/v4"
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

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

func main() {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)
	ks1 := readKeyStore("keystore.jks", password)

	writeKeyStore(ks1, "keystore2.jks", password)

	ks2 := readKeyStore("keystore2.jks", password)

	log.Printf("is equal: %v\n", reflect.DeepEqual(ks1, ks2))
}
