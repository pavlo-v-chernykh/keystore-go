package main

import (
	"crypto/x509"
	"log"
	"os"

	"github.com/pavel-v-chernykh/keystore-go/v3"
)

func readKeyStore(filename string, storePassword []byte, keysPasswords ...keystore.KeyPassword) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	keyStore, err := keystore.Decode(f, storePassword, keysPasswords...)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

// keytool -genkeypair -alias alias -storepass password -keypass keypassword -keyalg RSA -keystore keystore.jks
func main() {
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	keyPassword := []byte{'k', 'e', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)

	kp := keystore.KeyPassword{Alias: "alias", Password: keyPassword}
	ks := readKeyStore("keystore.jks", password, kp)

	entry := ks["alias"]
	privKeyEntry := entry.(*keystore.PrivateKeyEntry)

	key, err := x509.ParsePKCS8PrivateKey(privKeyEntry.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%#v", key)
}
