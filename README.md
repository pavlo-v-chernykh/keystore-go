# Keystore
A go (golang) implementation of Java [KeyStore][1] encoder/decoder

### Example

```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/pavel-v-chernykh/keystore-go"
	"log"
	"os"
	"reflect"
)

func readKeyStore(filename, password string) (keystore.KeyStore, error) {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		return nil, err
	}
	return keyStore, nil
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
	ks1, err := readKeyStore("keystore1.jks", "password")
	if err != nil {
		log.Fatal(err)
	}

	writeKeyStore(ks1, "keystore2.jks", "password")

	ks2, err := readKeyStore("keystore2.jks", "password")

	privKeyEntry, err := ks1.GetPrivateKeyEntry("alias")
	if err != nil {
		log.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(privKeyEntry.PrivKey)
	if err != nil {
		log.Fatal(err)
	}
	_, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("Should be a rsa private key")
	}

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Is equal: %v\n", reflect.DeepEqual(ks1, ks2))
}
```

[1]: https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement
