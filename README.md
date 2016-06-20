# Keystore
A go (golang) implementation of Java [KeyStore][1] decoder

### Example

```go
package main

import (
	"github.com/pavel-v-chernykh/keystore-go"
	"os"
	"log"
	"fmt"
	"crypto/x509"
	"crypto/rsa"
)

func main() {
	f, err := os.Open("./keystore.jks")
	if err != nil {
		log.Fatal(err)
	}
	keyStore, err := keystore.Decode(f, "password")
	if err != nil {
		log.Fatal(err)
	}
	privKeyEntry, err := keyStore.GetPrivateKeyEntry("alias")
	if err != nil {
		log.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(privKeyEntry.PrivKey)
	if err != nil {
		log.Fatal(err)
	}
	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("Should be a rsa private key")
	}
	fmt.Printf("RSA: %v\n", rsaPrivateKey.PublicKey)
}
```

[1]: https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement
