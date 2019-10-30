# Keystore
A go (golang) implementation of Java [KeyStore][1] encoder/decoder

Take into account that JKS assumes that private keys are PKCS8 encoded.

### Example

```go
package main

import (
	"log"
	"os"
	"reflect"
	
	"github.com/pavel-v-chernykh/keystore-go"
)

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer o.Close()
	err = keystore.Encode(o, keyStore, password)
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
	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)
	ks1 := readKeyStore("keystore.jks", password)

	writeKeyStore(ks1, "keystore2.jks", password)

	ks2 := readKeyStore("keystore2.jks", password)

	log.Printf("Is equal: %v\n", reflect.DeepEqual(ks1, ks2))
}
```

For more examples explore [examples](examples) dir

## Development

1. Install [go][2]
2. Install [mage][3]
3. Install [golangci-lint][4]
4. Clone the repo `git clone git@github.com:pavel-v-chernykh/keystore-go.git`
5. Go to the project dir `cd keystore-go`
4. Run `mage`  to format, test and lint

[1]: https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement
[2]: https://golang.org
[3]: https://github.com/magefile/mage
[4]: https://github.com/golangci/golangci-lint
