[![Gitpod ready-to-code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/pavlo-v-chernykh/keystore-go)

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

	"github.com/pavlo-v-chernykh/keystore-go/v4"
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

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		log.Fatal(err) //nolint: gocritic
	}

	return ks
}

func writeKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		log.Fatal(err) //nolint: gocritic
	}
}

func zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
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
```

For more examples explore [examples](examples) dir

## Development

1. Install [go][2]
2. Install [golangci-lint][3]
3. Clone the repo `git clone git@github.com:pavlo-v-chernykh/keystore-go.git`
4. Go to the project dir `cd keystore-go`
5. Run `make`  to format, test and lint

[1]: https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement
[2]: https://golang.org
[3]: https://github.com/golangci/golangci-lint
