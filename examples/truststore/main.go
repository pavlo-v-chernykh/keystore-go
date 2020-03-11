package main

import (
	"crypto/x509"
	"log"
	"os"

	"github.com/pavel-v-chernykh/keystore-go"
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

// go run main.go "/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/jre/lib/security/cacerts" "changeit"
func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: <path> <password>")
	}
	ks := readKeyStore(os.Args[1], []byte(os.Args[2]))
	for _, e := range ks {
		switch k := e.(type) {
		case *keystore.PrivateKeyEntry:
			log.Fatal("found private key in truststore")
		case *keystore.TrustedCertificateEntry:
			cert, err := x509.ParseCertificates(k.Certificate.Content)
			if err != nil {
				log.Fatal(err)
			}
			log.Println(cert[0].Subject.Organization)
		}
	}
}
