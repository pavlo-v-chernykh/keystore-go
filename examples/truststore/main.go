package main

import (
	"crypto/x509"
	"log"
	"os"

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

// nolint: godot, lll
// go run main.go "/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/jre/lib/security/cacerts" "changeit"
func main() {
	if len(os.Args) < 3 { // nolint: gomnd
		log.Fatal("usage: <path> <password>")
	}

	ks := readKeyStore(os.Args[1], []byte(os.Args[2]))

	for _, a := range ks.Aliases() {
		tce, err := ks.GetTrustedCertificateEntry(a)
		if err != nil {
			log.Fatal(err)
		}

		cert, err := x509.ParseCertificates(tce.Certificate.Content)
		if err != nil {
			log.Fatal(err)
		}

		log.Println(cert[0].Subject)
	}
}
