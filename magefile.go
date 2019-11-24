// +build mage

package main

import (
	"fmt"

	"github.com/magefile/mage/sh"
)

var Default = All

func Fmt() error {
	if err := sh.Run("go", "fmt", "github.com/pavel-v-chernykh/keystore-go/..."); err != nil {
		return fmt.Errorf("go fmt: %w", err)
	}
	return nil
}

func Test() error {
	if err := sh.Run("go", "test", "-cover", "-count=1", "-v", "./..."); err != nil {
		return fmt.Errorf("go test: %w", err)
	}
	return nil
}

func Lint() error {
	if err := sh.Run("golangci-lint", "run"); err != nil {
		return fmt.Errorf("golangci-lint run: %w", err)
	}
	return nil
}

func All() error {
	if err := Fmt(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	return Lint()
}
