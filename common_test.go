package keystore

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestZeroing(t *testing.T) {
	var table [][]byte

	for i := 0; i < 20; i++ {
		buf := make([]byte, 4096)
		if _, err := rand.Read(buf); err != nil {
			t.Errorf("read random bytes: %v", err)
		}

		table = append(table, buf)
	}

	for _, tt := range table {
		zeroing(tt)

		for i := range tt {
			if tt[i] != 0 {
				t.Errorf("fill input with zeros '%v'", tt)
			}
		}
	}
}

func TestPasswordBytes(t *testing.T) {
	type item struct {
		input  []byte
		output []byte
	}

	var table []item

	for i := 0; i < 20; i++ {
		input := make([]byte, 1024)
		if _, err := rand.Read(input); err != nil {
			t.Errorf("read random bytes: %v", err)
		}

		output := make([]byte, len(input)*2)

		for j, k := 0, 0; j < len(output); j, k = j+2, k+1 {
			output[j] = 0
			output[j+1] = input[k]
		}

		table = append(table, item{input: input, output: output})
	}

	for _, tt := range table {
		output := passwordBytes(tt.input)
		if !reflect.DeepEqual(output, tt.output) {
			t.Errorf("convert password bytes '%v', '%v'", output, tt.output)
		}
	}
}
