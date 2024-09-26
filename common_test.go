package keystore

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestZeroing(t *testing.T) {
	var table [][]byte

	for i := 0; i < 20; i++ {
		buf := make([]byte, 4096)
		_, err := rand.Read(buf)
		require.NoError(t, err)

		table = append(table, buf)
	}

	for _, tt := range table {
		zeroing(tt)

		for i := range tt {
			assert.Equalf(t, uint8(0), tt[i], "fill input with zeros '%v'", tt)
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
		_, err := rand.Read(input)
		require.NoError(t, err)

		output := make([]byte, len(input)*2)

		for j, k := 0, 0; j < len(output); j, k = j+2, k+1 {
			output[j] = 0
			output[j+1] = input[k]
		}

		table = append(table, item{input: input, output: output})
	}

	for _, tt := range table {
		output := passwordBytes(tt.input)
		assert.Truef(t, reflect.DeepEqual(output, tt.output), "convert password bytes '%v', '%v'", output, tt.output)
	}
}
