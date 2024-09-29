package keystore

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZeroing(t *testing.T) {
	const tableLength = 20

	var table = make([][]byte, tableLength)

	for i := range tableLength {
		buf := make([]byte, 4096)
		_, err := rand.Read(buf)
		require.NoError(t, err)

		table[i] = buf
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

	const tableLength = 20

	var table = make([]item, tableLength)

	for i := range tableLength {
		input := make([]byte, 1024)
		_, err := rand.Read(input)
		require.NoError(t, err)

		output := make([]byte, len(input)*2)

		for j, k := 0, 0; j < len(output); j, k = j+2, k+1 {
			output[j] = 0
			output[j+1] = input[k]
		}

		table[i] = item{input: input, output: output}
	}

	for _, tt := range table {
		output := passwordBytes(tt.input)
		assert.Truef(t, reflect.DeepEqual(output, tt.output), "convert password bytes '%v', '%v'", output, tt.output)
	}
}
