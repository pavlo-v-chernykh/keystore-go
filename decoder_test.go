package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"reflect"
	"testing"
)

func TestReadUint16(t *testing.T) {
	type item struct {
		input  []byte
		number uint16
		err    error
		hash   [sha1.Size]byte
	}

	var table = func() []item {
		var table []item
		table = append(table, item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read 2 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read 2 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{1},
			number: 0,
			err:    fmt.Errorf("read 2 bytes: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 2)
		var number uint16 = 10
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 2)
		number = 0
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		number, err := d.readUint16()
		assert.Truef(t, reflect.DeepEqual(err, tt.err), "invalid error '%v' '%v'", err, tt.err)

		if err == nil {
			assert.Equal(t, tt.number, number)
		}

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}

func TestReadUint32(t *testing.T) {
	type item struct {
		input  []byte
		number uint32
		err    error
		hash   [sha1.Size]byte
	}

	var table = func() []item {
		var table []item
		table = append(table, item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read 4 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read 4 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{1, 2, 3},
			number: 0,
			err:    fmt.Errorf("read 4 bytes: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 4)
		var number uint32 = 10
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 4)
		number = 0
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		number, err := d.readUint32()
		assert.Truef(t, reflect.DeepEqual(err, tt.err), "invalid error '%v' '%v'", err, tt.err)

		if err == nil {
			assert.Equal(t, tt.number, number)
		}

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}

func TestReadUint64(t *testing.T) {
	type item struct {
		input  []byte
		number uint64
		err    error
		hash   [sha1.Size]byte
	}

	table := func() []item {
		var table []item
		table = append(table, item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read 8 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read 8 bytes: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{1, 2, 3},
			number: 0,
			err:    fmt.Errorf("read 8 bytes: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 8)

		var number uint64 = 10

		binary.BigEndian.PutUint64(buf, number)

		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 8)
		number = 0
		binary.BigEndian.PutUint64(buf, number)

		table = append(table, item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		number, err := d.readUint64()
		assert.Truef(t, reflect.DeepEqual(err, tt.err), "invalid error '%v' '%v'", err, tt.err)

		if err == nil {
			assert.Equal(t, tt.number, number)
		}

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}

func TestReadBytes(t *testing.T) {
	type item struct {
		input   []byte
		readLen uint32
		bytes   []byte
		hash    [sha1.Size]byte
	}

	table := func() []item {
		var table []item
		table = append(table, item{
			input:   nil,
			readLen: 0,
			bytes:   []byte{},
			hash:    sha1.Sum(nil),
		})
		table = append(table, item{
			input:   []byte{1, 2, 3},
			readLen: 3,
			bytes:   []byte{1, 2, 3},
			hash:    sha1.Sum([]byte{1, 2, 3}),
		})
		table = append(table, item{
			input:   []byte{1, 2, 3},
			readLen: 2,
			bytes:   []byte{1, 2},
			hash:    sha1.Sum([]byte{1, 2}),
		})
		buf := func() []byte {
			buf := make([]byte, 10*1024)
			_, err := rand.Read(buf)
			require.NoError(t, err)

			return buf
		}()

		table = append(table, item{
			input:   buf,
			readLen: 9 * 1024,
			bytes:   buf[:9*1024],
			hash:    sha1.Sum(buf[:9*1024]),
		})

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		bts, err := d.readBytes(tt.readLen)
		require.NoError(t, err)

		assert.Truef(t, reflect.DeepEqual(bts, tt.bytes), "invalid bytes '%v' '%v'", bts, tt.bytes)

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}

func TestReadString(t *testing.T) {
	type item struct {
		input  []byte
		string string
		err    error
		hash   [sha1.Size]byte
	}

	table := func() []item {
		var table []item
		table = append(table, item{
			input:  nil,
			string: "",
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read 2 bytes: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{},
			string: "",
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read 2 bytes: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, item{
			input:  []byte{1, 2, 3},
			string: "",
			err: fmt.Errorf("read body: %w",
				fmt.Errorf("read 258 bytes: %w",
					io.ErrUnexpectedEOF)),
			hash: sha1.Sum([]byte{1, 2}),
		})
		str := "some string to read"
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(len(str)))
		buf = append(buf, []byte(str)...)
		table = append(table, item{
			input:  buf,
			string: str,
			err:    nil,
			hash:   sha1.Sum(buf),
		})

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		str, err := d.readString()
		assert.Truef(t, reflect.DeepEqual(err, tt.err), "invalid error '%v' '%v'", err, tt.err)
		assert.Equal(t, tt.string, str)

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}

func TestReadCertificate(t *testing.T) {
	type item struct {
		input   []byte
		version uint32
		cert    Certificate
		err     error
		hash    [sha1.Size]byte
	}

	var table = func() []item {
		var table []item
		table = append(table, item{
			input:   nil,
			version: version01,
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read 4 bytes: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, item{
			input:   nil,
			version: version02,
			err: fmt.Errorf("read type: %w",
				fmt.Errorf("read length: %w",
					fmt.Errorf("read 2 bytes: %w",
						io.EOF))),
			hash: sha1.Sum(nil),
		})
		table = append(table, item{
			input:   nil,
			version: 3,
			err:     errors.New("got unknown version"),
			hash:    sha1.Sum(nil),
		})
		table = append(table, func() item {
			input := []byte{0, 0, 0, 0}

			return item{
				input:   input,
				version: version01,
				cert: Certificate{
					Type:    defaultCertificateType,
					Content: []byte{},
				},
				err:  nil,
				hash: sha1.Sum(input),
			}
		}())
		table = append(table, func() item {
			buf := make([]byte, 2)
			byteOrder.PutUint16(buf, uint16(len(defaultCertificateType)))
			buf = append(buf, []byte(defaultCertificateType)...)
			buf = append(buf, 0, 0, 0, 0)

			return item{
				input:   buf,
				version: version02,
				cert: Certificate{
					Type:    defaultCertificateType,
					Content: []byte{},
				},
				err:  nil,
				hash: sha1.Sum(buf),
			}
		}())
		table = append(table, func() item {
			buf := make([]byte, 2)
			byteOrder.PutUint16(buf, uint16(len(defaultCertificateType)))
			buf = append(buf, []byte(defaultCertificateType)...)
			buf = append(buf, 0, 0, 0, 1)

			return item{
				input:   buf,
				version: version02,
				err: fmt.Errorf("read content: %w",
					fmt.Errorf("read 1 bytes: %w",
						io.EOF)),
				hash: sha1.Sum(buf),
			}
		}())

		return table
	}()

	for _, tt := range table {
		d := decoder{
			r: bytes.NewReader(tt.input),
			h: sha1.New(),
		}

		cert, err := d.readCertificate(tt.version)
		assert.Truef(t, reflect.DeepEqual(err, tt.err), "invalid error '%v' '%v'", err, tt.err)
		assert.Truef(t, reflect.DeepEqual(cert, tt.cert), "invalid certificate '%v' '%v'", cert, tt.cert)

		hash := d.h.Sum(nil)
		assert.Truef(t, reflect.DeepEqual(hash, tt.hash[:]), "invalid hash '%v' '%v'", hash, tt.hash)
	}
}
