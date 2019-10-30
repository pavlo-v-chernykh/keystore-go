package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestReadUint16(t *testing.T) {
	type readUint16Item struct {
		input  []byte
		number uint16
		err    error
		hash   [sha1.Size]byte
	}
	var readUint32Table = func() []readUint16Item {
		var table []readUint16Item
		table = append(table, readUint16Item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read uint16: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint16Item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read uint16: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint16Item{
			input:  []byte{1},
			number: 0,
			err:    fmt.Errorf("read uint16: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 2)
		var number uint16 = 10
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, readUint16Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 2)
		number = 0
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, readUint16Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint16()
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("invalid error '%v' '%v'", err, tt.err)
		}
		if number != tt.number {
			t.Errorf("invalid number '%v' '%v'", number, tt.number)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}

func TestReadUint32(t *testing.T) {
	type readUint32Item struct {
		input  []byte
		number uint32
		err    error
		hash   [sha1.Size]byte
	}
	var readUint32Table = func() []readUint32Item {
		var table []readUint32Item
		table = append(table, readUint32Item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read uint32: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint32Item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read uint32: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint32Item{
			input:  []byte{1, 2, 3},
			number: 0,
			err:    fmt.Errorf("read uint32: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 4)
		var number uint32 = 10
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, readUint32Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 4)
		number = 0
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, readUint32Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint32()
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("invalid error '%v' '%v'", err, tt.err)
		}
		if number != tt.number {
			t.Errorf("invalid uint32 '%v' '%v'", number, tt.number)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}

func TestReadUint64(t *testing.T) {
	type readUint64Item struct {
		input  []byte
		number uint64
		err    error
		hash   [sha1.Size]byte
	}
	var readUint64Table = func() []readUint64Item {
		var table []readUint64Item
		table = append(table, readUint64Item{
			input:  nil,
			number: 0,
			err:    fmt.Errorf("read uint64: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint64Item{
			input:  []byte{},
			number: 0,
			err:    fmt.Errorf("read uint64: %w", io.EOF),
			hash:   sha1.Sum(nil),
		})
		table = append(table, readUint64Item{
			input:  []byte{1, 2, 3},
			number: 0,
			err:    fmt.Errorf("read uint64: %w", io.ErrUnexpectedEOF),
			hash:   sha1.Sum(nil),
		})
		buf := make([]byte, 8)
		var number uint64 = 10
		binary.BigEndian.PutUint64(buf, number)
		table = append(table, readUint64Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		buf = make([]byte, 8)
		number = 0
		binary.BigEndian.PutUint64(buf, number)
		table = append(table, readUint64Item{
			input:  buf,
			number: number,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		return table
	}()

	for _, tt := range readUint64Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint64()
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("invalid error '%v' '%v'", err, tt.err)
		}
		if number != tt.number {
			t.Errorf("invalid uint64 '%v' '%v'", number, tt.number)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}

func TestReadBytes(t *testing.T) {
	type readBytesItem struct {
		input   []byte
		readLen uint32
		bytes   []byte
		hash    [sha1.Size]byte
	}
	var readUint32Table = func() []readBytesItem {
		var table []readBytesItem
		table = append(table, readBytesItem{
			input:   nil,
			readLen: 0,
			bytes:   nil,
			hash:    sha1.Sum(nil),
		})
		table = append(table, readBytesItem{
			input:   []byte{1, 2, 3},
			readLen: 3,
			bytes:   []byte{1, 2, 3},
			hash:    sha1.Sum([]byte{1, 2, 3}),
		})
		table = append(table, readBytesItem{
			input:   []byte{1, 2, 3},
			readLen: 2,
			bytes:   []byte{1, 2},
			hash:    sha1.Sum([]byte{1, 2}),
		})
		buf := func() []byte {
			buf := make([]byte, 10*1024)
			if _, err := rand.Read(buf); err != nil {
				t.Errorf("read random bytes: %v", err)
			}
			return buf
		}()
		table = append(table, readBytesItem{
			input:   buf,
			readLen: 9 * 1024,
			bytes:   buf[:9*1024],
			hash:    sha1.Sum(buf[:9*1024]),
		})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		bts, err := ksd.readBytes(tt.readLen)
		if err != nil {
			t.Errorf("got error '%v'", err)
		}
		if !reflect.DeepEqual(bts, tt.bytes) {
			t.Errorf("invalid bytes '%v' '%v'", bts, tt.bytes)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}

func TestReadString(t *testing.T) {
	type readStringItem struct {
		input  []byte
		string string
		err    error
		hash   [sha1.Size]byte
	}
	var readUint32Table = func() []readStringItem {
		var table []readStringItem
		table = append(table, readStringItem{
			input:  nil,
			string: "",
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read uint16: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, readStringItem{
			input:  []byte{},
			string: "",
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read uint16: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, readStringItem{
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
		table = append(table, readStringItem{
			input:  buf,
			string: str,
			err:    nil,
			hash:   sha1.Sum(buf),
		})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		str, err := ksd.readString()
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("invalid error '%v' '%v'", err, tt.err)
		}
		if str != tt.string {
			t.Errorf("invalid string '%v' '%v'", str, tt.string)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}

func TestReadCertificate(t *testing.T) {
	type readCertificateItem struct {
		input   []byte
		version uint32
		cert    *Certificate
		err     error
		hash    [sha1.Size]byte
	}

	var readCertificateTable = func() []readCertificateItem {
		var table []readCertificateItem
		table = append(table, readCertificateItem{
			input:   nil,
			version: version01,
			cert:    nil,
			err: fmt.Errorf("read length: %w",
				fmt.Errorf("read uint32: %w",
					io.EOF)),
			hash: sha1.Sum(nil),
		})
		table = append(table, readCertificateItem{
			input:   nil,
			version: version02,
			cert:    nil,
			err: fmt.Errorf("read type: %w",
				fmt.Errorf("read length: %w",
					fmt.Errorf("read uint16: %w",
						io.EOF))),
			hash: sha1.Sum(nil),
		})
		table = append(table, readCertificateItem{
			input:   nil,
			version: 3,
			cert:    nil,
			err:     errors.New("got unknown version"),
			hash:    sha1.Sum(nil),
		})
		table = append(table, func() readCertificateItem {
			input := []byte{0, 0, 0, 0}
			return readCertificateItem{
				input:   input,
				version: version01,
				cert: &Certificate{
					Type:    defaultCertificateType,
					Content: nil,
				},
				err:  nil,
				hash: sha1.Sum(input),
			}
		}())
		table = append(table, func() readCertificateItem {
			buf := make([]byte, 2)
			byteOrder.PutUint16(buf, uint16(len(defaultCertificateType)))
			buf = append(buf, []byte(defaultCertificateType)...)
			buf = append(buf, 0, 0, 0, 0)
			return readCertificateItem{
				input:   buf,
				version: version02,
				cert: &Certificate{
					Type:    defaultCertificateType,
					Content: nil,
				},
				err:  nil,
				hash: sha1.Sum(buf),
			}
		}())
		table = append(table, func() readCertificateItem {
			buf := make([]byte, 2)
			byteOrder.PutUint16(buf, uint16(len(defaultCertificateType)))
			buf = append(buf, []byte(defaultCertificateType)...)
			buf = append(buf, 0, 0, 0, 1)
			return readCertificateItem{
				input:   buf,
				version: version02,
				cert:    nil,
				err: fmt.Errorf("read content: %w",
					fmt.Errorf("read 1 bytes: %w",
						io.EOF)),
				hash: sha1.Sum(buf),
			}
		}())

		return table
	}()

	for _, tt := range readCertificateTable {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		cert, err := ksd.readCertificate(tt.version)
		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("invalid error '%v' '%v'", err, tt.err)
		}
		if cert != nil && tt.cert != nil && !reflect.DeepEqual(cert, tt.cert) {
			t.Errorf("invalid certificate '%v' '%v'", cert, tt.cert)
		}
		hash := ksd.md.Sum(nil)
		if !reflect.DeepEqual(hash, tt.hash[:]) {
			t.Errorf("invalid hash '%v' '%v'", hash, tt.hash)
		}
	}
}
