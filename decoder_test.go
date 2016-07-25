package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestReadUint16(t *testing.T) {
	type readUint16Item struct {
		input  []byte
		number uint16
		err    error
	}
	var readUint32Table = func() []readUint16Item {
		var table []readUint16Item
		table = append(table, readUint16Item{nil, 0, ErrIo})
		table = append(table, readUint16Item{[]byte{}, 0, ErrIo})
		table = append(table, readUint16Item{[]byte{1}, 0, ErrIo})
		buf := make([]byte, 2)
		var number uint16 = 10
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, readUint16Item{buf, number, nil})
		buf = make([]byte, 2)
		number = 0
		binary.BigEndian.PutUint16(buf, number)
		table = append(table, readUint16Item{buf, number, nil})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint16()
		if err != tt.err {
			t.Errorf("Invalid error '%v' '%v'", tt.err, err)
		}
		if number != tt.number {
			t.Errorf("Invalid uint16 '%v' '%v'", tt.number, number)
		}
	}
}

func TestReadUint32(t *testing.T) {
	type readUint32Item struct {
		input  []byte
		number uint32
		err    error
	}
	var readUint32Table = func() []readUint32Item {
		var table []readUint32Item
		table = append(table, readUint32Item{nil, 0, ErrIo})
		table = append(table, readUint32Item{[]byte{}, 0, ErrIo})
		table = append(table, readUint32Item{[]byte{1, 2, 3}, 0, ErrIo})
		buf := make([]byte, 4)
		var number uint32 = 10
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, readUint32Item{buf, number, nil})
		buf = make([]byte, 4)
		number = 0
		binary.BigEndian.PutUint32(buf, number)
		table = append(table, readUint32Item{buf, number, nil})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint32()
		if err != tt.err {
			t.Errorf("Invalid error '%v' '%v'", tt.err, err)
		}
		if number != tt.number {
			t.Errorf("Invalid uint32 '%v' '%v'", tt.number, number)
		}
	}
}

func TestReadUint64(t *testing.T) {
	type readUint64Item struct {
		input  []byte
		number uint64
		err    error
	}
	var readUint64Table = func() []readUint64Item {
		var table []readUint64Item
		table = append(table, readUint64Item{nil, 0, ErrIo})
		table = append(table, readUint64Item{[]byte{}, 0, ErrIo})
		table = append(table, readUint64Item{[]byte{1, 2, 3}, 0, ErrIo})
		buf := make([]byte, 8)
		var number uint64 = 10
		binary.BigEndian.PutUint64(buf, number)
		table = append(table, readUint64Item{buf, number, nil})
		buf = make([]byte, 8)
		number = 0
		binary.BigEndian.PutUint64(buf, number)
		table = append(table, readUint64Item{buf, number, nil})
		return table
	}()

	for _, tt := range readUint64Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		number, err := ksd.readUint64()
		if err != tt.err {
			t.Errorf("Invalid error '%v' '%v'", tt.err, err)
		}
		if number != tt.number {
			t.Errorf("Invalid uint64 '%v' '%v'", tt.number, number)
		}
	}
}

func TestReadBytes(t *testing.T) {
	type readBytesItem struct {
		input   []byte
		readLen uint32
		bytes   []byte
		err     error
	}
	var readUint32Table = func() []readBytesItem {
		var table []readBytesItem
		table = append(table, readBytesItem{nil, 0, nil, nil})
		table = append(table, readBytesItem{[]byte{1, 2, 3}, 3, []byte{1, 2, 3}, nil})
		table = append(table, readBytesItem{[]byte{1, 2, 3}, 2, []byte{1, 2}, nil})
		buf := func() []byte {
			buf := make([]byte, 10*1024)
			_, err := rand.Read(buf)
			if err != nil {
				t.Errorf("Error: %v", err)
			}
			return buf
		}()
		table = append(table, readBytesItem{buf, 9 * 1024, buf[:9*1024], nil})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		bts, err := ksd.readBytes(tt.readLen)
		if err != tt.err {
			t.Errorf("Invalid error '%v' '%v'", tt.err, err)
		}
		if !reflect.DeepEqual(bts, tt.bytes) {
			t.Errorf("Invalid bytes '%v' '%v'", tt.bytes, bts)
		}
	}
}

func TestReadString(t *testing.T) {
	type readStringItem struct {
		input  []byte
		string string
		err    error
	}
	var readUint32Table = func() []readStringItem {
		var table []readStringItem
		table = append(table, readStringItem{nil, "", ErrIo})
		table = append(table, readStringItem{[]byte{}, "", ErrIo})
		table = append(table, readStringItem{[]byte{1, 2, 3}, "", ErrIo})
		str := "some string to read"
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(len(str)))
		buf = append(buf, []byte(str)...)
		table = append(table, readStringItem{buf, str, nil})
		return table
	}()

	for _, tt := range readUint32Table {
		ksd := keyStoreDecoder{
			r:  bytes.NewReader(tt.input),
			md: sha1.New(),
		}
		str, err := ksd.readString()
		if err != tt.err {
			t.Errorf("Invalid error '%v' '%v'", tt.err, err)
		}
		if str != tt.string {
			t.Errorf("Invalid string '%v' '%v'", tt.string, str)
		}
	}
}
