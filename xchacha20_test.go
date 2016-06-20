// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.
//
// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package chacha20

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	codahale "github.com/codahale/chacha20"
	"github.com/tmthrgd/chacha20/internal/ref"
)

// stolen from https://github.com/codahale/chacha20/blob/master/chacha20_test.go
type xTestVector struct {
	key       []byte
	nonce     []byte
	keyStream []byte
}

var xTestVectors = []xTestVector{
	xTestVector{
		[]byte{
			0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
			0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
			0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
			0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
		},
		[]byte{
			0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
			0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
			0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
		},
		[]byte{
			0x4f, 0xeb, 0xf2, 0xfe, 0x4b, 0x35, 0x9c, 0x50,
			0x8d, 0xc5, 0xe8, 0xb5, 0x98, 0x0c, 0x88, 0xe3,
			0x89, 0x46, 0xd8, 0xf1, 0x8f, 0x31, 0x34, 0x65,
			0xc8, 0x62, 0xa0, 0x87, 0x82, 0x64, 0x82, 0x48,
			0x01, 0x8d, 0xac, 0xdc, 0xb9, 0x04, 0x17, 0x88,
			0x53, 0xa4, 0x6d, 0xca, 0x3a, 0x0e, 0xaa, 0xee,
			0x74, 0x7c, 0xba, 0x97, 0x43, 0x4e, 0xaf, 0xfa,
			0xd5, 0x8f, 0xea, 0x82, 0x22, 0x04, 0x7e, 0x0d,
			0xe6, 0xc3, 0xa6, 0x77, 0x51, 0x06, 0xe0, 0x33,
			0x1a, 0xd7, 0x14, 0xd2, 0xf2, 0x7a, 0x55, 0x64,
			0x13, 0x40, 0xa1, 0xf1, 0xdd, 0x9f, 0x94, 0x53,
			0x2e, 0x68, 0xcb, 0x24, 0x1c, 0xbd, 0xd1, 0x50,
			0x97, 0x0d, 0x14, 0xe0, 0x5c, 0x5b, 0x17, 0x31,
			0x93, 0xfb, 0x14, 0xf5, 0x1c, 0x41, 0xf3, 0x93,
			0x83, 0x5b, 0xf7, 0xf4, 0x16, 0xa7, 0xe0, 0xbb,
			0xa8, 0x1f, 0xfb, 0x8b, 0x13, 0xaf, 0x0e, 0x21,
			0x69, 0x1d, 0x7e, 0xce, 0xc9, 0x3b, 0x75, 0xe6,
			0xe4, 0x18, 0x3a,
		},
	},
}

func TestXChaCha20(t *testing.T) {
	t.Parallel()

	switch {
	case useAVX2:
		t.Log("testing AVX2 implementation")
	case useAVX:
		t.Log("testing AVX implementation")
	default:
		t.Log("testing Go implementation")
	}

	for i, vector := range xTestVectors {
		t.Logf("Running test vector %d", i)

		c, err := NewXChaCha(vector.key, vector.nonce)
		if err != nil {
			t.Error(err)
			continue
		}

		src := make([]byte, len(vector.keyStream))
		dst := make([]byte, len(vector.keyStream))
		c.XORKeyStream(dst, src)

		if !bytes.Equal(vector.keyStream, dst) {
			t.Error("Bad keystream:")
			t.Errorf("\texpected %x", vector.keyStream)
			t.Errorf("\twas      %x", dst)

			for i, v := range vector.keyStream {
				if dst[i] != v {
					t.Logf("\tMismatch at offset %d: %x vs %x", i, v, dst[i])
					break
				}
			}
		}
	}
}

func TestXBadKeySize(t *testing.T) {
	t.Parallel()

	key := make([]byte, 3)
	nonce := make([]byte, XNonceSize)

	_, err := NewXChaCha(key, nonce)

	if err != ErrInvalidKey {
		t.Error("Should have rejected an invalid key")
	}
}

func TestXBadNonceSize(t *testing.T) {
	t.Parallel()

	key := make([]byte, KeySize)
	nonce := make([]byte, 3)

	_, err := NewXChaCha(key, nonce)

	if err != ErrInvalidNonce {
		t.Error("Should have rejected an invalid nonce")
	}
}

func testXEqual(t *testing.T, calls int) {
	if !useAVX && !useAVX2 {
		t.Skip("skipping: using Go implementation already")
	}

	if err := quick.Check(func(key, nonce, src []byte) bool {
		c1, err := NewXChaCha(key, nonce)
		if err != nil {
			t.Error(err)
			return false
		}

		c2, err := codahale.NewXChaCha(key, nonce)
		if err != nil {
			t.Error(err)
			return false
		}

		dst1 := make([]byte, len(src))
		dst2 := make([]byte, len(src))

		for i := 0; i < calls; i++ {
			c1.XORKeyStream(dst1, src)
			c2.XORKeyStream(dst2, src)
		}

		if bytes.Equal(dst1, dst2) {
			return true
		}

		t.Error("Bad output:")
		t.Errorf("\tcodahale/chacha20: %x", dst2)
		t.Errorf("\ttmthrgd/chacha20:  %x", dst1)

		for i, v := range dst2 {
			if dst1[i] != v {
				t.Logf("\tMismatch at offset %d: %x vs %x", i, v, dst1[i])
				break
			}
		}

		return false
	}, &quick.Config{
		Values: func(args []reflect.Value, rand *rand.Rand) {
			key := make([]byte, KeySize)
			rand.Read(key)
			args[0] = reflect.ValueOf(key)

			nonce := make([]byte, XNonceSize)
			rand.Read(nonce)
			args[1] = reflect.ValueOf(nonce)

			src := make([]byte, 1+rand.Intn(1024*1024))
			rand.Read(src)
			args[2] = reflect.ValueOf(src)
		},
	}); err != nil {
		t.Error(err)
	}
}

func TestXEqualOneShot(t *testing.T) {
	t.Parallel()

	testXEqual(t, 1)
}

func TestXEqualMultiUse(t *testing.T) {
	t.Parallel()

	testXEqual(t, 5)
}

func BenchmarkHChaChaGo(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, ref.HNonceSize)
	var block [ref.HChaChaSize]byte

	for i := 0; i < b.N; i++ {
		ref.HChaCha20(key, nonce, &block)
	}
}
