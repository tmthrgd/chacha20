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
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/tmthrgd/chacha20/internal/ref"
)

// stolen from https://tools.ietf.org/html/rfc7539
type rfcTestVector struct {
	key       string
	nonce     string
	keyStream string
	counter   uint64
}

var rfcTestVectors = []rfcTestVector{
	rfcTestVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
		0,
	},
	rfcTestVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" +
			"29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
		1,
	},
	rfcTestVector{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"000000000000000000000000",
		"3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a" +
			"8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
		1,
	},
	rfcTestVector{
		"00ff000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca" +
			"13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
		2,
	},
	rfcTestVector{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000002",
		"c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7" +
			"8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
		0,
	},
	rfcTestVector{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000000000000004a00000000",
		"224f51f3401bd9e12fde276fb8631ded8c131f823d2c06" +
			"e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b" +
			"9334794cba40c63e34cdea212c4cf07d41b769a6749f3f" +
			"630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a" +
			"c40c5945398b6eda1a832c89c167eacd901d7e2bf363",
		1,
	},
}

func TestRFCChaCha20(t *testing.T) {
	t.Parallel()

	switch {
	case useAVX2:
		t.Log("testing AVX2 implementation")
	case useAVX:
		t.Log("testing AVX implementation")
	default:
		t.Log("testing Go implementation")
	}

	for i, vector := range rfcTestVectors {
		t.Logf("Running test vector %d", i)

		key, err := hex.DecodeString(vector.key)
		if err != nil {
			t.Error(err)
		}

		nonce, err := hex.DecodeString(vector.nonce)
		if err != nil {
			t.Error(err)
		}

		c, err := NewRFC(key, nonce)
		if err != nil {
			t.Error(err)
			continue
		}

		var block [64]byte
		for i := uint64(0); i < vector.counter; i++ {
			c.XORKeyStream(block[:], block[:])
		}

		expected, err := hex.DecodeString(vector.keyStream)
		if err != nil {
			t.Error(err)
		}

		src := make([]byte, len(expected))
		dst := make([]byte, len(expected))
		c.XORKeyStream(dst, src)

		if !bytes.Equal(expected, dst) {
			t.Error("Bad keystream:")
			t.Errorf("\texpected %x", expected)
			t.Errorf("\twas      %x", dst)

			for i, v := range expected {
				if dst[i] != v {
					t.Logf("\tMismatch at offset %d: %x vs %x", i, v, dst[i])
					break
				}
			}
		}
	}
}

func TestRFCBadKeySize(t *testing.T) {
	t.Parallel()

	key := make([]byte, 3)
	nonce := make([]byte, RFCNonceSize)

	_, err := NewRFC(key, nonce)

	if err != ErrInvalidKey {
		t.Error("Should have rejected an invalid key")
	}
}

func TestRFCBadNonceSize(t *testing.T) {
	t.Parallel()

	key := make([]byte, KeySize)
	nonce := make([]byte, 3)

	_, err := NewRFC(key, nonce)

	if err != ErrInvalidNonce {
		t.Error("Should have rejected an invalid nonce")
	}
}

func testRFCEqual(t *testing.T, calls int) {
	if !useAVX && !useAVX2 {
		t.Skip("skipping: using Go implementation already")
	}

	if err := quick.Check(func(key, nonce, src []byte) bool {
		c1, err := NewRFC(key, nonce)
		if err != nil {
			t.Error(err)
			return false
		}

		c2, err := ref.NewRFC(key, nonce)
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
		t.Errorf("\ttmthrgd/chacha20/internal/ref: %x", dst2)
		t.Errorf("\ttmthrgd/chacha20:              %x", dst1)

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

			nonce := make([]byte, RFCNonceSize)
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

func TestRFCEqualOneShot(t *testing.T) {
	t.Parallel()

	testRFCEqual(t, 1)
}

func TestRFCEqualMultiUse(t *testing.T) {
	t.Parallel()

	testRFCEqual(t, 5)
}

func ExampleNewRFC() {
	key, err := hex.DecodeString("60143a3d7c7137c3622d490e7dbb85859138d198d9c648960e186412a6250722")
	if err != nil {
		panic(err)
	}

	// A nonce should only be used once. Generate it randomly.
	nonce, err := hex.DecodeString("00000000308c92676fa95973")
	if err != nil {
		panic(err)
	}

	c, err := NewRFC(key, nonce)
	if err != nil {
		panic(err)
	}

	src := []byte("hello I am a secret message")
	dst := make([]byte, len(src))

	c.XORKeyStream(dst, src)

	fmt.Printf("%x\n", dst)
	// Output: a05452ebd981422dcdab2c9cde0d20a03f769e87d3e976ee6d6a11
}
