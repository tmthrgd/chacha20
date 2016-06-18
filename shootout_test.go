// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"testing"

	codahale "github.com/codahale/chacha20"
	ref "github.com/tmthrgd/chacha20/internal/ref"
)

const benchSize = 1024 * 1024

func benchmarkStream(b *testing.B, c cipher.Stream) {
	b.SetBytes(benchSize)

	input := make([]byte, benchSize)
	output := make([]byte, benchSize)

	for i := 0; i < b.N; i++ {
		c.XORKeyStream(output, input)
	}
}

func BenchmarkDraftChaCha20Codahale(b *testing.B) {
	key := make([]byte, codahale.KeySize)
	nonce := make([]byte, codahale.NonceSize)
	c, _ := codahale.New(key, nonce)

	benchmarkStream(b, c)
}

func BenchmarkRFCChaCha20Go(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := ref.NewRFC(key, nonce)

	benchmarkStream(b, c)
}

func BenchmarkDraftChaCha20Go(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, DraftNonceSize)
	c, _ := ref.NewDraft(key, nonce)

	benchmarkStream(b, c)
}

func BenchmarkRFCChaCha20(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := NewRFC(key, nonce)

	benchmarkStream(b, c)
}

func BenchmarkDraftChaCha20(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, DraftNonceSize)
	c, _ := NewDraft(key, nonce)

	benchmarkStream(b, c)
}

func BenchmarkAESCTR(b *testing.B) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)

	iv := make([]byte, aes.BlockSize)
	c := cipher.NewCTR(a, iv)

	benchmarkStream(b, c)
}

func BenchmarkAESGCM(b *testing.B) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(a)

	nonce := make([]byte, c.NonceSize())

	b.SetBytes(benchSize)

	input := make([]byte, benchSize)
	output := make([]byte, 0, benchSize+c.Overhead())

	for i := 0; i < b.N; i++ {
		c.Seal(output, nonce, input, nil)
	}
}

func BenchmarkRC4(b *testing.B) {
	key := make([]byte, 32)
	c, _ := rc4.NewCipher(key)

	benchmarkStream(b, c)
}
