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

func benchmarkStream(b *testing.B, c cipher.Stream, l int) {
	input := make([]byte, l)
	output := make([]byte, l)

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.XORKeyStream(output, input)
	}
}

func benchmarkChaCha20Codahale(b *testing.B, l int) {
	key := make([]byte, codahale.KeySize)
	nonce := make([]byte, codahale.NonceSize)
	c, _ := codahale.New(key, nonce)

	benchmarkStream(b, c, l)
}

func BenchmarkChaCha20Codahale_32(b *testing.B) {
	benchmarkChaCha20Codahale(b, 32)
}

func BenchmarkChaCha20Codahale_128(b *testing.B) {
	benchmarkChaCha20Codahale(b, 128)
}

func BenchmarkChaCha20Codahale_1k(b *testing.B) {
	benchmarkChaCha20Codahale(b, 1*1024)
}

func BenchmarkChaCha20Codahale_16k(b *testing.B) {
	benchmarkChaCha20Codahale(b, 16*1024)
}

func BenchmarkChaCha20Codahale_128k(b *testing.B) {
	benchmarkChaCha20Codahale(b, 128*1024)
}

func BenchmarkChaCha20Codahale_1M(b *testing.B) {
	benchmarkChaCha20Codahale(b, 1024*1024)
}

func benchmarkChaCha20Go(b *testing.B, l int) {
	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := ref.NewRFC(key, nonce)

	benchmarkStream(b, c, l)
}

func BenchmarkChaCha20Go_32(b *testing.B) {
	benchmarkChaCha20Go(b, 32)
}

func BenchmarkChaCha20Go_128(b *testing.B) {
	benchmarkChaCha20Go(b, 128)
}

func BenchmarkChaCha20Go_1k(b *testing.B) {
	benchmarkChaCha20Go(b, 1*1024)
}

func BenchmarkChaCha20Go_16k(b *testing.B) {
	benchmarkChaCha20Go(b, 16*1024)
}

func BenchmarkChaCha20Go_128k(b *testing.B) {
	benchmarkChaCha20Go(b, 128*1024)
}

func BenchmarkChaCha20Go_1M(b *testing.B) {
	benchmarkChaCha20Go(b, 1024*1024)
}

func benchmarkChaCha20x64(b *testing.B, l int) {
	if useRef {
		b.Skip("skipping: do not have x64 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := NewRFC(key, nonce)

	benchmarkStream(b, c, l)
}

func BenchmarkChaCha20x64_32(b *testing.B) {
	benchmarkChaCha20x64(b, 32)
}

func BenchmarkChaCha20x64_128(b *testing.B) {
	benchmarkChaCha20x64(b, 128)
}

func BenchmarkChaCha20x64_1k(b *testing.B) {
	benchmarkChaCha20x64(b, 1*1024)
}

func BenchmarkChaCha20x64_16k(b *testing.B) {
	benchmarkChaCha20x64(b, 16*1024)
}

func BenchmarkChaCha20x64_128k(b *testing.B) {
	benchmarkChaCha20x64(b, 128*1024)
}

func BenchmarkChaCha20x64_1M(b *testing.B) {
	benchmarkChaCha20x64(b, 1024*1024)
}

func benchmarkChaCha20AVX(b *testing.B, l int) {
	if !useAVX {
		b.Skip("skipping: do not have AVX implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = true, false
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := NewRFC(key, nonce)

	benchmarkStream(b, c, l)
}

func BenchmarkChaCha20AVX_32(b *testing.B) {
	benchmarkChaCha20AVX(b, 32)
}

func BenchmarkChaCha20AVX_128(b *testing.B) {
	benchmarkChaCha20AVX(b, 128)
}

func BenchmarkChaCha20AVX_1k(b *testing.B) {
	benchmarkChaCha20AVX(b, 1*1024)
}

func BenchmarkChaCha20AVX_16k(b *testing.B) {
	benchmarkChaCha20AVX(b, 16*1024)
}

func BenchmarkChaCha20AVX_128k(b *testing.B) {
	benchmarkChaCha20AVX(b, 128*1024)
}

func BenchmarkChaCha20AVX_1M(b *testing.B) {
	benchmarkChaCha20AVX(b, 1024*1024)
}

func benchmarkChaCha20AVX2(b *testing.B, l int) {
	if !useAVX2 {
		b.Skip("skipping: do not have AVX2 implementation")
	}

	oldAVX, oldAVX2 := useAVX, useAVX2
	useAVX, useAVX2 = false, true
	defer func() {
		useAVX, useAVX2 = oldAVX, oldAVX2
	}()

	key := make([]byte, KeySize)
	nonce := make([]byte, RFCNonceSize)
	c, _ := NewRFC(key, nonce)

	benchmarkStream(b, c, l)
}

func BenchmarkChaCha20AVX2_32(b *testing.B) {
	benchmarkChaCha20AVX2(b, 32)
}

func BenchmarkChaCha20AVX2_128(b *testing.B) {
	benchmarkChaCha20AVX2(b, 128)
}

func BenchmarkChaCha20AVX2_1k(b *testing.B) {
	benchmarkChaCha20AVX2(b, 1*1024)
}

func BenchmarkChaCha20AVX2_16k(b *testing.B) {
	benchmarkChaCha20AVX2(b, 16*1024)
}

func BenchmarkChaCha20AVX2_128k(b *testing.B) {
	benchmarkChaCha20AVX2(b, 128*1024)
}

func BenchmarkChaCha20AVX2_1M(b *testing.B) {
	benchmarkChaCha20AVX2(b, 1024*1024)
}

func benchmarkAESCTR(b *testing.B, l int) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)

	iv := make([]byte, aes.BlockSize)
	c := cipher.NewCTR(a, iv)

	benchmarkStream(b, c, l)
}

func BenchmarkAESCTR_32(b *testing.B) {
	benchmarkAESCTR(b, 32)
}

func BenchmarkAESCTR_128(b *testing.B) {
	benchmarkAESCTR(b, 128)
}

func BenchmarkAESCTR_1k(b *testing.B) {
	benchmarkAESCTR(b, 1*1024)
}

func BenchmarkAESCTR_16k(b *testing.B) {
	benchmarkAESCTR(b, 16*1024)
}

func BenchmarkAESCTR_128k(b *testing.B) {
	benchmarkAESCTR(b, 128*1024)
}

func BenchmarkAESCTR_1M(b *testing.B) {
	benchmarkAESCTR(b, 1024*1024)
}

func benchmarkAESGCM(b *testing.B, l int) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(a)

	nonce := make([]byte, c.NonceSize())

	input := make([]byte, l)
	output := make([]byte, 0, l+c.Overhead())

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Seal(output, nonce, input, nil)
	}
}

func BenchmarkAESGCM_32(b *testing.B) {
	benchmarkAESGCM(b, 32)
}

func BenchmarkAESGCM_128(b *testing.B) {
	benchmarkAESGCM(b, 128)
}

func BenchmarkAESGCM_1k(b *testing.B) {
	benchmarkAESGCM(b, 1*1024)
}

func BenchmarkAESGCM_16k(b *testing.B) {
	benchmarkAESGCM(b, 16*1024)
}

func BenchmarkAESGCM_128k(b *testing.B) {
	benchmarkAESGCM(b, 128*1024)
}

func BenchmarkAESGCM_1M(b *testing.B) {
	benchmarkAESGCM(b, 1024*1024)
}

func benchmarkRC4(b *testing.B, l int) {
	key := make([]byte, 32)
	c, _ := rc4.NewCipher(key)

	benchmarkStream(b, c, l)
}

func BenchmarkRC4_32(b *testing.B) {
	benchmarkRC4(b, 32)
}

func BenchmarkRC4_128(b *testing.B) {
	benchmarkRC4(b, 128)
}

func BenchmarkRC4_1k(b *testing.B) {
	benchmarkRC4(b, 1*1024)
}

func BenchmarkRC4_16k(b *testing.B) {
	benchmarkRC4(b, 16*1024)
}

func BenchmarkRC4_128k(b *testing.B) {
	benchmarkRC4(b, 128*1024)
}

func BenchmarkRC4_1M(b *testing.B) {
	benchmarkRC4(b, 1024*1024)
}
