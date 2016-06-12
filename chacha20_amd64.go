// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build amd64,!gccgo,!appengine

package chacha20

import (
	"crypto/cipher"

	ref "github.com/codahale/chacha20"
)

const (
	// KeySize is the length of ChaCha20 keys, in bytes.
	KeySize = 32

	// NonceSize is the length of ChaCha20 nonces, in bytes.
	NonceSize = 8
)

var (
	// ErrInvalidKey is returned when the provided key is not 256 bits long.
	ErrInvalidKey = ref.ErrInvalidKey

	// ErrInvalidNonce is returned when the provided nonce is not 64 bits long.
	ErrInvalidNonce = ref.ErrInvalidNonce

	useAVX, useAVX2 = hasAVX()
)

// New creates and returns a new cipher.Stream. The key argument must be 256
// bits long, and the nonce argument must be 64 bits long. The nonce must be
// randomly generated or used only once. This Stream instance must not be used
// to encrypt more than 2^70 bytes (~1 zettabyte).
func New(key, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	if !useAVX && !useAVX2 {
		return ref.New(key, nonce)
	}

	s := new(stream20avx)
	copy(s.key[:], key)
	copy(s.nonce[:], nonce)
	return s, nil
}

type stream20avx struct {
	key     [32]byte
	nonce   [8]byte
	counter uint64

	buffer [128]byte
	bufPos int
	bufLen int
}

func (s *stream20avx) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if s.bufLen != 0 {
		i := 0

		for ; i < len(src) && i < s.bufLen; i++ {
			dst[i] = s.buffer[s.bufPos+i] ^ src[i]
			s.buffer[s.bufPos+i] = 0
		}

		src = src[i:]
		dst = dst[i:]

		s.bufPos += i
		s.bufLen -= i

		if len(src) == 0 {
			return
		}
	}

	var bufSize uint

	if useAVX2 {
		chacha_20_core_avx2(&dst[0], &src[0], uint64(len(src)), &s.key[0], &s.nonce[0], s.counter)

		bufSize = 128
	} else {
		chacha_20_core_avx(&dst[0], &src[0], uint64(len(src)), &s.key[0], &s.nonce[0], s.counter)

		bufSize = 64
	}

	if todo := uint(len(src)) &^ -bufSize; todo != 0 {
		copy(s.buffer[:todo], src[len(src)-int(todo):])

		if useAVX2 {
			s.counter += uint64(len(src)/64) &^ 1

			chacha_20_core_avx2(&s.buffer[0], &s.buffer[0], 128, &s.key[0], &s.nonce[0], s.counter)

			s.counter += 2
		} else {
			s.counter += uint64(len(src) / 64)

			chacha_20_core_avx(&s.buffer[0], &s.buffer[0], 64, &s.key[0], &s.nonce[0], s.counter)

			s.counter++
		}

		copy(dst[len(src)-int(todo):], s.buffer[:todo])

		s.bufPos = int(todo)
		s.bufLen = int(bufSize - todo)

		for i := 0; i < s.bufPos; i++ {
			s.buffer[i] = 0
		}
	} else {
		s.counter += uint64(len(src) / 64)
	}
}

//go:generate perl chacha20_avx.pl golang-no-avx chacha20_avx_amd64.s
//go:generate perl chacha20_avx2.pl golang-no-avx chacha20_avx2_amd64.s

// This function is implemented in avx_amd64.s
//go:noescape
func hasAVX() (avx, avx2 bool)

// This function is implemented in chacha20_avx_amd64.s
//go:noescape
func chacha_20_core_avx(out, in *byte, in_len uint64, key, nonce *byte, counter uint64)

// This function is implemented in chacha20_avx2_amd64.s
//go:noescape
func chacha_20_core_avx2(out, in *byte, in_len uint64, key, nonce *byte, counter uint64)
