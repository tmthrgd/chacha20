// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build amd64,!gccgo,!appengine

package chacha20

import (
	"crypto/cipher"

	"github.com/tmthrgd/chacha20/internal/ref"
	"github.com/tmthrgd/chacha20/internal/xor"
)

var useAVX, useAVX2 = hasAVX()

// NewRFC creates and returns a new cipher.Stream. The key argument must be 256
// bits long, and the nonce argument must be 96 bits long. The nonce must be
// randomly generated or used only once. This Stream instance must not be used
// to encrypt more than 2^38 bytes (256 gigabytes).
func NewRFC(key, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(nonce) != RFCNonceSize {
		return nil, ErrInvalidNonce
	}

	if !useAVX && !useAVX2 {
		return ref.NewRFC(key, nonce)
	}

	s := new(streamAVX)
	copy(s.state[:32], key)
	copy(s.state[36:], nonce)
	return s, nil
}

// NewDraft creates and returns a new cipher.Stream. The key argument must be
// 256 bits long, and the nonce argument must be 64 bits long. The nonce must
// be randomly generated or used only once. This Stream instance must not be
// used to encrypt more than 2^70 bytes (~1 zettabyte).
func NewDraft(key, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(nonce) != DraftNonceSize {
		return nil, ErrInvalidNonce
	}

	if !useAVX && !useAVX2 {
		return ref.NewDraft(key, nonce)
	}

	s := new(streamAVX)
	copy(s.state[:32], key)
	copy(s.state[40:], nonce)
	return s, nil
}

// NewXChaCha creates and returns a new cipher.Stream. The key argument must be
// 256 bits long, and the nonce argument must be 192 bits long. The nonce must
// be randomly generated or only used once. This Stream instance must not be
// used to encrypt more than 2^70 bytes (~1 zetta byte).
func NewXChaCha(key, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(nonce) != XNonceSize {
		return nil, ErrInvalidNonce
	}

	if !useAVX && !useAVX2 {
		return ref.NewXChaCha(key, nonce)
	}

	var subKey [ref.HChaChaSize]byte
	ref.HChaCha20(key, nonce[:ref.HNonceSize], &subKey)

	s := new(streamAVX)
	copy(s.state[:32], subKey[:])
	copy(s.state[40:], nonce[ref.HNonceSize:])
	return s, nil
}

type streamAVX struct {
	state [48]byte

	backing [128]byte
	buffer  []byte
}

func (s *streamAVX) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if len(s.buffer) != 0 {
		i := xor.Bytes(dst, s.buffer, src)
		for j := 0; j < i; j++ {
			s.buffer[j] = 0
		}

		s.buffer = s.buffer[i:]
		src = src[i:]
		dst = dst[i:]

		if len(src) == 0 {
			return
		}
	}

	if useAVX2 {
		chacha_20_core_avx2(&dst[0], &src[0], uint64(len(src)), &s.state)
	} else {
		chacha_20_core_avx(&dst[0], &src[0], uint64(len(src)), &s.state)
	}

	var minSize uint
	if useAVX2 {
		minSize = 128
	} else {
		minSize = 64
	}

	if todo := int(uint(len(src)) &^ -minSize); todo != 0 {
		copy(s.backing[:todo], src[len(src)-todo:])

		if useAVX2 {
			chacha_20_core_avx2(&s.backing[0], &s.backing[0], 128, &s.state)
		} else {
			chacha_20_core_avx(&s.backing[0], &s.backing[0], 128, &s.state)
		}

		copy(dst[len(src)-todo:], s.backing[:todo])
		for i := 0; i < todo; i++ {
			s.backing[i] = 0
		}

		s.buffer = s.backing[todo:]
	}
}

//go:generate perl chacha20_avx.pl golang-no-avx chacha20_avx_amd64.s
//go:generate perl chacha20_avx2.pl golang-no-avx chacha20_avx2_amd64.s

// This function is implemented in avx_amd64.s
//go:noescape
func hasAVX() (avx, avx2 bool)

// This function is implemented in chacha20_avx_amd64.s
//go:noescape
func chacha_20_core_avx(out, in *byte, in_len uint64, state *[48]byte)

// This function is implemented in chacha20_avx2_amd64.s
//go:noescape
func chacha_20_core_avx2(out, in *byte, in_len uint64, state *[48]byte)
