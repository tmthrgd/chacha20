// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

// Package chacha20 provides a pure Go implementation of ChaCha20, a fast,
// secure stream cipher.
//
// From Bernstein, Daniel J. "ChaCha, a variant of Salsa20." Workshop Record of
// SASC. 2008. (http://cr.yp.to/chacha/chacha-20080128.pdf):
//
//	ChaCha8 is a 256-bit stream cipher based on the 8-round cipher Salsa20/8.
//	The changes from Salsa20/8 to ChaCha8 are designed to improve diffusion per
//	round, conjecturally increasing resistance to cryptanalysis, while
//	preserving -- and often improving -- time per round. ChaCha12 and ChaCha20
//	are analogous modiﬁcations of the 12-round and 20-round ciphers Salsa20/12
//	and Salsa20/20. This paper presents the ChaCha family and explains the
//	differences between Salsa20 and ChaCha.
//
// For more information, see http://cr.yp.to/chacha.html
package ref

import (
	"crypto/cipher"
	"encoding/binary"
	"unsafe"

	"github.com/tmthrgd/chacha20/internal/xor"
)

const (
	// KeySize is the length of ChaCha20 keys, in bytes.
	KeySize = 32
	// NonceSize is the length of ChaCha20-RFC nonces, in bytes.
	RFCNonceSize = 12
	// DraftNonceSize is the length of ChaCha20-draft nonces, in bytes.
	DraftNonceSize = 8
	// XNonceSize is the length of XChaCha20 nonces, in bytes.
	XNonceSize = 24
	// HNonceSize is the length of HChaCha20 nonces, in bytes.
	HNonceSize = 16
	// HChaChaSize is the length of HChaCha20 output, in bytes.
	HChaChaSize = blockSize / 2
)

// NewRFC creates and returns a new cipher.Stream. The key argument must be 256
// bits long, and the nonce argument must be 96 bits long. The nonce must be
// randomly generated or used only once. This Stream instance must not be used
// to encrypt more than 2^38 bytes (256 gigabytes).
func NewRFC(key []byte, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		panic("invalid key length")
	}

	if len(nonce) != RFCNonceSize {
		panic("invalid nonce length")
	}

	s := new(stream)
	s.init(key, nonce)
	s.advance()

	return s, nil
}

// NewDraft creates and returns a new cipher.Stream. The key argument must be
// 256 bits long, and the nonce argument must be 64 bits long. The nonce must
// be randomly generated or used only once. This Stream instance must not be
// used to encrypt more than 2^70 bytes (~1 zettabyte).
func NewDraft(key []byte, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		panic("invalid key length")
	}

	if len(nonce) != DraftNonceSize {
		panic("invalid nonce length")
	}

	s := new(stream)
	s.init(key, nonce)
	s.advance()

	return s, nil
}

// NewXChaCha creates and returns a new cipher.Stream. The key argument must be
// 256 bits long, and the nonce argument must be 192 bits long. The nonce must
// be randomly generated or only used once. This Stream instance must not be
// used to encrypt more than 2^70 bytes (~1 zetta byte).
func NewXChaCha(key, nonce []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		panic("invalid key length")
	}

	if len(nonce) != XNonceSize {
		panic("invalid nonce length")
	}

	s := new(stream)

	// Call HChaCha to derive the subkey using the key and the first 16 bytes
	// of the nonce.
	s.init(key, nonce[:HNonceSize])

	var subKey [HChaChaSize]byte
	s.hChaCha20(&subKey)

	// Re-initialize the state using the subkey and the remaining nonce.
	s.init(subKey[:], nonce[HNonceSize:])
	s.advance()
	return s, nil
}

// HChaCha20 produces a 256-bit output block starting from a 512 bit
// input block where (x0,x1,...,x15) where
//
//  * (x0, x1, x2, x3) is the ChaCha20 constant.
//  * (x4, x5, ... x11) is a 256 bit key.
//  * (x12, x13, x14, x15) is a 128 bit nonce.
func HChaCha20(key, nonce []byte, out *[HChaChaSize]byte) {
	if len(key) != KeySize {
		panic("invalid key length")
	}

	if len(nonce) != HNonceSize {
		panic("invalid nonce length")
	}

	s := new(stream)
	s.init(key, nonce)
	s.hChaCha20(out)
	return
}

type stream struct {
	state  [stateSize]uint32 // the state as an array of 16 32-bit words
	block  [blockSize]byte   // the keystream as an array of 64 bytes
	offset int               // the offset of used bytes in block
}

func (s *stream) hChaCha20(out *[HChaChaSize]byte) {
	core(&s.state, (*[stateSize]uint32)(unsafe.Pointer(&s.block)), 20, true)

	copy(out[:16], s.block[:16])
	copy(out[16:], s.block[48:])
}

func (s *stream) XORKeyStream(dst, src []byte) {
	// Stride over the input in 64-byte blocks, minus the amount of keystream
	// previously used. This will produce best results when processing blocks
	// of a size evenly divisible by 64.
	i := 0
	max := len(src)
	for i < max {
		gap := blockSize - s.offset

		limit := i + gap
		if limit > max {
			limit = max
		}

		j := xor.Bytes(dst[i:limit], src[i:limit], s.block[s.offset:])
		for o := s.offset; o < j; o++ {
			s.block[o] = 0
		}

		s.offset += j
		i += gap

		if s.offset == blockSize {
			s.advance()
		}
	}
}

func (s *stream) init(key []byte, nonce []byte) {
	// the magic constants for 256-bit keys
	s.state[0] = 0x61707865
	s.state[1] = 0x3320646e
	s.state[2] = 0x79622d32
	s.state[3] = 0x6b206574

	s.state[4] = binary.LittleEndian.Uint32(key[0:])
	s.state[5] = binary.LittleEndian.Uint32(key[4:])
	s.state[6] = binary.LittleEndian.Uint32(key[8:])
	s.state[7] = binary.LittleEndian.Uint32(key[12:])
	s.state[8] = binary.LittleEndian.Uint32(key[16:])
	s.state[9] = binary.LittleEndian.Uint32(key[20:])
	s.state[10] = binary.LittleEndian.Uint32(key[24:])
	s.state[11] = binary.LittleEndian.Uint32(key[28:])

	switch len(nonce) {
	case RFCNonceSize:
		// ChaCha20-RFC uses 12 byte nonces.
		s.state[12] = 0
		s.state[13] = binary.LittleEndian.Uint32(nonce[0:])
		s.state[14] = binary.LittleEndian.Uint32(nonce[4:])
		s.state[15] = binary.LittleEndian.Uint32(nonce[8:])
	case DraftNonceSize:
		// ChaCha20-draft uses 8 byte nonces.
		s.state[12] = 0
		s.state[13] = 0
		s.state[14] = binary.LittleEndian.Uint32(nonce[0:])
		s.state[15] = binary.LittleEndian.Uint32(nonce[4:])
	case HNonceSize:
		// XChaCha20 derives the subkey via HChaCha initialized
		// with the first 16 bytes of the nonce.
		s.state[12] = binary.LittleEndian.Uint32(nonce[0:])
		s.state[13] = binary.LittleEndian.Uint32(nonce[4:])
		s.state[14] = binary.LittleEndian.Uint32(nonce[8:])
		s.state[15] = binary.LittleEndian.Uint32(nonce[12:])
	default:
		// Never happens, both ctors validate the nonce length.
		panic("invalid nonce size")
	}
}

// BUG(codahale): Totally untested on big-endian CPUs. Would very much
// appreciate someone with an ARM device giving this a swing.

// advances the keystream
func (s *stream) advance() {
	core(&s.state, (*[stateSize]uint32)(unsafe.Pointer(&s.block)), 20, false)

	if bigEndian {
		j := blockSize - 1
		for i := 0; i < blockSize/2; i++ {
			s.block[j], s.block[i] = s.block[i], s.block[j]
			j--
		}
	}

	s.offset = 0
	i := s.state[12] + 1
	s.state[12] = i
	if i == 0 {
		s.state[13]++
	}
}

const (
	wordSize  = 4                    // the size of ChaCha20's words
	stateSize = 16                   // the size of ChaCha20's state, in words
	blockSize = stateSize * wordSize // the size of ChaCha20's block, in bytes
)

var (
	bigEndian bool // whether or not we're running on a bigEndian CPU
)

// Do some up-front bookkeeping on what sort of CPU we're using. ChaCha20 treats
// its state as a little-endian byte array when it comes to generating the
// keystream, which allows for a zero-copy approach to the core transform. On
// big-endian architectures, we have to take a hit to reverse the bytes.
func init() {
	x := uint32(0x04030201)
	y := [4]byte{0x1, 0x2, 0x3, 0x4}
	bigEndian = *(*[4]byte)(unsafe.Pointer(&x)) != y
}
