// Copyright 2016 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build !amd64 gccgo appengine

package chacha20

import (
	"crypto/cipher"

	ref "github.com/codahale/chacha20"
)

const (
	// KeySize is the length of ChaCha20 keys, in bytes.
	KeySize = ref.KeySize

	// NonceSize is the length of ChaCha20 nonces, in bytes.
	NonceSize = ref.NonceSize
)

var (
	// ErrInvalidKey is returned when the provided key is not 256 bits long.
	ErrInvalidKey = ref.ErrInvalidKey

	// ErrInvalidNonce is returned when the provided nonce is not 64 bits long.
	ErrInvalidNonce = ref.ErrInvalidNonce
)

// New creates and returns a new cipher.Stream. The key argument must be 256
// bits long, and the nonce argument must be 64 bits long. The nonce must be
// randomly generated or used only once. This Stream instance must not be used
// to encrypt more than 2^70 bytes (~1 zettabyte).
func New(key, nonce []byte) (cipher.Stream, error) {
	return ref.New(key, nonce)
}
