// Package jc1 - project uberJc1.go
package jc1

import (
	"math/big"
)

const (
	uintSize  = 32 << (^uint(0) >> 32 & 1) // 32 or 64
	maxInt    = 1<<(uintSize-1) - 1        // 1<<31 - 1 or 1<<63 - 1
	minInt    = maxInt - 1                 // -1 << 31 or -1 << 63
	maxUint   = uint(1<<uintSize - 1)      // 1<<32 - 1 or 1<<64 - 1
	maxInt32  = 1<<(32-1) - 1
	minInt32  = -maxInt32 - 1
	maxUint32 = 1<<32 - 1
	maxInt64  = 1<<(64-1) - 1
	minInt64  = -maxInt64 - 1
	maxUint64 = 1<<64 - 1
)

// UberJc1 - the type of the UberJc1 generator.
type UberJc1 struct {
	keys [4]*Cipher
}

// NewUberJc1 - create a new UberJc1 generator based on the key.
func NewUberJc1(key []byte) *UberJc1 {
	var k UberJc1
	k.keys[0] = NewCipher(key)
	k.keys[1] = NewCipher(k.keys[0].XORKeyStream(key))
	k.keys[2] = NewCipher(k.keys[1].XORKeyStream(key))
	k.keys[3] = NewCipher(k.keys[2].XORKeyStream(key))

	return &k
}

// XORKeyStream - encrypt/decrypt the bytes in src.
func (key *UberJc1) XORKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))

	for i := range src {
		dst[i] = src[i] ^ key.Core(0)
	}

	return dst
}

// Reset - reset the UberJc1 key to an initial (unkeyed) state.
func (key *UberJc1) Reset() {
	for i := range key.keys {
		key.keys[i].Reset()
	}
}

// Core - the core UberJc1 algorithm.
func (key *UberJc1) Core(b byte) byte {
	return key.keys[3].Core(key.keys[2].Core(key.keys[1].Core(key.keys[0].Core(b))))
}

// Int32 - returns a (pseudo)random 32bit integer in the range 0..MaxInt32.
func (key *UberJc1) Int32() int32 {
	n := new(big.Int)
	return int32(key.int(n.SetInt64(maxInt32)).Int64())
}

// Int32n - returns a (pseudo)random 32bit integer in the range 0..nRange
func (key *UberJc1) Int32n(nRange int32) int32 {
	n := new(big.Int)
	return int32(key.int(n.SetInt64(int64(nRange))).Int64())
}

// Rand32 - returns  (pseudo)random 32bit integer.
func (key *UberJc1) Rand32() int32 {
	n := new(big.Int)
	return int32(key.int(n.SetInt64(int64(maxInt32))).Int64())
}

// Int64 - returns a (pseudo)random 64bit integer in the range 0..MaxInt64
func (key *UberJc1) Int64() int64 {
	n := new(big.Int)
	return key.int(n.SetInt64(maxInt64)).Int64()
}

// Int64n - returns a (pseudo)random 64bit integer in the range 0..nRange
func (key *UberJc1) Int64n(nRange int64) int64 {
	n := new(big.Int)
	return key.int(n.SetInt64(nRange)).Int64()
}

// Rand64 - returns a (pseudo)random 64bit integer in the range 0..MaxInt64
func (key *UberJc1) Rand64() int64 {
	n := new(big.Int)
	return key.int(n.SetInt64(maxInt64)).Int64()
}

// Intn - returns a (pseudo)random integer in the range 0..nRange
func (key *UberJc1) Intn(nRange int) int {
	n := new(big.Int)
	return int(key.int(n.SetInt64(int64(nRange))).Int64())
}

// Rand - returns a (pseudo)random 32bit or 64bit integer depending on the default int size.
func (key *UberJc1) Rand() int {
	n := new(big.Int)
	return int(key.int(n.SetInt64(int64(maxInt))).Int64())
}

// Perm - returns a (pseudo)random permutation of interger 0..(n-1)
func (key *UberJc1) Perm(n int) []int {
	res := make([]int, n, n)

	for i := range res {
		res[i] = i
	}

	for i := (n - 1); i > 0; i-- {
		j := key.Intn(i)
		res[i], res[j] = res[j], res[i]
	}

	return res
}

// int returns a uniform random value in [0, max). It panics if max <= 0.
func (key *UberJc1) int(max *big.Int) (n *big.Int) {
	if max.Sign() <= 0 {
		panic("argument to UberJc1.int is <= 0")
	}

	n = new(big.Int)
	n.Sub(max, n.SetUint64(1))

	// bitLen is the maximum bit length needed to encode a value < max.
	bitLen := n.BitLen()
	if bitLen == 0 {
		// the only valid result is 0
		return
	}
	// k is the maximum byte length needed to encode a value < max.
	k := (bitLen + 7) / 8
	// b is the number of bits in the most significant byte of max-1.
	b := uint(bitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, k)

	for {
		bytes = key.XORKeyStream(bytes)

		// Clear bits in the first byte to increase the probability
		// that the candidate is < max.
		bytes[0] &= uint8(int(1<<b) - 1)

		n.SetBytes(bytes)
		if n.Cmp(max) < 0 {
			return
		}
	}
}
