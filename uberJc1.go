// Package jc1 - project uberJc1.go
package jc1

import (
	"fmt"
	"os"
)

// UberJc1 - the type of the UberJc1 generator.
type UberJc1 struct {
	keys [4]*Cipher
}

// NewUberJc1 - create a new UberJc1 generator based on the key.
func NewUberJc1(key []byte) *UberJc1 {
	fmt.Fprintln(os.Stderr, "WARNING: UberJc1.NewUberJc1() is deprecated.  Use UberJc1.New() instead")
	return new(UberJc1).New(key)
}

func (k *UberJc1) New(key []byte) *UberJc1 {
	k.keys[0] = new(Cipher).New(key)
	k.keys[1] = new(Cipher).New(k.keys[0].XORKeyStream(key))
	k.keys[2] = new(Cipher).New(k.keys[1].XORKeyStream(key))
	k.keys[3] = new(Cipher).New(k.keys[2].XORKeyStream(key))

	return k

}

// XORKeyStream - encrypt/decrypt the bytes in src.
func (key *UberJc1) XORKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))

	for i := range src {
		dst[i] = src[i] ^ key.Core(0)
	}

	return dst
}

func (key *UberJc1) Read(buf []byte) (n int, err error) {
	return copy(buf, key.XORKeyStream(buf)), nil
}

// Reset - reset the UberJc1 key to an initial (unkeyed) state.
func (key *UberJc1) Reset() {
	for i := range key.keys {
		key.keys[i].Reset()
	}
}

// Core - the core UberJc1 algorithm.
func (k *UberJc1) Core(b byte) byte {
	return k.keys[3].Core(k.keys[2].Core(k.keys[1].Core(k.keys[0].Core(b))))
}

// shuffle - shuffles the UberJC1 state.
func (k *UberJc1) shuffle() {
	for _, v := range k.keys {
		v.shuffle()
	}
}

func (k *UberJc1) String() string {
	return k.keys[0].String() + k.keys[1].String() + k.keys[2].String() + k.keys[3].String()
}
