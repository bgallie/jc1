// Package jc1 - project uberJc1.go
package jc1

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
