// Package jc1 project jc1.go
/*
	JC1 - A new pseudorandom byte generator.
	John C. Craig
	jcc...@sprynet.com
	June 23, 1996

	This algorithm is original with the author, and was
	created during the development of encryption software
	over the past few years. JC1 is now in the public
	domain. The author wishes only that the designation
	"JC1" be mentioned wherever this algorithm is used.
	Any feedback to the author as to the security,
	randomness, suitability, or any discovered problems
	with the JC1 algorithm would be greatly appreciated.
*/
package jc1

import "encoding/json"

// Cipher - the type defining the JC1 generator's state.
type Cipher struct {
	state [256]byte
	p, q  byte
}

// NewCipher - create a new JC1 generator based on a given key.
func NewCipher(key []byte) *Cipher {
	var k Cipher

	k.Reset()

	// Set the Cipher to a uniqe state based on the key.
	for _, val := range key {
		k.Core(val)
	}

	k.shuffle()

	return &k
}

// XORKeyStream - encrypt/decrypt the bytes in src.
func (key *Cipher) XORKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))

	for i := range src {
		dst[i] = src[i] ^ key.Core(0)
	}

	return dst
}

// Reset - resets the JC1 key to it's initial (unkeyed) state.
func (key *Cipher) Reset() {
	for i := range key.state {
		key.state[i] = 0
	}

	key.p, key.q = 0, 0
}

// Core - the core JC1 algorithm.
func (key *Cipher) Core(b byte) byte {
	key.p++
	key.state[key.p] += b
	key.q += key.state[key.p]
	key.state[key.p] += (key.state[key.q] + key.p)
	return key.state[key.p]
}

// shuffle - shuffles the JC1 state.
func (key *Cipher) shuffle() {
	for i := range key.state {
		key.Core(uint8(i))
	}
}

// String - implement the Stringer interface
func (key *Cipher) String() ([]byte, error) {
	data := make(map[string]interface{})
	data["p"] = key.p
	data["q"] = key.q
	data["state"] = key.state
	return json.Marshal(data)
}
