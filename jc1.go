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

import (
	"bytes"
	"fmt"
	"os"
)

// Cipher - the type defining the JC1 generator's state.
type Cipher struct {
	state [256]byte
	p, q  byte
}

// NewCipher - create a new JC1 generator based on a given key. [Depreciated]
func NewCipher(key []byte) *Cipher {
	fmt.Fprintln(os.Stderr, "WARNING: jc1.NewCipher() is deprecated.  Use jc1.New() instead")
	return new(Cipher).New(key)
}

// New - create a new JC1 generator based on a given key.
func (k *Cipher) New(key []byte) *Cipher {
	k.Reset()

	// Set the Cipher to a uniqe state based on the key.
	for _, val := range key {
		k.Core(val)
	}

	k.shuffle()

	return k
}

// XORKeyStream - encrypt/decrypt the bytes in src.
func (key *Cipher) XORKeyStream(src []byte) []byte {
	dst := make([]byte, len(src))

	for i := range src {
		dst[i] = src[i] ^ key.Core(0)
	}

	return dst
}

// Read - implement a Reader for jc1
func (key *Cipher) Read(buf []byte) (n int, err error) {
	return copy(buf, key.XORKeyStream(buf)), nil
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
func (key *Cipher) String() string {
	var output bytes.Buffer
	output.WriteString("jc1:\t[]byte{\n")
	for i := 0; i < 256; i += 16 {
		output.WriteString("\t\t")
		if i != (256 - 16) {
			for _, k := range key.state[i : i+15] {
				output.WriteString(fmt.Sprintf("%02x, ", k))
			}
			output.WriteString(fmt.Sprintf("%02x,", key.state[i+15]))
		} else {
			for _, k := range key.state[i : i+15] {
				output.WriteString(fmt.Sprintf("%02x, ", k))
			}
			output.WriteString(fmt.Sprintf("%02x})", key.state[i+15]))
		}
		output.WriteString("\n")
	}
	output.WriteString(fmt.Sprintf("\tp: %02x\n\tq: %02x", key.p, key.q))
	return output.String()
}
