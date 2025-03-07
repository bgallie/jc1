package jc1

// Define the random number generator using tntengine as the source.

import (
	"fmt"
	"math/bits"
	"slices"
)

type rndSource interface {
	Core(byte) byte
	XORKeyStream([]byte) []byte
	Read([]byte) (int, error)
	Reset()
	shuffle()
	String() string
}

// Define constants needed for ikengine
const (
	BitsPerByte      int = 8                      // bits
	CipherBlockSize  int = 256                    // bits
	CipherBlockBytes int = 32                     // bytes
	maxRotors        int = 30                     // ikmachine will support a max of 30 rotors
	maxPermutators   int = 8                      // and a max of 8 permutators.
	IntSize              = 32 << (^uint(0) >> 63) // IntSize is the size in bits of an int or uint value.
	MaxInt               = (1<<(IntSize-1) - 1)
	MaxInt64             = (1<<(63) - 1)
	MaxInt32             = (1<<(31) - 1)
	MaxInt16             = (1<<(15) - 1)
	MaxInt8              = (1<<(7) - 1)
	MaxUint64            = (1<<(64) - 1)
	MaxUint32            = (1<<(32) - 1)
	MaxUint16            = (1<<(16) - 1)
	MaxUint8             = (1<<(8) - 1)
)

type Rand struct {
	machine rndSource
}

// New returns a Rand object.
func (rnd *Rand) New(src rndSource) *Rand {
	rnd.machine = src
	return rnd
}

func (rnd *Rand) StopRand() {
	rnd.machine = nil
}

// Intn returns, as an int, a non-negative pseudo-random number in the
// half-open interval [0,n) from the tntengine. It panics if n <= 0.
func (rnd *Rand) Intn(max int) int {
	if max <= 0 {
		panic("argument to Intn is <= 0")
	}
	return int(rnd.Int63n(int64(max)))
}

// Int15n returns, as an int16, a non-negative pseudo-random number in the
// half-open interval [0,n). It panics if n <= 0.
func (rnd *Rand) Int15n(max int16) int16 {
	if max <= 0 {
		panic("argument to Int15n is <= 0")
	}
	return int16(rnd.Int63n(int64(max)))
}

// Int31n returns, as an int32, a non-negative pseudo-random number in the
// half-open interval [0,n). It panics if n <= 0.
func (rnd *Rand) Int31n(max int32) int32 {
	if max < 0 {
		panic("argument to Int31n is < 0")
	}
	return int32(rnd.Int63n(int64(max)))
}

// Int63n returns, as an int64, a non-negative pseudo-random number in the
// half-open interval [0,n). It panics if n <= 0.
func (rnd *Rand) Int63n(max int64) int64 {
	if max < 0 {
		panic("argument to Int63n is < 0")
	}
	if max == 0 {
		return max
	}
	n := max - 1
	// bitLen is the maximum bit length needed to encode a value < max.
	bitLen := bits.Len64(uint64(n))
	if bitLen == 0 {
		// the only valid result is 0
		return n
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
		_, _ = rnd.Read(bytes)
		// Clear bits in the first byte to increase the probability
		// that the candidate is < max.
		bytes[0] &= uint8(int(1<<b) - 1)

		// Change the data in the byte slice into an integer ('n')
		n = 0
		for _, val := range bytes {
			n = (n << 8) | int64(val)
		}

		if n < max {
			return n
		}
	}
}

// Uint63n returns, as an uint64, a unsigned 64 bit pseudo-random number in
// the half-open interval [0, max).
func (rnd *Rand) Uint64n(max uint64) uint64 {
	if max == 0 {
		return max
	}
	n := max - 1
	// bitLen is the maximum bit length needed to encode a value < max.
	bitLen := bits.Len64(n)
	if bitLen == 0 {
		// the only valid result is 0
		return n
	}
	// k is the maximum byte length needed to encode a value < max.
	k := (bitLen + 7) / 8
	bytes := make([]byte, k)
	for {
		_, _ = rnd.Read(bytes)
		// Change the data in the byte slice into an integer ('n')
		n = 0
		for _, val := range bytes {
			n = (n << 8) | uint64(val)
		}
		// Clear all but bitLen bits to increase the probibility that
		// n is less then max.
		n &= ((1 << bitLen) - 1)
		if n < max {
			return n
		}
	}
}

// Uint64 returns, as an uint64, a pseudo-random 64 bit number.
func (rnd *Rand) Uint64() uint64 {
	buf := make([]byte, 4)
	_, _ = rnd.Read(buf)
	n := uint64(0) | uint64(buf[0])
	n = (n << 8) | uint64(buf[1])
	n = (n << 8) | uint64(buf[2])
	n = (n << 8) | uint64(buf[3])
	return n
}

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
// in the half-open interval [0,n).
func (rnd *Rand) Perm(n int) []int {
	if n < 0 {
		panic(fmt.Sprintf("Perm called with a negative argument [%d]", n))
	}
	res := make([]int, n)
	for i := 1; i < n; i++ {
		j := rnd.Intn(i + 1)
		res[i] = res[j]
		res[j] = i
	}
	return res
}

// N returns a pseudo-random number in the half-open interval [0,n) from the default Source.
// The type parameter Int can be any integer type.
// It panics if n <= 0.
func N[Int intType](n Int, rnd *Rand) Int {
	if n <= 0 {
		panic("invalid argument to N")
	}
	return Int(rnd.Uint64n(uint64(n)))
}

type intType interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

func Shuffle[S ~[]E, E any](s S, rnd *Rand) S {
	nSlice := slices.Clone(s)
	for i := len(nSlice) - 1; i > 0; i-- {
		j := int(rnd.Int63n(int64(i + 1)))
		nSlice[i], nSlice[j] = nSlice[j], nSlice[i]
	}
	return nSlice
}

// Read generates len(p) random bytes and writes them into p. It
// always returns len(p) and a nil error.
// Read should not be called concurrently with any other Rand method.
func (rnd *Rand) Read(p []byte) (n int, err error) {
	return copy(p, rnd.machine.XORKeyStream(p)), nil
}
