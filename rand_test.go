package jc1

import (
	"bytes"
	"fmt"
	"math/bits"
	"reflect"
	"testing"
)

// Equals - Tests if actual and expected are equal.
func Equals[T comparable](t *testing.T, actual, expected T) {
	t.Helper()

	if actual != expected {
		t.Errorf("got: %v; want: %v", actual, expected)
	}
}

// GenericEquals - Tests if actual and expected are equal and have the same
// type.
func GenericEquals[T comparable](t *testing.T, actual, expected T) {
	t.Helper()

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("got: %v(%v); want: %v(%v)",
			reflect.TypeOf(actual), actual, reflect.TypeOf(expected), expected)
	}
}

func fmtByteSlice(data []byte) string {
	var output bytes.Buffer
	dataLen := len(data)
	output.WriteString("[]byte{\n")
	for i := 0; i < dataLen; i += 16 {
		output.WriteString("    ")
		if i+16 < dataLen {
			for _, k := range data[i : i+15] {
				output.WriteString(fmt.Sprintf("%#02x, ", byte(k)))
			}
			output.WriteString(fmt.Sprintf("%#02x,\n", byte(data[i+15])))
		} else {
			l := len(data[i:])
			for _, k := range data[i : i+l-1] {
				output.WriteString(fmt.Sprintf("%#02x, ", byte(k)))
			}
			output.WriteString(fmt.Sprintf("%#02x}}\n", byte(data[i+l-1])))
		}
	}
	return output.String()
}

func fmtIntSlice(data []int) string {
	var output bytes.Buffer
	dataLen := len(data)
	output.WriteString("[]byte{\n")
	for i := 0; i < dataLen; i += 16 {
		output.WriteString("    ")
		if i+16 < dataLen {
			for _, k := range data[i : i+15] {
				output.WriteString(fmt.Sprintf("%#02x, ", byte(k)))
			}
			output.WriteString(fmt.Sprintf("%#02x,\n", byte(data[i+15])))
		} else {
			l := len(data[i:])
			for _, k := range data[i : i+l-1] {
				output.WriteString(fmt.Sprintf("%#02x, ", byte(k)))
			}
			output.WriteString(fmt.Sprintf("%#02x}}\n", byte(data[i+l-1])))
		}
	}
	return output.String()
}

// testPerm - Test that the result of the Perm call has every number
// in the half-open interval [0,n).
func testPerm(p []int) bool {
	u := make([]uint64, (len(p)+63)/64)
	for _, v := range p {
		if v < 0 || v >= len(p) {
			return false
		}
		u[v>>6] |= (1 << (v & 63))
	}
	var bitCnt int = 0
	for _, v := range u {
		bitCnt += bits.OnesCount64(v)
	}
	return bitCnt == len(p)
}

func TestRand_New(t *testing.T) {
	jc1Machine := new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun"))
	type args struct {
		src *Cipher
	}
	tests := []struct {
		name  string
		rnd   *Rand
		args  args
		wantM *Cipher
	}{
		{
			name:  "TestRand_New",
			rnd:   new(Rand),
			args:  args{src: jc1Machine},
			wantM: jc1Machine,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rnd.New(tt.args.src)
			defer got.StopRand()
			if got.machine != tt.wantM {
				t.Errorf("Rand.New().jc1Machine = %v, want = %v\n", got.machine, tt.wantM)
			}
		})
	}
}

func TestRand_StopRand(t *testing.T) {
	tests := []struct {
		name string
		rnd  *Rand
	}{
		{
			name: "TestRand_StopRand1",
			rnd:  new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun"))),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rnd := new(Rand)
			tt.rnd.StopRand()
			if !reflect.DeepEqual(tt.rnd, rnd) {
				t.Errorf("Rand = %v, want %v", tt.rnd, rnd)
			}
		})
	}
}

func TestRand_Intn(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer rnd.StopRand()
	type args struct {
		max int
	}
	tests := []struct {
		name string
		rnd  *Rand
		args args
		want int
	}{
		{
			name: "TestRand_Intn1",
			rnd:  rnd,
			args: args{MaxInt},
			want: 1409018342421102683,
		},
		{
			name: "TestRand_Intn2",
			rnd:  rnd,
			args: args{MaxInt},
			want: 9019649713407190787,
		},
		{
			name: "TestRand_Intn3",
			rnd:  rnd,
			args: args{MaxInt},
			want: 6131602311772895323,
		},
		{
			name: "TestRand_Intn4",
			rnd:  rnd,
			args: args{MaxInt},
			want: 3863511892633736299,
		},
		{
			name: "TestRand_Intn5",
			rnd:  rnd,
			args: args{MaxInt},
			want: 7783430371597520802,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rnd.Intn(tt.args.max); got != tt.want {
				t.Errorf("Rand.Intn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRand_Int15n(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer rnd.StopRand()
	type args struct {
		max int16
	}
	tests := []struct {
		name string
		args args
		want int16
	}{
		{
			name: "TestRand_Int15n1",
			args: args{MaxInt16},
			want: 5005,
		},
		{
			name: "TestRand_Int15n2",
			args: args{MaxInt16},
			want: 22199,
		},
		{
			name: "TestRand_Int15n3",
			args: args{MaxInt16},
			want: 5637,
		},
		{
			name: "TestRand_Int15n4",
			args: args{MaxInt16},
			want: 91,
		},
		{
			name: "TestRand_Int15n5",
			args: args{MaxInt16},
			want: 32044,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rnd.Int15n(tt.args.max); got != tt.want {
				t.Errorf("Rand.Int15n() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRand_Int31n(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer rnd.StopRand()
	type args struct {
		max int32
	}
	tests := []struct {
		name string
		args args
		want int32
	}{
		{
			name: "TestRand_Int31n1",
			args: args{MaxInt32},
			want: 328062647,
		},
		{
			name: "TestRand_Int31n2",
			args: args{MaxInt32},
			want: 369426523,
		},
		{
			name: "TestRand_Int31n3",
			args: args{MaxInt32},
			want: 2100050848,
		},
		{
			name: "TestRand_Int31n4",
			args: args{MaxInt32},
			want: 1310123779,
		},
		{
			name: "TestRand_Int31n5",
			args: args{MaxInt32},
			want: 1427624912,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rnd.Int31n(tt.args.max); got != tt.want {
				t.Errorf("Rand.Int31n() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRand_Int63n(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer rnd.StopRand()
	type args struct {
		max int64
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "TestRand_Int63n1",
			args: args{MaxInt64},
			want: 1409018342421102683,
		},
		{
			name: "TestRand_Int63n2",
			args: args{MaxInt64},
			want: 9019649713407190787,
		},
		{
			name: "TestRand_Int63n3",
			args: args{MaxInt64},
			want: 6131602311772895323,
		},
		{
			name: "TestRand_Int63n4",
			args: args{MaxInt64},
			want: 3863511892633736299,
		},
		{
			name: "TestRand_Int63n5",
			args: args{MaxInt64},
			want: 7783430371597520802,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rnd.Int63n(tt.args.max); got != tt.want {
				t.Errorf("Rand.Int63n() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRand_Uint64(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer rnd.StopRand()
	tests := []struct {
		name string
		rnd  *Rand
		want uint64
	}{
		{
			name: "Rand_Uint64.1",
			rnd:  rnd,
			want: uint64(2475546295),
		},
		{
			name: "Rand_Uint64.2",
			rnd:  rnd,
			want: uint64(2516910171),
		},
		{
			name: "Rand_Uint64.3",
			rnd:  rnd,
			want: uint64(2100050848),
		},
		{
			name: "Rand_Uint64.4",
			rnd:  rnd,
			want: uint64(1310123779),
		},
		{
			name: "Rand_Uint64.5",
			rnd:  rnd,
			want: uint64(3575108560),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Equals(t, tt.rnd.Uint64(), tt.want)
		})
	}
}

func TestRand_Perm(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	type args struct {
		n int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "Perm Test 1",
			args: args{0},
			want: []int{},
		},
		{
			name: "Perm Test 2",
			args: args{1},
			want: []int{0},
		},
		{
			name: "Perm Test 3",
			args: args{10},
			want: []int{0x06, 0x08, 0x03, 0x07, 0x02, 0x09, 0x00, 0x01, 0x04, 0x05},
		}, {
			name: "Perm Test 4",
			args: args{256},
			want: []int{
				0x32, 0xf2, 0xc6, 0xe6, 0xaa, 0xae, 0x03, 0x4e, 0x3f, 0xf3, 0xf7, 0x0e, 0xe1, 0x72, 0x28, 0x36,
				0x8a, 0xf0, 0x19, 0x4a, 0xd4, 0x47, 0xd7, 0x62, 0xfa, 0x6c, 0x05, 0x20, 0xaf, 0xab, 0x1b, 0x8c,
				0xf1, 0xa1, 0x7a, 0xac, 0xfc, 0x81, 0xbc, 0xc0, 0x6e, 0xd6, 0x60, 0xe8, 0xbb, 0x50, 0x23, 0x41,
				0xb7, 0xea, 0x1a, 0x25, 0x21, 0x07, 0x89, 0xee, 0xb4, 0x5d, 0x13, 0x94, 0xf5, 0x46, 0x90, 0x45,
				0x0c, 0x37, 0xeb, 0xe4, 0x2e, 0xcb, 0xb6, 0x6b, 0x7f, 0x33, 0x6f, 0x02, 0x69, 0x17, 0x61, 0xe9,
				0x7e, 0x44, 0x2f, 0xd3, 0xb5, 0x01, 0x16, 0xef, 0xcc, 0x78, 0xbe, 0x56, 0x09, 0x75, 0x22, 0x3b,
				0xbf, 0xe2, 0x2c, 0xec, 0xd5, 0x2a, 0x97, 0xd2, 0x76, 0x40, 0x7b, 0x74, 0x96, 0x38, 0xb9, 0x06,
				0x3a, 0x1e, 0xed, 0x10, 0x65, 0xb1, 0x84, 0x9b, 0xd1, 0x18, 0x04, 0x51, 0x39, 0xe0, 0x11, 0x7d,
				0x8b, 0x1f, 0x71, 0x0d, 0x6d, 0x9a, 0x24, 0x48, 0xad, 0xa5, 0xa4, 0x98, 0x79, 0xc8, 0xa9, 0x59,
				0x0a, 0x85, 0xcf, 0xa7, 0xc2, 0x0f, 0x99, 0x95, 0xa0, 0xca, 0x2b, 0xce, 0x8e, 0xc9, 0x5a, 0x82,
				0xfb, 0x88, 0xdd, 0x57, 0xa8, 0x34, 0x87, 0x83, 0x9e, 0x73, 0x7c, 0xe3, 0x3e, 0xc7, 0xdc, 0x67,
				0xda, 0xa6, 0xb8, 0x6a, 0x53, 0xdf, 0x9f, 0x52, 0x31, 0x63, 0x42, 0x1c, 0xe5, 0x93, 0x5e, 0xd0,
				0x29, 0x9c, 0x91, 0x26, 0x77, 0xd8, 0xfe, 0x86, 0x4b, 0x43, 0xba, 0x68, 0x55, 0x58, 0x4c, 0xf4,
				0xa2, 0x08, 0x8d, 0xff, 0x3d, 0xc5, 0x2d, 0xcd, 0x66, 0xf8, 0x80, 0xf6, 0x4d, 0x5f, 0xc1, 0xb2,
				0xdb, 0x27, 0x35, 0xc3, 0x49, 0x4f, 0x30, 0x3c, 0x12, 0x1d, 0xfd, 0x00, 0x14, 0x92, 0xd9, 0xf9,
				0x64, 0x8f, 0x54, 0xc4, 0x5c, 0xb3, 0xde, 0xb0, 0xe7, 0xbd, 0x70, 0xa3, 0x15, 0x9d, 0x5b, 0x0b},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rnd.Perm(tt.args.n); !(testPerm(got) && reflect.DeepEqual(got, tt.want)) {
				t.Errorf("Rand.Perm() = %v, want %v", fmtIntSlice(got), fmtIntSlice(tt.want))
			}
		})
	}
}

func TestN(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "TestN for int8 type",
			got:  N(int8(45), rnd),
			want: int8(19),
		},
		{
			name: "TestN for int16 type",
			got:  N(int16(12345), rnd),
			want: int16(3542),
		},
		{
			name: "TestN for int32 type",
			got:  N(int32(123456), rnd),
			want: int32(103941),
		},
		{
			name: "TestN for int64 type",
			got:  N(int64(1234567), rnd),
			want: int64(23421),
		},
		{
			name: "TestN for uint8 type",
			got:  N(uint8(45), rnd),
			want: uint8(44),
		},
		{
			name: "TestN for uint16 type",
			got:  N(uint16(12345), rnd),
			want: uint16(4789),
		},
		{
			name: "TestN for uint32 type",
			got:  N(uint32(123456), rnd),
			want: uint32(71635),
		},
		{
			name: "TestN for uint64 type",
			got:  N(uint64(1234567), rnd),
			want: uint64(1106223),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GenericEquals(t, tt.got, tt.want)
		})
	}
}

func TestShuffle(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "TestShuffle1",
			got:  Shuffle([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, rnd),
			want: []int{6, 1, 7, 2, 0, 9, 8, 5, 4, 3},
		},
		{
			name: "TestShuffle2",
			got:  Shuffle([]int16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, rnd),
			want: []int16{2, 4, 8, 6, 1, 0, 9, 7, 5, 3},
		},
		{
			name: "TestShuffle3",
			got:  Shuffle([]string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}, rnd),
			want: []string{"G", "E", "H", "C", "B", "A", "D", "I", "F"},
		},
		{
			name: "TestShuffle4",
			got:  Shuffle([][]int64{{0, 1}, {2, 3}, {4, 5}, {6, 7}, {8, 9}}, rnd),
			want: [][]int64{{4, 5}, {2, 3}, {6, 7}, {0, 1}, {8, 9}},
		},
		{
			name: "TestShuffle5",
			got:  Shuffle([][][]int64{{{0, 1}, {2, 3}}, {{4, 5}, {6, 7}}, {{8, 9}}}, rnd),
			want: [][][]int64{{{8, 9}}, {{0, 1}, {2, 3}}, {{4, 5}, {6, 7}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GenericEquals(t, tt.got, tt.want)
		})
	}
}

func TestRand_Read(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		args    args
		wantN   int
		wantErr bool
		wantP   []byte
	}{
		{
			name:    "Rand_Read1",
			args:    args{p: make([]byte, CipherBlockBytes)},
			wantN:   CipherBlockBytes,
			wantErr: false,
			wantP: []byte{
				0x93, 0x8d, 0xd6, 0xb7, 0x96, 0x05, 0x00, 0x5b, 0x7d, 0x2c, 0x3b, 0xa0, 0x4e, 0x16, 0xe7, 0x03,
				0xd5, 0x17, 0xd3, 0xd0, 0xe1, 0x2f, 0xf8, 0x5b, 0xb5, 0x9d, 0xf3, 0x98, 0xb9, 0xee, 0x54, 0x6b},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotN, err := rnd.Read(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Rand.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("Rand.Read() = %v, want %v", gotN, tt.wantN)
			}
			if !reflect.DeepEqual(tt.args.p, tt.wantP) {
				t.Errorf("Rand.Read(p) = %s, want %s\n", fmtByteSlice(tt.args.p), fmtByteSlice(tt.wantP))
			}
		})
	}
}

func TestRand_Uint64n(t *testing.T) {
	rnd := new(Rand).New(new(Cipher).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	type args struct {
		max uint64
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{
			name: "TestRand_Uint64n0",
			args: args{max: MaxUint8},
			want: 147,
		},
		{
			name: "TestRand_Uint64n1",
			args: args{max: MaxUint16},
			want: 36310,
		},
		{
			name: "TestRand_Uint64n2",
			args: args{max: MaxUint32},
			want: 3080062208,
		},
		{
			name: "TestRand_Uint64n3",
			args: args{max: MaxUint64},
			want: 6592474064144439015,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rnd.Uint64n(tt.args.max); got != tt.want {
				t.Errorf("Rand.Uint64n() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUberRand_New(t *testing.T) {
	jc1Machine := new(UberJc1).New([]byte("NowIsNotTheTimeToRunForFun"))
	type args struct {
		src *UberJc1
	}
	tests := []struct {
		name  string
		rnd   *Rand
		args  args
		wantM *UberJc1
	}{
		{
			name:  "TestUberRand_New",
			rnd:   new(Rand),
			args:  args{src: jc1Machine},
			wantM: jc1Machine,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rnd.New(tt.args.src)
			defer got.StopRand()
			if got.machine != tt.wantM {
				t.Errorf("Rand.New().jc1Machine = %v, want = %v\n", got.machine, tt.wantM)
			}
		})
	}
}

func TestUberRand_Read(t *testing.T) {
	rnd := new(Rand).New(new(UberJc1).New([]byte("NowIsNotTheTimeToRunForFun")))
	defer func() { rnd = nil }()
	defer rnd.StopRand()
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		args    args
		wantN   int
		wantErr bool
		wantP   []byte
	}{
		{
			name:    "Rand_Read1",
			args:    args{p: make([]byte, CipherBlockBytes)},
			wantN:   CipherBlockBytes,
			wantErr: false,
			wantP: []byte{
				0xa5, 0xd2, 0xff, 0x12, 0xdc, 0xa1, 0x32, 0x28, 0x3a, 0xde, 0x47, 0xb2, 0x07, 0x7f, 0xec, 0x10,
				0x7c, 0x3a, 0x98, 0x56, 0xe5, 0xc4, 0x04, 0xa6, 0xe4, 0xc1, 0x8c, 0x4b, 0x30, 0x10, 0xfb, 0x67},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotN, err := rnd.Read(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("UberRand.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("UberRand.Read() = %v, want %v", gotN, tt.wantN)
			}
			if !reflect.DeepEqual(tt.args.p, tt.wantP) {
				t.Errorf("UberRand.Read(p) = %s, want %s\n", fmtByteSlice(tt.args.p), fmtByteSlice(tt.wantP))
			}
		})
	}
}
