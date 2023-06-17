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
	"reflect"
	"testing"
)

func TestCipher_New(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		want *Cipher
	}{
		{
			name: "tcn1",
			args: args{
				key: []byte("SecretKey"),
			},
			want: &Cipher{
				state: [256]byte{
					100, 234, 203, 226, 40, 184, 146, 92, 253, 108, 10, 12, 14, 16, 18, 20,
					22, 24, 26, 28, 30, 32, 34, 36, 38, 122, 78, 44, 46, 48, 50, 52,
					54, 56, 58, 60, 62, 194, 4, 68, 70, 72, 74, 76, 78, 186, 154, 84,
					86, 88, 90, 92, 128, 96, 98, 100, 102, 104, 174, 108, 110, 112, 114, 120,
					118, 120, 122, 242, 240, 128, 130, 132, 220, 136, 138, 140, 232, 144, 146, 148,
					134, 152, 154, 202, 158, 160, 162, 46, 166, 168, 14, 172, 174, 106, 178, 180,
					4, 184, 186, 60, 190, 192, 66, 196, 198, 124, 202, 2, 206, 208, 90, 212,
					244, 216, 218, 196, 222, 24, 226, 228, 172, 232, 110, 236, 56, 240, 10, 244,
					246, 188, 250, 186, 254, 168, 2, 158, 6, 156, 10, 146, 14, 176, 18, 198,
					22, 26, 26, 84, 152, 58, 82, 36, 140, 40, 88, 44, 156, 64, 50, 150,
					54, 116, 58, 212, 216, 64, 2, 171, 124, 192, 74, 66, 136, 80, 206, 102,
					86, 4, 192, 228, 0, 180, 178, 114, 211, 218, 46, 146, 110, 96, 202, 116,
					18, 66, 134, 124, 136, 232, 130, 68, 122, 220, 138, 226, 104, 240, 146, 94,
					148, 36, 182, 156, 160, 120, 18, 174, 116, 83, 142, 136, 252, 176, 244, 6,
					132, 170, 230, 188, 80, 128, 106, 126, 60, 252, 202, 80, 84, 16, 110, 46,
					116, 68, 22, 234, 222, 138, 210, 18, 98, 12, 136, 152, 184, 90, 138, 118},
				p: 9,
				q: 203,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(Cipher).New(tt.args.key)
			if got := k.New(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Cipher.New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCipher_XORKeyStream(t *testing.T) {
	type args struct {
		key []byte
		src []byte
	}
	tests := []struct {
		name  string
		args  args
		want  []byte
		wantS []byte
	}{
		{
			name: "tcxs1",
			args: args{
				key: []byte("SecretKey"),
				src: make([]byte, 16),
			},
			want:  []byte{140, 193, 72, 147, 56, 229, 146, 243, 252, 203, 221, 121, 52, 206, 154, 227},
			wantS: make([]byte, 16),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := new(Cipher).New(tt.args.key)
			got := key.XORKeyStream(tt.args.src)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Cipher.XORKeyStream() = %v, want %v", got, tt.want)
			}
			if reflect.DeepEqual(got, tt.args.src) {
				t.Errorf("Cipher.XORKeyStream() = %v, should not equal %v", got, tt.wantS)
			}
		})
	}
}

func TestCipher_Read(t *testing.T) {
	type args struct {
		key []byte
		buf []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantN   int
		wantErr bool
	}{
		{
			name: "tcr1",
			args: args{
				key: []byte("SecretKey"),
				buf: make([]byte, 16),
			},
			want:    []byte{140, 193, 72, 147, 56, 229, 146, 243, 252, 203, 221, 121, 52, 206, 154, 227},
			wantN:   16,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := new(Cipher).New(tt.args.key)
			gotN, err := key.Read(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Cipher.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("Cipher.Read() = %v, want %v", gotN, tt.wantN)
			}
			if !reflect.DeepEqual(tt.args.buf, tt.want) {
				t.Errorf("Cipher.Read(buf) = %v, want %v", tt.args.buf, tt.want)
			}
		})
	}
}

func TestCipher_Reset(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		want *Cipher
	}{
		{
			name: "tcr1",
			args: args{
				key: []byte("SecretKey"),
			},
			want: &Cipher{
				state: [256]byte{
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				p: 0,
				q: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := new(Cipher).New(tt.args.key)
			key.Reset()
			if !reflect.DeepEqual(key, tt.want) {
				t.Errorf("Cipher.Reset() = %v, want %v", key, tt.want)
			}
		})
	}
}

func TestCipher_String(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "tcn1",
			args: args{
				key: []byte("SecretKey"),
			},
			want: "jc1:\t[]byte{\n" +
				"\t\t64, ea, cb, e2, 28, b8, 92, 5c, fd, 6c, 0a, 0c, 0e, 10, 12, 14,\n" +
				"\t\t16, 18, 1a, 1c, 1e, 20, 22, 24, 26, 7a, 4e, 2c, 2e, 30, 32, 34,\n" +
				"\t\t36, 38, 3a, 3c, 3e, c2, 04, 44, 46, 48, 4a, 4c, 4e, ba, 9a, 54,\n" +
				"\t\t56, 58, 5a, 5c, 80, 60, 62, 64, 66, 68, ae, 6c, 6e, 70, 72, 78,\n" +
				"\t\t76, 78, 7a, f2, f0, 80, 82, 84, dc, 88, 8a, 8c, e8, 90, 92, 94,\n" +
				"\t\t86, 98, 9a, ca, 9e, a0, a2, 2e, a6, a8, 0e, ac, ae, 6a, b2, b4,\n" +
				"\t\t04, b8, ba, 3c, be, c0, 42, c4, c6, 7c, ca, 02, ce, d0, 5a, d4,\n" +
				"\t\tf4, d8, da, c4, de, 18, e2, e4, ac, e8, 6e, ec, 38, f0, 0a, f4,\n" +
				"\t\tf6, bc, fa, ba, fe, a8, 02, 9e, 06, 9c, 0a, 92, 0e, b0, 12, c6,\n" +
				"\t\t16, 1a, 1a, 54, 98, 3a, 52, 24, 8c, 28, 58, 2c, 9c, 40, 32, 96,\n" +
				"\t\t36, 74, 3a, d4, d8, 40, 02, ab, 7c, c0, 4a, 42, 88, 50, ce, 66,\n" +
				"\t\t56, 04, c0, e4, 00, b4, b2, 72, d3, da, 2e, 92, 6e, 60, ca, 74,\n" +
				"\t\t12, 42, 86, 7c, 88, e8, 82, 44, 7a, dc, 8a, e2, 68, f0, 92, 5e,\n" +
				"\t\t94, 24, b6, 9c, a0, 78, 12, ae, 74, 53, 8e, 88, fc, b0, f4, 06,\n" +
				"\t\t84, aa, e6, bc, 50, 80, 6a, 7e, 3c, fc, ca, 50, 54, 10, 6e, 2e,\n" +
				"\t\t74, 44, 16, ea, de, 8a, d2, 12, 62, 0c, 88, 98, b8, 5a, 8a, 76})\n" +
				"\tp: 09\n" +
				"\tq: cb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := new(Cipher).New(tt.args.key)
			got := key.String()
			if got != tt.want {
				t.Errorf("Cipher.String() = \n%v, want \n%v", got, tt.want)
			}
		})
	}
}
