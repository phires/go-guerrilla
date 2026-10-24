package backends

import (
	"compress/zlib"
	"io"
	"strings"
	"testing"
)

func TestBLAKE2s128Hex(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		want      string
		expectErr bool
	}{
		{
			name:      "single string",
			input:     []string{"example"},
			want:      "8b944eb07157cea5041a4b209fda1f09",
			expectErr: false,
		},
		{
			name:      "multiple strings",
			input:     []string{"example", "string", "arguments"},
			want:      "9645451b82265ee62552a4a1a12bc285",
			expectErr: false,
		},
		{
			name:      "empty input",
			input:     []string{""},
			want:      "69c907decfc59db6ceec48fb3412eccc",
			expectErr: false,
		},
		{
			name:      "no input",
			input:     []string{},
			want:      "69c907decfc59db6ceec48fb3412eccc",
			expectErr: false,
		},
		{
			name:      "♥️ unicode input",
			input:     []string{"♥️ unicode input"},
			want:      "900fdd1d2a1c73d69a60fe08721e8ddc",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BLAKE2s128Hex(tt.input...)
			if (err != nil) != tt.expectErr {
				t.Errorf("BLAKE2s128Hex() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.want {
				t.Errorf("BLAKE2s128Hex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMD5Hex(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		want      string
		expectErr bool
	}{
		{
			name:      "single string",
			input:     []string{"example"},
			want:      "1a79a4d60de6718e8e5b326e338ae533",
			expectErr: false,
		},
		{
			name:      "multiple strings",
			input:     []string{"example", "string", "arguments"},
			want:      "3a64be4275748ae9b712864a9d827405",
			expectErr: false,
		},
		{
			name:      "empty input",
			input:     []string{""},
			want:      "d41d8cd98f00b204e9800998ecf8427e",
			expectErr: false,
		},
		{
			name:      "no input",
			input:     []string{},
			want:      "d41d8cd98f00b204e9800998ecf8427e",
			expectErr: false,
		},
		{
			name:      "♥️ unicode input",
			input:     []string{"♥️ unicode input"},
			want:      "a4b99076d321097b647088684692363f",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MD5Hex(tt.input...)
			if got != tt.want {
				t.Errorf("MD5Hex() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCompress checks the contract of Compress: the result is a zlib stream that
// inflates back to the concatenated input. The exact bytes are not compared because
// they depend on the compress/flate implementation of the Go version in use.
func TestCompress(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "single string",
			input: []string{"example"},
			want:  "example",
		},
		{
			name:  "multiple strings",
			input: []string{"example", "string", "arguments"},
			want:  "examplestringarguments",
		},
		{
			name:  "empty input",
			input: []string{""},
			want:  "",
		},
		{
			name:  "no input",
			input: []string{},
			want:  "",
		},
		{
			name:  "♥️ unicode input",
			input: []string{"♥️ unicode input"},
			want:  "♥️ unicode input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compress(tt.input...)
			zr, err := zlib.NewReader(strings.NewReader(got))
			if err != nil {
				t.Fatalf("Compress() did not return a zlib stream: %v", err)
			}
			defer zr.Close()
			inflated, err := io.ReadAll(zr)
			if err != nil {
				t.Fatalf("Compress() returned a stream that does not inflate: %v", err)
			}
			if string(inflated) != tt.want {
				t.Errorf("Compress() inflates to %q, want %q", inflated, tt.want)
			}
		})
	}
}
