package backends

import (
	"encoding/base64"
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

// TestCompress tests the compress function
// It converts the compressed string to base64 to make it comparable
func TestCompress(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		want      string
		expectErr bool
	}{
		{
			name:      "single string",
			input:     []string{"example"},
			want:      "eAEABwD4/2V4YW1wbGUBAAD//wvAAu0=",
			expectErr: false,
		},
		{
			name:      "multiple strings",
			input:     []string{"example", "string", "arguments"},
			want:      "eAEAFgDp/2V4YW1wbGVzdHJpbmdhcmd1bWVudHMBAAD//2sQCVo=",
			expectErr: false,
		},
		{
			name:      "empty input",
			input:     []string{""},
			want:      "eAEBAAD//wAAAAE=",
			expectErr: false,
		},
		{
			name:      "no input",
			input:     []string{},
			want:      "eAEBAAD//wAAAAE=",
			expectErr: false,
		},
		{
			name:      "♥️ unicode input",
			input:     []string{"♥️ unicode input"},
			want:      "eAEAFADr/+KZpe+4jyB1bmljb2RlIGlucHV0AQAA//9yqAmu",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compress(tt.input...)
			base64 := base64.StdEncoding.EncodeToString([]byte(got))
			if base64 != tt.want {
				t.Errorf("Compress() = %v, want %v", base64, tt.want)
			}
		})
	}
}
