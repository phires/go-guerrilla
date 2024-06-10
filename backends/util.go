package backends

import (
	"bytes"
	"compress/zlib"
	"crypto/md5" //#nosec G501 - Deprecated, kept for backwards compatibility
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"strings"

	"golang.org/x/crypto/blake2s"
)

// First capturing group is header name, second is header value.
// Accounts for folding headers.
var headerRegex, _ = regexp.Compile(`^([\S ]+):([\S ]+(?:\r\n\s[\S ]+)?)`)

// ParseHeaders parses the headers from the given mailData string and returns a map of header names to their values.
//
// Parameters:
// - mailData: a string containing the mail data.
//
// Return:
// - a map[string]string containing the parsed headers, where the keys are the header names and the values are the header values.
// Deprecated: use mail.Envelope.ParseHeader
func ParseHeaders(mailData string) map[string]string {
	var headerSectionEnds int
	for i, char := range mailData[:len(mailData)-4] {
		if char == '\r' {
			if mailData[i+1] == '\n' && mailData[i+2] == '\r' && mailData[i+3] == '\n' {
				headerSectionEnds = i + 2
			}
		}
	}
	headers := make(map[string]string)
	matches := headerRegex.FindAllStringSubmatch(mailData[:headerSectionEnds], -1)
	for _, h := range matches {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(strings.Replace(h[1], "\r\n", "", -1)))
		val := strings.TrimSpace(strings.Replace(h[2], "\r\n", "", -1))
		headers[name] = val
	}
	return headers
}

// MD5Hex generates a hexadecimal representation of the MD5 hash of the given string arguments.
//
// Parameters:
// - stringArguments: A variadic parameter that accepts one or more string arguments.
//
// Returns:
// - string: The hexadecimal representation of the MD5 hash.
// Deprecated: use BLAKE128s128Hex instead
func MD5Hex(stringArguments ...string) string {
	h := md5.New() //#nosec G401 - Deprecated, kept for backwards compatibility
	var r *strings.Reader
	for i := 0; i < len(stringArguments); i++ {
		r = strings.NewReader(stringArguments[i])
		_, _ = io.Copy(h, r)
	}
	sum := h.Sum([]byte{})
	return fmt.Sprintf("%x", sum)
}

// BLAKE2s128Hex generates a Blake2s-128 hash as a string of hex characters from the given string arguments.
//
// Parameters:
// - stringArguments: A variadic parameter that accepts one or more string arguments.
//
// Returns:
// - string: The Blake2s-128 hash as a string of hex characters.
// - error: An error if the hash generation fails.
func BLAKE2s128Hex(stringArguments ...string) (string, error) {
	// Create a zeroed 16-byte slice for unkeyed hashing.
	key := make([]byte, 16) // Zeroed key for unkeyed BLAKE2s

	h, err := blake2s.New128(key)
	if err != nil {
		return "", err
	}
	var r *strings.Reader
	for i := 0; i < len(stringArguments); i++ {
		r = strings.NewReader(stringArguments[i])
		_, err := io.Copy(h, r)
		if err != nil {
			return "", err
		}
	}
	sum := h.Sum([]byte{})
	return fmt.Sprintf("%x", sum), nil
}

// Compress concatenates and compresses all the strings passed in using zlib.
//
// Parameters:
// - stringArguments: A variadic parameter that accepts one or more string arguments.
//
// Returns:
// - string: The compressed string.
func Compress(stringArguments ...string) string {
	var b bytes.Buffer
	var r *strings.Reader
	w, _ := zlib.NewWriterLevel(&b, zlib.BestSpeed)
	for i := 0; i < len(stringArguments); i++ {
		r = strings.NewReader(stringArguments[i])
		_, _ = io.Copy(w, r)
	}
	_ = w.Close()
	return b.String()
}
