// This file provides minimal HTTP/1.1 response parsing helpers used by the
// meeklike backhaul. We avoid pulling in net/http for the response path
// because the backhaul reads from a raw sillad.Pipe (net.Conn) that may not be
// an http.Response-friendly reader; a hand-rolled line reader is simpler and
// avoids buffering surprises.
package meeklike

import (
	"bufio"
	"io"
	"strings"
)

// bufReader wraps a bufio.Reader over r.
type bufReader struct {
	r *bufio.Reader
}

func newBufReader(r io.Reader) *bufReader {
	return &bufReader{r: bufio.NewReader(r)}
}

// ReadString reads until delim (inclusive) and returns the accumulated string.
func (b *bufReader) ReadString(delim byte) (string, error) {
	return b.r.ReadString(delim)
}

// Read implements io.Reader.
func (b *bufReader) Read(p []byte) (int, error) { return b.r.Read(p) }

// trimCRLF removes a trailing \r\n (or \n) from a line.
func trimCRLF(s string) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}

// trimSpace removes leading/trailing ASCII whitespace.
func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

// equalFold reports whether a and b are equal under ASCII case-folding, like
// http.Header matching.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
