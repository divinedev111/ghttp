package ghttp

import (
	"io"
	"net/http/httptrace"
	"net/textproto"
	"strings"
)

var (
	headerNewlineToSpace = strings.NewReplacer("\n", " ", "\r", " ")
	defaultUserAgent     = "fqrious/ghttp (1.0)"
)

type hpair struct {
	key    string
	values []string
}
type myHeaders ([]*hpair)

func (h *myHeaders) set(k string, v string) {
	*h = append(*h, &hpair{k, []string{v}})
}

func (h *myHeaders) add(k string, vv []string) {
	*h = append([]*hpair(*h), &hpair{k, vv})
}

// stringWriter implements WriteString on a Writer.
type stringWriter struct {
	w io.Writer
}

func (w stringWriter) WriteString(s string) (n int, err error) {
	return w.w.Write([]byte(s))
}

func (h *myHeaders) writeSubset(w io.Writer, exclude map[string]bool, trace *httptrace.ClientTrace) error {
	ws, ok := w.(io.StringWriter)
	if !ok {
		ws = stringWriter{w}
	}
	for _, kv := range *h {
		var formattedVals []string
		for _, v := range kv.values {
			v = headerNewlineToSpace.Replace(v)
			v = textproto.TrimString(v)

			s := kv.key + ": " + v + "\r\n"
			if _, err := ws.WriteString(s); err != nil {
				return err
			}
			if trace != nil && trace.WroteHeaderField != nil {
				formattedVals = append(formattedVals, v)
			}
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(kv.key, formattedVals)
			formattedVals = nil
		}
	}
	return nil
}

// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if strings.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

func hasKey(h Header, key string) bool {
	_, ok := h[key]
	return ok
}
