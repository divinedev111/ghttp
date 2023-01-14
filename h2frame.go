package ghttp

import (
	"fmt"
	"net/http"

	"golang.org/x/net/http2/hpack"
)

type headersEnder interface {
	HeadersEnded() bool
}

type continuable interface {
	http2Frame
	headersEnder
	HeaderBlockFragment() []byte
	clearHeaderBlockFragment()
}

type metaFrame struct {
	Fields    []hpack.HeaderField
	Truncated bool
}

// pseudoFields returns the pseudo header fields of mf.
// The caller does not own the returned slice.
func (mf *metaFrame) pseudoFields() []hpack.HeaderField {
	for i, hf := range mf.Fields {
		if !hf.IsPseudo() {
			return mf.Fields[:i]
		}
	}
	return mf.Fields
}

func (mf *metaFrame) checkPseudos() error {
	var isRequest, isResponse bool
	pf := mf.pseudoFields()
	for i, hf := range pf {
		switch hf.Name {
		case ":method", ":path", ":scheme", ":authority":
			isRequest = true
		case ":status":
			isResponse = true
		default:
			return http2pseudoHeaderError(hf.Name)
		}
		// Check for duplicates.
		// This would be a bad algorithm, but N is 4.
		// And this doesn't allocate.
		for _, hf2 := range pf[:i] {
			if hf.Name == hf2.Name {
				return http2duplicatePseudoHeaderError(hf.Name)
			}
		}
	}
	if isRequest && isResponse {
		return http2errMixPseudoHeaderTypes
	}
	return nil
}

var bodyRequestHeaders = []string{
	"Content-Encoding",
	"Content-Length",
	"Expect",
	"Te",
	"Trailer",
}

func checkValidPushPromiseRequestHeaders(h http.Header) error {
	// PUSH_PROMISE requests cannot have a body
	// http://tools.ietf.org/html/rfc7540#section-8.2
	for _, k := range bodyRequestHeaders {
		if _, ok := h[k]; ok {
			return fmt.Errorf("promised request cannot include body related header %q", k)
		}
	}
	if _, ok := h["Host"]; ok {
		fmt.Println(h)
		return fmt.Errorf(`promised URL must be absolute so "Host" header disallowed`)
	}
	return nil
}

// A MetaPushPromiseFrame is the representation of one PUSH_PROMISE frame and
// zero or more contiguous CONTINUATION frames and the decoding of
// their HPACK-encoded contents.
//
// This type of frame does not appear on the wire and is only returned
// by the Framer when Framer.ReadMetaHeaders is set.
type MetaPushPromiseFrame struct {
	*http2PushPromiseFrame

	// Fields are the fields contained in the PUSH_PROMISE and
	// CONTINUATION frames. The underlying slice is owned by the
	// Framer and must not be retained after the next call to
	// ReadFrame.
	//
	// Fields are guaranteed to be in the correct http2 order and
	// not have unknown pseudo header fields or invalid header
	// field names or values. Required pseudo header fields may be
	// missing, however. Use the MetaPushPromiseFrame.Pseudo accessor
	// method to access pseudo headers.
	Fields []hpack.HeaderField

	// Truncated is whether the max header list size limit was hit
	// and Fields is incomplete. The hpack decoder state is still
	// valid, however.
	Truncated bool
}

// PseudoValue returns the given pseudo header field's value.
// The provided pseudo field should not contain the leading colon.
func (mp *MetaPushPromiseFrame) PseudoValue(pseudo string) string {
	for _, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return ""
		}
		if hf.Name[1:] == pseudo {
			return hf.Value
		}
	}
	return ""
}

// RegularFields returns the regular (non-pseudo) header fields of mp.
// The caller does not own the returned slice.
func (mp *MetaPushPromiseFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return mp.Fields[i:]
		}
	}
	return nil
}

// PseudoFields returns the pseudo header fields of mp.
// The caller does not own the returned slice.
func (mp *MetaPushPromiseFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mp.Fields {
		if !hf.IsPseudo() {
			return mp.Fields[:i]
		}
	}
	return mp.Fields
}

func (f *http2HeadersFrame) clearHeaderBlockFragment() {
	f.headerFragBuf = nil
}
func (f *http2PushPromiseFrame) clearHeaderBlockFragment() {
	f.headerFragBuf = nil
}
func (f *http2ContinuationFrame) clearHeaderBlockFragment() {
	f.headerFragBuf = nil
}
