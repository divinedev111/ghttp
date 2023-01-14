// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

var (
	errMissingHeaderMethod    = errors.New("http2: missing required request pseudo-header :method")
	errMissingHeaderScheme    = errors.New("http2: missing required request pseudo-header :scheme")
	errMissingHeaderPath      = errors.New("http2: missing required request pseudo-header :path")
	errMissingHeaderAuthority = errors.New("http2: missing required request pseudo-header :authority")
	errInvalidMethod          = errors.New("http2: method must be GET or HEAD")
	errInvalidScheme          = errors.New("http2: scheme must be http or https")
)

// PushHandler consumes a pushed response.
type PushHandler interface {
	// HandlePush will be called once for every PUSH_PROMISE received
	// from the server. If HandlePush returns before the pushed stream
	// has completed, the pushed stream will be canceled.
	HandlePush(r *PushedRequest)
}

// PushedRequest describes a request that was pushed from the server.
type PushedRequest struct {
	// Promise is the HTTP/2 PUSH_PROMISE message. The promised
	// request does not have a body. Handlers should not modify Promise.
	//
	// Promise.RemoteAddr is the address of the server that started this push request.
	Promise *http.Request

	// OriginalRequestURL is the URL of the original client request that triggered the push.
	OriginalRequestURL *url.URL

	// OriginalRequestHeader contains the headers of the original client request that triggered the push.
	OriginalRequestHeader http.Header

	pushedStream *http2clientStream
}

// ReadResponse reads the pushed response. If ctx is done before the
// response headers are fully received, ReadResponse will fail and PushedRequest
// will be cancelled.
func (pr *PushedRequest) ReadResponse(ctx context.Context) (*http.Response, error) {
	select {
	case <-ctx.Done():
		pr.Cancel()
		pr.pushedStream.bufPipe.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	case <-pr.pushedStream.peerReset:
		return nil, pr.pushedStream.resetErr
	case resErr := <-pr.pushedStream.resc:
		if resErr.err != nil {
			pr.Cancel()
			pr.pushedStream.bufPipe.CloseWithError(resErr.err)
			return nil, resErr.err
		}
		resErr.res.Request = pr.Promise
		resErr.res.TLS = convertStatePtr(pr.pushedStream.cc.tlsState)
		return resErr.res, resErr.err
	}
}

// Cancel tells the server that the pushed response stream should be terminated.
// See: https://tools.ietf.org/html/rfc7540#section-8.2.2
func (pr *PushedRequest) Cancel() {
	pr.pushedStream.cancelStream()
}

func pushedRequestToHTTPRequest(mppf *MetaPushPromiseFrame) (*http.Request, error) {
	method := mppf.PseudoValue("method")
	scheme := mppf.PseudoValue("scheme")
	authority := mppf.PseudoValue("authority")
	path := mppf.PseudoValue("path")
	// pseudo-headers required in all http2 requests
	if method == "" {
		return nil, errMissingHeaderMethod
	}
	if scheme == "" {
		return nil, errMissingHeaderScheme
	}
	if path == "" {
		return nil, errMissingHeaderPath
	}
	// authority is required for PUSH_PROMISE requests per RFC 7540 Section 8.2
	if authority == "" {
		return nil, errMissingHeaderAuthority
	}

	// "Promised requests MUST be cacheable (see [RFC7231], Section 4.2.3),
	// MUST be safe (see [RFC7231], Section 4.2.1)"
	// https://tools.ietf.org/html/rfc7540#section-8.2
	if method != "GET" && method != "HEAD" {
		return nil, errInvalidMethod
	}
	if scheme != "http" && scheme != "https" {
		return nil, errInvalidScheme
	}

	var headers http.Header
	for _, header := range mppf.RegularFields() {
		if len(headers) == 0 {
			headers = http.Header{}
		}
		if strings.EqualFold(header.Name, "host") {
			// fmt.Println("equals ====>", header.Value)
			continue
		}
		headers.Add(header.Name, header.Value)
	}
	if err := checkValidPushPromiseRequestHeaders(headers); err != nil {
		return nil, err
	}
	if err := http2checkValidHTTP2RequestHeaders(headers); err != nil {
		return nil, err
	}

	reqUrl, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, err
	}
	reqUrl.Host = authority
	reqUrl.Scheme = scheme
	return &http.Request{
		Method:     method,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		URL:        reqUrl,
		Header:     headers,
	}, nil
}

// handlePushEarlyReturnCancel handles the pushed request with the push handler.
// If PushHandler.HandlePush returns before the pushed stream has completed, the pushed
// stream is canceled.
func handlePushEarlyReturnCancel(pushHandler PushHandler, pushedRequest *PushedRequest) {
	handleReturned := make(chan struct{})
	go func() {
		defer close(handleReturned)
		pushHandler.HandlePush(pushedRequest)
	}()
	select {
	case <-handleReturned:
		pushedRequest.Cancel()
	case <-pushedRequest.pushedStream.done:
	}
}

//lol

func (rl *http2clientConnReadLoop) _processPushPromise(f *MetaPushPromiseFrame) error {
	if rl.cc.t.PushHandler == nil { // should not be receiving PUSH_PROMISE if ENABLE_PUSH is disabled
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	if f.StreamID%2 != 1 { // Reject recursive push
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	if f.PromiseID%2 != 0 { // Reject invalid server-initiated stream id
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	stream := rl.cc.streamByID(f.StreamID, false)
	// "A receiver MUST treat the receipt of a PUSH_PROMISE on a stream that is neither
	// "open" nor "half-closed (local)" as a connection error of type PROTOCOL_ERROR"
	// See: https://tools.ietf.org/html/rfc7540#section-6.6
	if stream == nil || stream.resetErr != nil || stream.gotEndStream {
		return http2ConnectionError(http2ErrCodeProtocol)
	}

	rl.cc.mu.Lock()
	if f.PromiseID <= rl.cc.highestPromiseID {
		rl.cc.mu.Unlock()
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	rl.cc.highestPromiseID = f.PromiseID
	pushedStream := rl.cc.newStreamWithId(f.PromiseID, false)
	rl.cc.mu.Unlock()

	pushedReq, err := pushedRequestToHTTPRequest(f)
	if err != nil {
		return http2StreamError{f.StreamID, http2ErrCodeProtocol, err}
	}
	pushedReq.RemoteAddr = rl.cc.dialedAddr

	// Reject non-authoritative pushes
	skipVerify := true //rl.cc.t.TLSClientConfig != nil && rl.cc.t.TLSClientConfig.InsecureSkipVerify
	if !skipVerify {
		if stream.req.URL.Scheme != pushedReq.URL.Scheme {
			err := fmt.Errorf("push's scheme %q not equal to original request's scheme %q",
				pushedReq.URL.Scheme, stream.req.URL.Scheme)
			return http2StreamError{f.StreamID, http2ErrCodeProtocol, err}
		}
		pushHost, pushPort := authorityHostPort(pushedReq.URL.Scheme, pushedReq.URL.Host)
		origHost, origPort := authorityHostPort(stream.req.URL.Scheme, stream.req.URL.Host)
		if origPort != pushPort {
			err := fmt.Errorf("push's port %q not equal to original request's port %q", pushPort, origPort)
			return http2StreamError{f.StreamID, http2ErrCodeProtocol, err}
		}
		var authoritative bool
		if rl.cc.tlsState != nil {
			authoritative = len(rl.cc.tlsState.VerifiedChains) > 0 &&
				rl.cc.tlsState.PeerCertificates[0].VerifyHostname(pushedReq.URL.Hostname()) == nil
		} else {
			// Non-TLS connection
			authoritative = pushHost == origHost
		}
		if !authoritative {
			// fmt.Printf("origHost: %q, pushHost: %q, certLength: %d, verifySSL: %t \n", origHost, pushHost, len(rl.cc.tlsState.VerifiedChains), rl.cc.t.TLSClientConfig.InsecureSkipVerify)
			err := fmt.Errorf("server not authoritative for push with host %q", pushedReq.URL.Hostname())
			return http2StreamError{f.StreamID, http2ErrCodeProtocol, err}
		}
	}

	pushedReq.TLS = convertStatePtr(rl.cc.tlsState)
	pushedStream.req = pushedReq
	pr := &PushedRequest{
		Promise:               pushedReq,
		OriginalRequestURL:    stream.req.URL,
		OriginalRequestHeader: stream.req.Header.Clone(),
		pushedStream:          pushedStream,
	}
	go handlePushEarlyReturnCancel(rl.cc.t.PushHandler, pr)
	return nil
}

// authorityHostPort accepts a given authority (a host/IP, or host:port / ip:port)
// and returns a host and port.
func authorityHostPort(scheme string, authority string) (host, port string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	return
}

// authorityAddr accepts a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port := authorityHostPort(scheme, authority)
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

type DefaultPushHandler struct {
	promise               *Request
	originalRequestURL    *url.URL
	originalRequestHeader http.Header
	push                  *Response
	pushErr               error
	done                  chan struct{}
}

func (ph DefaultPushHandler) HandlePush(r *PushedRequest) {
	// panic("lol")
	ph.promise = r.Promise
	ph.originalRequestHeader = r.OriginalRequestHeader
	ph.originalRequestURL = r.OriginalRequestURL
	ph.push, ph.pushErr = r.ReadResponse(r.Promise.Context())
	if ph.pushErr != nil || ph.push != nil {
		discardResp(ph.push)
	}
}

func discardResp(resp *Response) {
	defer resp.Body.Close()
	io.Copy(ioutil.Discard, resp.Body)
}
