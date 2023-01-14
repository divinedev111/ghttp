package ghttp

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	gotls "crypto/tls"

	tls "gitlab.com/yawning/utls.git"
	utls "gitlab.com/yawning/utls.git"
	"github.com/andybalholm/brotli"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
)

type RoundTripper = http.RoundTripper

type Request = http.Request
type Header = http.Header
type Response = http.Response
type CookieJar = http.CookieJar

var ccccccc http.Client

type TlsConn interface {
	net.Conn
	Handshake() error
	ConnectionState() utls.ConnectionState
}

type atomicBool int32

func (b *atomicBool) isSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *atomicBool) setTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *atomicBool) setFalse()   { atomic.StoreInt32((*int32)(b), 0) }

var (
	NoBody           = http.NoBody
	omitBundledHTTP2 = false

	// var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")
	ReadResponse   = http.ReadResponse
	headerOrderKey = "ghttp_header_order"
)

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	// "Host": true, // not in Header map anyway
	// "User-Agent":        false,
	// "Content-Length":    true,
	// "Transfer-Encoding": true,
	// "Trailer":           true,
	headerOrderKey:       true,
	pseudoHeaderOrderKey: true,
}

const maxPostHandlerReadBytes = 256 << 10

type incomparable [0]func()

func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

const maxInt64 = 1<<63 - 1
const StatusSwitchingProtocols = 101

func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

func isReplayable(r *Request) bool {
	if r.Body == nil || r.Body == NoBody || r.GetBody != nil {
		switch valueOrDefault(r.Method, "GET") {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return true
		}
		// The Idempotency-Key, while non-standard, is widely used to
		// mean a POST or other request is idempotent. See
		// https://golang.org/issue/19943#issuecomment-421092421
		_, ok1 := r.Header["Idempotency-Key"]
		_, ok2 := r.Header["X-Idempotency-Key"]
		if ok1 || ok2 {
			return true
		}
	}
	return false
}

func closeBody(r *Request) {
	if r.Body != nil {
		r.Body.Close()
	}
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
func outgoingLength(r *Request) int64 {
	if length := r.Header.Get("content-length"); length != "" {
		if ilen, err := strconv.Atoi(length); err == nil && ilen < 0 {
			// fmt.Println("lol")
			return -1
		}
	}

	if r.Body == nil || r.Body == NoBody {
		return 0
	}
	if r.ContentLength != 0 {
		return r.ContentLength
	}
	return -1
}

func badStringError(what, val string) error { return fmt.Errorf("%s %q", what, val) }

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func isNotToken(v rune) bool {
	return !httpguts.IsTokenRune(v)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func bodyIsWritable(r *Response) bool {
	_, ok := r.Body.(io.Writer)
	return ok
}

func isProtocolSwitch(r *Response) bool {
	return r.StatusCode == StatusSwitchingProtocols &&
		r.Header.Get("Upgrade") != "" &&
		httpguts.HeaderValuesContainsToken(r.Header["Connection"], "Upgrade")
}

func get_requestBodyReadError(v interface{}) (error, bool) {
	b := reflect.TypeOf(v).Name()
	if !strings.Contains(b, "requestBodyReadError") {
		return nil, false
	}
	val := reflect.ValueOf(v)
	xval := val.Field(0)
	r, ok := xval.Interface().(error)
	return r, ok
}

func expectsContinue(r *Request) bool {
	return httpguts.HeaderValuesContainsToken(r.Header["Expect"], "100-continue")
}

func wantsClose(r *Request) bool {
	if r.Close {
		return true
	}
	return httpguts.HeaderValuesContainsToken(r.Header["Connection"], "close")
}

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func convertState(s utls.ConnectionState) gotls.ConnectionState {
	return gotls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
	}
}

func convertStatePtr(s *utls.ConnectionState) *gotls.ConnectionState {
	if s == nil {
		return nil
	}
	state := convertState(*s)
	return &state
}

func ChromeClientFunc(conn net.Conn, cfg *utls.Config) TlsConn {
	c := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
	return c
}

func ClientFuncByID(id utls.ClientHelloID) func(net.Conn, *utls.Config) (TlsConn, error) {
	fn := func(conn net.Conn, cfg *utls.Config) (TlsConn, error) {
		c := utls.UClient(conn, cfg, id)
		return c, nil
	}
	return fn
}

func hostMissing(r *Request) bool {
	host := cleanHost(r.Host)
	if host == "" {
		if r.URL == nil {
			return true
		}
	}
	return false
}

// cleanHost cleans up the host sent in request's Host header.
//
// It both strips anything after '/' or ' ', and puts the value
// into Punycode form, if necessary.
//
// Ideally we'd clean the Host header according to the spec:
//   https://tools.ietf.org/html/rfc7230#section-5.4 (Host = uri-host [ ":" port ]")
//   https://tools.ietf.org/html/rfc7230#section-2.7 (uri-host -> rfc3986's host)
//   https://tools.ietf.org/html/rfc3986#section-3.2.2 (definition of host)
// But practically, what we are trying to avoid is the situation in
// issue 11206, where a malformed Host header used in the proxy context
// would create a bad request. So it is enough to just truncate at the
// first offending character.
func cleanHost(in string) string {
	if i := strings.IndexAny(in, " /"); i != -1 {
		in = in[:i]
	}
	host, port, err := net.SplitHostPort(in)
	if err != nil { // input was just a host
		a, err := idnaASCII(in)
		if err != nil {
			return in // garbage in, garbage out
		}
		return a
	}
	a, err := idnaASCII(host)
	if err != nil {
		return in // garbage in, garbage out
	}
	return net.JoinHostPort(a, port)
}

var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")

// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

func requestWrite(r *Request, w io.Writer, usingProxy bool, waitForContinue func() bool) (err error) {
	headers := make(myHeaders, 0)
	trace := httptrace.ContextClientTrace(r.Context())
	if trace != nil && trace.WroteRequest != nil {
		defer func() {
			trace.WroteRequest(httptrace.WroteRequestInfo{
				Err: err,
			})
		}()
	}
	// Find the target host. Prefer the Host: header, but if that
	// is not given, use the host from the request URL.
	//
	// Clean the host, in case it arrives with unexpected stuff in it.
	host := cleanHost(r.Host)
	if host == "" {
		if r.URL == nil {
			return errMissingHost
		}
		host = cleanHost(r.URL.Host)
	}

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	host = removeZone(host)

	ruri := r.URL.RequestURI()
	if usingProxy && r.URL.Scheme != "" && r.URL.Opaque == "" {
		ruri = r.URL.Scheme + "://" + host + ruri
	} else if r.Method == "CONNECT" && r.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
		if r.URL.Opaque != "" {
			ruri = r.URL.Opaque
		}
	}
	if stringContainsCTLByte(ruri) {
		return errors.New("net/http: can't write control character in Request.URL")
	}
	// TODO: validate r.Method too? At least it's less likely to
	// come from an attacker (more likely to be a constant in
	// code).

	// Wrap the writer in a bufio Writer if it's not already buffered.
	// Don't always call NewWriter, as that forces a bytes.Buffer
	// and other small bufio Writers to have a minimum 4k buffer
	// size.
	var bw *bufio.Writer
	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	_, err = fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", valueOrDefault(r.Method, "GET"), ruri)
	if err != nil {
		return err
	}

	// Header lines
	// _, err = fmt.Fprintf(w, "Host: %s\r\n", host)
	// if err != nil {
	// 	return err
	// }
	// if trace != nil && trace.WroteHeaderField != nil {
	// 	trace.WroteHeaderField("Host", []string{host})
	// }
	rhost := host
	if host := r.Header.Get("host"); host != "" {
		rhost = host
	}
	r.Header.Set("Host", rhost)

	// Use the defaultUserAgent unless the Header contains one, which
	// may be blank to not send the header.
	userAgent := defaultUserAgent

	if _, has := r.Header["User-Agent"]; has {
		userAgent = r.Header.Get("User-Agent")
	}

	r.Header.Set("User-Agent", userAgent)

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(r)
	if err != nil {
		return err
	}
	// TODO edit tw.writeHeader
	err = tw.writeHeader2()
	if err != nil {
		return err
	}
	for _, k := range getHeaderOrder(r.Header, reqWriteExcludeHeader) {
		headers.add(k, r.Header.Values(k))
		// fmt.Println(k, ",")
	}
	err = headers.writeSubset(w, reqWriteExcludeHeader, trace)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}

	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}

	// Flush and wait for 100-continue if expected.
	if waitForContinue != nil {
		if bw, ok := w.(*bufio.Writer); ok {
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
		if trace != nil && trace.Wait100Continue != nil {
			trace.Wait100Continue()
		}
		if !waitForContinue() {
			closeBody(r)
			return nil
		}
	}

	if bw, ok := w.(*bufio.Writer); ok && tw.FlushHeaders {
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	// Write body and trailer
	err = tw.writeBody(w)
	if err != nil {
		if tw.bodyReadError == err {
			err = requestBodyReadError{err}
		}
		return err
	}

	if bw != nil {
		return bw.Flush()
	}
	return nil
}

// requestBodyReadError wraps an error from (*Request).write to indicate
// that the error came from a Read call on the Request.Body.
// This error type should not escape the net/http package to users.
type requestBodyReadError struct{ error }

func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

func getHeaderOrder(headers http.Header, exclude map[string]bool) []string {
	retval := []string{}
	seen := map[string]bool{
		pseudoHeaderOrderKey:                     true,
		CanonicalHeaderKey(pseudoHeaderOrderKey): true,
		CanonicalHeaderKey(headerOrderKey):       true,
		headerOrderKey:                           true,
	}
	for k := range exclude {
		seen[CanonicalHeaderKey(k)] = true
	}
	for _, k := range headers.Values(headerOrderKey) {
		k2 := CanonicalHeaderKey(k)
		if _, exist := headers[k2]; exist && !seen[k2] {
			if httpguts.ValidHeaderFieldName(k) {
				retval = append(retval, k)
				seen[k2] = exist
			}
		}
	}
	for k := range headers {
		k2 := CanonicalHeaderKey(k)
		if !seen[k2] {
			retval = append(retval, string(k))
			seen[k2] = true
		}
	}
	// fmt.Println(retval)
	if _, exist := headers[headerOrderKey]; !exist {
		headers[headerOrderKey] = []string{}
	}

	for _, k := range pseudoHeaders {
		headers.Add(pseudoHeaderOrderKey, k)
	}

	return retval
}

func HeaderFromSlice(headers [][2]string) Header {
	h := make(Header)
	pHMap := map[string]bool{}
	for _, k := range pseudoHeaders {
		pHMap[k] = true
	}
	for _, item := range headers {
		k := item[0]
		v := item[1]
		if isPseudo := pHMap[k]; isPseudo {
			h.Add(pseudoHeaderOrderKey, k)
			continue
		}
		if _, present := h[CanonicalHeaderKey(k)]; !present {
			h.Add(headerOrderKey, k)
		}
		h.Add(k, v)
	}
	return h
}

func NewTransport(helloid tls.ClientHelloID, proxy string) (*Transport, error) {
	proxier, err := proxy_from_str(proxy)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		ClientFunc:         ClientFuncByID(helloid),
		Proxy:              proxier,
		DisableCompression: true,
	}
	t.CopySession(nil)
	return t, nil
}

func NewTransportFromSpec(hello_spec *tls.ClientHelloSpec, proxy string) (*Transport, error) {
	proxier, err := proxy_from_str(proxy)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		ClientFunc:         ClientFuncBySpec(hello_spec),
		Proxy:              proxier,
		DisableCompression: true,
	}
	t.CopySession(nil)
	return t, nil
}



func decompressResponse(resp *Response) {
	if resp == nil {
		return
	}

	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if encoding == "gzip" {
		resp.Body = &http2gzipReader{body: resp.Body}
		resp.Uncompressed = true
	} else if encoding == "br" {
		resp.Body = io.NopCloser(brotli.NewReader(resp.Body))
		resp.Uncompressed = true
	}

	if resp.Uncompressed {
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	}
}

func proxy_from_str(proxy string) (func(*http.Request) (*url.URL, error), error) {
	var proxier func(*http.Request) (*url.URL, error) = nil
	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		proxier = http.ProxyURL(proxyUrl)
	}
	return proxier, nil
}

func newTransportFromJA3(ja3 string, proxy string) (*Transport, error) {
	proxier, err := proxy_from_str(proxy)
	if err != nil {
		return nil, err
	}
	client_func, err := ClientFuncFromJA3(ja3)

	// proxier = nil
	// client_func, err = ProxiedFuncFromJA3(ja3, proxy)
	if err != nil {
		return nil, err
	}
	return &Transport{
		ClientFunc:         client_func,
		Proxy:              proxier,
		DisableCompression: true,
	}, nil
}

func NewClientFromTransport(rt RoundTripper) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		jar = nil
	}
	return &http.Client{
		Transport: rt,
		Jar:       jar,
	}
}

func NewClientFromJA3(ja3 string, proxy string) (*http.Client, error) {
	t, err := newTransportFromJA3(ja3, proxy)
	if err != nil {
		return nil, err
	}
	return NewClientFromTransport(t), nil

}

func NewClient(helloid tls.ClientHelloID, proxy string) (*http.Client, error) {
	t, err := NewTransport(helloid, proxy)
	if err != nil {
		return nil, err
	}
	return NewClientFromTransport(t), nil
}

func (t *Transport) CopySession(old *Transport) {
	set_cache := func(cache utls.ClientSessionCache) {
		if cache == nil {
			cache = utls.NewLRUClientSessionCache(64)
		}
		if conf := t.TLSClientConfig; conf != nil {
			conf.ClientSessionCache = cache
		} else {
			t.TLSClientConfig = &utls.Config{
				ClientSessionCache: cache,
			}
		}
		t.ForceAttemptHTTP2 = true
	}
	if old == nil {
		set_cache(nil)
		return
	}
	if oldconf := old.TLSClientConfig; oldconf != nil {
		if cache := oldconf.ClientSessionCache; cache != nil {
			set_cache(cache)
			return
		}
	}
	set_cache(nil)
	return
}
