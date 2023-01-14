package ghttp

import (
	"net/http"
)

var (
	CanonicalHeaderKey    = http.CanonicalHeaderKey
	DefaultServeMux       = http.DefaultServeMux
	LocalAddrContextKey   = http.LocalAddrContextKey
	ServerContextKey      = http.ServerContextKey
	DefaultMaxHeaderBytes = http.DefaultMaxHeaderBytes
	ErrAbortHandler       = http.ErrAbortHandler
	ErrBodyNotAllowed     = http.ErrBodyNotAllowed
	ErrNotSupported       = http.ErrNotSupported
	DetectContentType     = http.DetectContentType
	TimeFormat            = http.TimeFormat
	Error                 = http.Error
	StatusBadRequest      = http.StatusBadRequest
	MethodGet             = http.MethodGet
	StatusText            = http.StatusText
)

type H2Settings map[string]uint32

func (s H2Settings) get(k http2SettingID, def uint32) uint32 {
	if s == nil {
		return def
	}
	key := k.String()
	value, ok := s[key]
	if ok {
		return value
	}
	return def
}

var nameToIDMap = map[string]http2SettingID{
	"HEADER_TABLE_SIZE":      http2SettingHeaderTableSize,
	"ENABLE_PUSH":            http2SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http2SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http2SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http2SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http2SettingMaxHeaderListSize,
}

func (s H2Settings) allBut(ids ...http2SettingID) (settings []http2Setting) {
	if s == nil {
		return []http2Setting{}
	}
	seen := map[string]bool{}
	for _, v := range ids {
		seen[v.String()] = true
	}
	for k, v := range s {
		if !seen[k] {
			settings = append(settings, http2Setting{
				ID:  nameToIDMap[k],
				Val: v,
			})
		}
	}
	return settings
}

type Server = http.Server
type Handler = http.Handler
type ConnState = http.ConnState
type ResponseWriter = http.ResponseWriter
type CloseNotifier = http.CloseNotifier
type Flusher = http.Flusher
type Pusher = http.Pusher
type PushOptions = http.PushOptions
type HandlerFunc = http.HandlerFunc
type H2StreamError = http2StreamError
type H2ConnError = http2connError

const (
	// StateNew represents a new connection that is expected to
	// send a request immediately. Connections begin at this
	// state and then transition to either StateActive or
	// StateClosed.
	StateNew ConnState = iota

	// StateActive represents a connection that has read 1 or more
	// bytes of a request. The Server.ConnState hook for
	// StateActive fires before the request has entered a handler
	// and doesn't fire again until the request has been
	// handled. After the request is handled, the state
	// transitions to StateClosed, StateHijacked, or StateIdle.
	// For HTTP/2, StateActive fires on the transition from zero
	// to one active request, and only transitions away once all
	// active requests are complete. That means that ConnState
	// cannot be used to do per-request work; ConnState only notes
	// the overall state of the connection.
	StateActive

	// StateIdle represents a connection that has finished
	// handling a request and is in the keep-alive state, waiting
	// for a new request. Connections transition from StateIdle
	// to either StateActive or StateClosed.
	StateIdle

	// StateHijacked represents a hijacked connection.
	// This is a terminal state. It does not transition to StateClosed.
	StateHijacked

	// StateClosed represents a closed connection.
	// This is a terminal state. Hijacked connections do not
	// transition to StateClosed.
	StateClosed
)

var pseudoHeaders = [4]string{
	":authority",
	":method",
	":scheme",
	":path",
}

const pseudoHeaderOrderKey = "ghttp_pseudo_header_order"

// func (t *Transport) SetH2TransportSettings(settings H2Settings) {
// 	t.HTTP2Settings = settings
// }

func (t *http2Transport) get_setting(id http2SettingID, def uint32) uint32 {
	return t.t1.HTTP2Settings.get(id, def)
}
