package ghttp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/divinedev111/ghttp/internal"
	"net"
	"net/url"
	"strconv"
	"strings"

	tls "gitlab.com/yawning/utls.git"
)

// greasePlaceholder is a random value (well, kindof '0x?a?a) specified in a
// random RFC.
const greasePlaceholder = 0x0a0a

// ErrExtensionNotExist is returned when an extension is not supported by the library
type ErrExtensionNotExist string

// Error is the error value which contains the extension that does not exist
func (e ErrExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension does not exist: %s\n", string(e))
}

var alpns = map[string]string{
	"1": "http/1.1",
	"2": "h2",
}

func BoringPaddingStyle(unpaddedLen int) (x int, y bool) {
	// defer fmt.Println(x, y, unpaddedLen)
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 1, true
}

// extMap maps extension values to the TLSExtension object associated with the
// number. Some values are not put in here because they must be applied in a
// special way. For example, "10" is the SupportedCurves extension which is also
// used to calculate the JA3 signature. These JA3-dependent values are applied
// after the instantiation of the map.
var extensions = map[string]tls.TLSExtension{
	"0": &tls.SNIExtension{},
	"5": &tls.StatusRequestExtension{},
	// These are applied later
	// "10": &tls.SupportedCurvesExtension{...}
	// "11": &tls.SupportedPointsExtension{...}
	"13": &tls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
		},
	},
	"16": &tls.ALPNExtension{
		AlpnProtocols: []string{"h2", "http/1.1"},
	},
	"17": nil, //&tls.StatusRequestExtension{},
	"18": &tls.SCTExtension{},
	"21": &tls.UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle, WillPad: true},
	"23": &tls.UtlsExtendedMasterSecretExtension{},
	"27": &tls.CompressCertificateExtension{
		Algorithms: []tls.CertCompressionAlgo{
			tls.CertCompressionBrotli,
			// tls.CertCompressionZlib,
		},
	},

	// "27": &tls.FakeCertCompressionAlgsExtension{
	// 	[]tls.CertCompressionAlgo{
	// 		tls.CertCompressionBrotli,
	// 		tls.CertCompressionZlib,
	// 	},
	// },

	"28": &tls.FakeRecordSizeLimitExtension{},
	"43": &tls.SupportedVersionsExtension{Versions: []uint16{
		// tls.GREASE_PLACEHOLDER,
		// tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10},
	},
	"35": &tls.SessionTicketExtension{},
	"44": &tls.CookieExtension{},
	"45": &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
		tls.PskModeDHE,
	}},
	"50": nil, //&tls.SignatureAlgorithmsCertExtension{
	// 	SupportedSignatureAlgorithmsCert: []tls.SignatureScheme{
	// 		tls.ECDSAWithP256AndSHA256,
	// 		tls.PSSWithSHA256,
	// 		tls.PKCS1WithSHA256,
	// 		tls.ECDSAWithP384AndSHA384,
	// 		tls.PSSWithSHA384,
	// 		tls.PKCS1WithSHA384,
	// 		tls.PSSWithSHA512,
	// 		tls.PKCS1WithSHA512,
	// 		tls.PKCS1WithSHA1,
	// 	},
	// },
	"51": &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
		// {Group: tls.X25519},
	}},
	"13172": &tls.NPNExtension{},
	"65281": &tls.RenegotiationInfoExtension{
		Renegotiation: tls.RenegotiateOnceAsClient,
	},
}

func ClientFuncFromJA3(ja3 string) (func(net.Conn, *tls.Config) (TlsConn, error), error) {
	spec, err := JA3StringToSpec(ja3)
	if err != nil {
		return nil, err
	}
	return ClientFuncBySpec(spec), nil
}

var emptySessionID = [32]byte{}

func GetEmptySessionID(_ []byte) [32]byte {
	return emptySessionID
}

func ClientFuncBySpec(spec *tls.ClientHelloSpec) func(net.Conn, *tls.Config) (TlsConn, error) {
	fn := func(conn net.Conn, cfg *tls.Config) (TlsConn, error) {

		c := tls.UClient(conn, cfg, tls.HelloCustom)
		if err := c.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if cfg != nil && cfg.ServerName != "" {
			c.SetSNI(cfg.ServerName)
		}
		if spec.GetSessionID([]byte{}) == emptySessionID {
			c.BuildHandshakeState()
			c.HandshakeState.Hello.SessionId = []byte{}
		}
		return c, nil
	}
	return fn
}

func ProxiedFuncFromJA3(ja3 string, proxy string) (func(net.Conn, *tls.Config) (TlsConn, error), error) {
	spec, err := JA3StringToSpec(ja3)
	if err != nil {
		return nil, err
	}

	var d internal.Dialer = internal.ProxyDirect
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		d, err = internal.ProxyFromURL(proxyURL, d)
		if err != nil {
			return nil, err
		}
	}
	fn := func(conn net.Conn, cfg *tls.Config) (TlsConn, error) {
		conn, err = d.Dial(conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		c := tls.UClient(conn, cfg, tls.HelloCustom)
		if err := c.ApplyPreset(spec); err != nil {
			return nil, err
		}
		return c, nil
	}
	return fn, nil
}

// stringToSpec creates a ClientHelloSpec based on a JA3 string
func JA3StringToSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	versionsSent := false
	tokens := strings.Split(ja3, ",")
	if len(tokens) < 5 {
		return nil, fmt.Errorf("invalid ja3-string: \"%s\"", ja3)
	}

	extMap := map[string]tls.TLSExtension{}
	for k, v := range extensions {
		extMap[k] = v
	}

	// adding ,1 to ja3 variable will force alpn to only send http/1.1
	if len(tokens) >= 6 && tokens[5] != "" {
		_protocols := strings.Split(tokens[5], "-")
		protocols := []string{}
		for _, k := range _protocols {
			if v, present := alpns[k]; present {
				protocols = append(protocols, v)
			}
		}
		extMap["16"] = &tls.ALPNExtension{
			AlpnProtocols: protocols,
		}
		// fmt.Println(protocols)
	}

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	// parse curves
	var targetCurves []tls.CurveID
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}

	// build SSLVersion
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	vid := uint16(vid64)

	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}
	// extMap["43"] =

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// build extenions list
	var exts []tls.TLSExtension
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, ErrExtensionNotExist(e)
		} else if te == nil {
			continue
		}
		if e == "43" {
			versionsSent = true
		}
		exts = append(exts, te)
	}

	// build CipherSuites
	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}

	spec := &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS10,
		TLSVersMax:         vid,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}
	if versionsSent {
		// fmt.Println("sent")
		spec.TLSVersMax = 0x0
		spec.TLSVersMin = 0x0
	}
	return spec, nil
}

func SpecFromHelloBytes(raw_hex string, fingerprinter *Fingerprinter) (*tls.ClientHelloSpec, error) {
	if fingerprinter == nil {
		fingerprinter = &Fingerprinter{
			KeepPSK: true,
		}
	}
	byteString := []byte(raw_hex)
	helloBytes := make([]byte, hex.DecodedLen(len(byteString)))
	_, err := hex.Decode(helloBytes, byteString)
	if err != nil {
		return nil, fmt.Errorf("got error: %v; expected to succeed", err)
	}
	return fingerprinter.FingerprintClientHello(helloBytes)
}
