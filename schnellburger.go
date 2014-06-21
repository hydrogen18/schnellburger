package schnellburger

import "net/http"
import "crypto/hmac"
import "hash"
import "encoding/base64"
import "encoding/binary"
import "bytes"
import "io"
import "log"
import "io/ioutil"
import "runtime"

/* Returns nil, nil if no such key exists. */
type KeyProvider interface {
	GetKey(index uint64) ([]byte, error)
}

type KeyProviderFunc func(index uint64) ([]byte, error)

func (kpf KeyProviderFunc) GetKey(index uint64) ([]byte, error) {
	return kpf(index)
}

type Schnellburger struct {
	Kp        KeyProvider
	Algorithm func() hash.Hash

	impl Handler
	//awareImpl     Handler
	algorithmSize int
}

func (sb Schnellburger) saneOrPanic() {
	if sb.Kp == nil {
		panic("KeyProvider can't be nil")
	}

	if sb.Algorithm == nil {
		panic("Algorithm can't be nil")
	}
}

type Handler interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request, verify func() bool)
}

type HandlerFunc func(rw http.ResponseWriter, req *http.Request, verify func() bool)

func (f HandlerFunc) ServeHTTP(rw http.ResponseWriter, req *http.Request, verify func() bool) {
	f(rw, req, verify)
}

func (sb Schnellburger) WrapHandler(handler Handler) http.Handler {
	sb.saneOrPanic()
	sb.algorithmSize = sb.Algorithm().Size()
	sb.impl = handler
	return sb
}

type httpHandlerWrapper struct {
	http.Handler
}

func (hhw httpHandlerWrapper) ServeHTTP(rw http.ResponseWriter, req *http.Request, verify func() bool) {

	if methodHasBody(req.Method) {

		buf := &bytes.Buffer{}

		//There are 2 cases here
		//
		// req.ContentLength == -1
		// The body length is unknown
		//
		// req.ContentLength >= 0
		// The body length is known
		//

		//If the content length is known, grow the buffer
		//ahead of time
		if req.ContentLength != -1 {
			buf.Grow(int(req.ContentLength))
		}

		_, err := io.Copy(buf, req.Body)

		//This should only when the connection drops or the
		//client hangs up, so the actual value returned
		//here is almost never seen by the client
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		//Replace the request body again
		req.Body = ioutil.NopCloser(buf)
	}

	if !verify() {
		return
	}

	hhw.Handler.ServeHTTP(rw, req)
}

func (sb Schnellburger) WrapHttpHandler(handler http.Handler) http.Handler {
	return sb.WrapHandler(httpHandlerWrapper{handler})

}

const HMAC_HEADER = "Authorization"

func (sb Schnellburger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	header := req.Header.Get(HMAC_HEADER)
	//If the header is not present, fail
	if len(header) == 0 {
		MissingHeader.Show(rw, req, sb, nil)
		return
	}

	//If the header cannot be decoded, fail
	headerBinary, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		InvalidHeader.Show(rw, req, sb, err)
		return
	}

	//If the header doesn't have enough bytes, fail
	if len(headerBinary) < sb.algorithmSize {
		HeaderTooShort.Show(rw, req, sb, nil)
		return
	}

	var keyIndex uint64
	reader := bytes.NewReader(headerBinary)

	//The header contains either
	// no index - use a value of 0
	// 2 byte unsigned integer
	// 4 byte unsigned integer
	// 8 byte unsigned integer
	//
	//If one of these conditions is not satisfied,
	//fail
	keyBytesLength := len(headerBinary) - sb.algorithmSize
	switch keyBytesLength {
	case 0:
		keyIndex = 0
	case 1:
		var i uint8
		err = binary.Read(reader, binary.BigEndian, &i)
		keyIndex = uint64(i)
	case 2:
		var i uint16
		err = binary.Read(reader, binary.BigEndian, &i)
		keyIndex = uint64(i)
	case 4:
		var i uint32
		err = binary.Read(reader, binary.BigEndian, &i)
		keyIndex = uint64(i)
	case 8:
		err = binary.Read(reader, binary.BigEndian, &keyIndex)
	default:
		KeyIndexWrongLength.Show(rw, req, sb, nil)
		return
	}

	if err != nil {
		InvalidHeader.Show(rw, req, sb, err)
		return
	}

	var provided []byte
	provided = make([]byte, sb.algorithmSize)

	//Read in the HMAC sent by the client
	n, err := reader.Read(provided)

	if err != nil {
		SignatureWrongSize.Show(rw, req, sb, err)
		return
	}

	//If the HMAC sent by the client is not
	//equal to HMAC generated by the algorithm
	//then it cannot be an authentic request
	if n != sb.algorithmSize {
		HeaderTooShort.Show(rw, req, sb, nil)
		return
	}

	//Lookup the key
	key, err := sb.Kp.GetKey(keyIndex)
	//If there was an error finding the key,
	//indicate as such
	if err != nil {
		KeyLookupFailure.Show(rw, req, sb, err)
		return
	}
	keyFound := (key != nil)

	//If the key is not found, don't stop here.
	//This might seem odd, but if a return
	//is made early here, an attacker
	//can use timing side channels to identify
	//what indices are valid keys
	if !keyFound {
		//supply the zero key to the hmac
		//algorithm
		key = make([]byte, 0)
	}

	expected := hmac.New(sb.Algorithm, key)

	//These writes cannot fail
	io.WriteString(expected, req.Method)
	if len(req.URL.Path) != 0 {
		io.WriteString(expected, req.URL.Path)
	} else {
		io.WriteString(expected, "/")
	}
	if len(req.URL.RawQuery) != 0 {
		io.WriteString(expected, "?")
		io.WriteString(expected, req.URL.RawQuery)
	}

	//Make a copy of the original body
	originalBody := req.Body

	//Restore the original body on function exit
	defer func() {
		req.Body = originalBody
	}()

	if methodHasBody(req.Method) {
		//Replace the body with a tee reader that copies into
		//'expected'
		tr := io.TeeReader(req.Body, expected)
		req.Body = ioutil.NopCloser(tr)

	}

	responseWriterWrapper := &CheckIfVerifiedResponseWriter{}
	responseWriterWrapper.ResponseWriter = rw
	responseWriterWrapper.keyFound = keyFound
	responseWriterWrapper.sb = sb
	responseWriterWrapper.req = req
	responseWriterWrapper.provided = provided
	responseWriterWrapper.expected = expected

	//call the aware implementation
	sb.impl.ServeHTTP(responseWriterWrapper, req, responseWriterWrapper.verify)

	//If the implementation didn't call anything on
	//responseWriterWrapper, a bad implementation could go unnoticed
	//check for that here
	if !responseWriterWrapper.verifyCalled {
		responseWriterWrapper.handleBadImpl()
	}

}

type CheckIfVerifiedResponseWriter struct {
	ok           bool
	badImpl      bool
	verifyCalled bool
	expected     hash.Hash
	provided     []byte
	sb           Schnellburger
	req          *http.Request
	keyFound     bool
	http.ResponseWriter
}

func (rw *CheckIfVerifiedResponseWriter) verify() bool {
	rw.verifyCalled = true

	//Note:
	//Due to timing side channel attacks,
	//even if the key is not found, the
	//call to hmac.Equal must be made.
	//
	// The 'if !keyFound' statement is seperated
	//from the 'if hmac.Equal' statement in the
	//hopes that the compiler will not
	//attempt to optimize away the call hmac.Equal

	expect := rw.expected.Sum(nil)
	if !hmac.Equal(expect, rw.provided) {
		NotAuthentic.Show(rw.ResponseWriter, rw.req, rw.sb, nil)
		rw.ok = false
		return rw.ok
	}

	//Check if a key was actually found
	if !rw.keyFound {
		NotAuthentic.Show(rw.ResponseWriter, rw.req, rw.sb, nil)
		rw.ok = false
		return rw.ok
	}

	rw.ok = true
	return rw.ok
}

func (rw *CheckIfVerifiedResponseWriter) handleBadImpl() {
	if !rw.badImpl {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			log.Printf("schnellburger.Handler implementation not calling verify %v:%d", file, line)
		}

		//Let the client know something is broken
		rw.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		rw.badImpl = true
	}
}

func (rw *CheckIfVerifiedResponseWriter) Header() http.Header {
	if !rw.ok {
		rw.handleBadImpl()
		return http.Header{}
	}

	return rw.ResponseWriter.Header()
}

func (rw *CheckIfVerifiedResponseWriter) WriteHeader(i int) {
	if !rw.ok {
		rw.handleBadImpl()
		return
	}
	rw.ResponseWriter.WriteHeader(i)
}

func (rw *CheckIfVerifiedResponseWriter) Write(b []byte) (int, error) {
	if !rw.ok {
		rw.handleBadImpl()
		return 0, io.EOF
	}
	return rw.ResponseWriter.Write(b)
}

func methodHasBody(method string) bool {
	var hasBody bool
	switch method {
	//These methods should never have a body
	case "GET":
	case "DELETE":
	case "HEAD":
	default:
		hasBody = true
	}

	return hasBody
}
