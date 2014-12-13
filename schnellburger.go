/*

This package allows you to add HMAC security to an existing http server.
This implementations builds on the existing "net/http" package.

The first step is create an instance of Schnellburger. Next, select
the cryptographic algorithm that is used to secure endpoints. This is done
by setting the `Algorithm` member of the Schnellburger structure to
a function like `md5.new`. Finally,
implement a KeyProvider. A KeyProvider allows the Schnellburger instance
to lookup keys by index. The HTTP client sends the key index as part of
the request. The value of the key used constitutes a preshared secret
between the server and the client. It is used to prove the authenticity
of the request by the client.

To prove the authenticity of a request, the client sends the signature for the request
and an optional key index. If the key index is not provided the key at index
zero is used. This value is placed in the Authorization header sent by the client.
The Authorization header is base64 encoded by the client. The server decodes
this and uses the resulting byte slice as follows

	|----X----|---------------Y-------------------|

	Where X is 0,1,2,4,6, or 8 bytes. These values correspond to the
	following types
	0 - No type. The key at index 0 is used.
	1 - uint8
	2 - uint16
	4 - uint32
	8 - uint64
	Integers are always considered to be in big endian byte order


	Where Y is the cryptographic signature, having exactly the same length
	as the number of bytes as the slice returned by Algorithm.Sum(nil)

The cryptographic signature is computed as follows using the HMAC
algorithm and the chosen cryptogrpaphic hash implementation.

	1. The request method ("GET","POST",etc.)
	2. The path of the request. There is no concept of an empty path, a
	request for the root resource has a path of "/".
	3. The raw request query with the leading question mark.
	4. The body of the request, if any.

The server responds with 403 if for any reason the value of the header does
not prove the authenticity of the request.

This example shows protecting http.FileServer with this package.

	package main

	import "net/http"

	import "github.com/hydrogen18/schnellburger"
	import "crypto/md5"

	//Simple implementation of key provider
	type DictKeyProvider map[uint64][]byte

	func (dkp DictKeyProvider) GetKey(index uint64) ([]byte, error) {
		k, ok := dkp[index]
		if !ok {
			return nil, nil
		}

		return k, nil
	}

	func main() {

		kp := DictKeyProvider{}

		//Configure keys
		kp[0] = []byte{0x1, 0x2, 0x3, 0x4}

		//Create an instance of schnellburger
		sb := schnellburger.Schnellburger{}

		//Use the MD5 hash
		sb.Algorithm = md5.New
		//Use the dictionary key provider
		sb.Kp = kp

		server := http.Server{}
		server.Addr = "0.0.0.0:8080"
		//Wrap the http.Handler to protect it
		//with HMAC
		server.Handler = sb.WrapHttpHandler(http.FileServer(http.Dir("/tmp")))

		//serve forever

		server.ListenAndServe()

	}


Using curl we can see the request is denied

	ericu@eric-phenom-linux:~$ curl -D - http://localhost:8080
	HTTP/1.1 403 Forbidden
	Content-Type: text/plain
	X-Schnellburger-Algo: *md5.digest
	X-Schnellburger-Doc: http://godoc.org/github.com/hydrogen18/schnellburger
	X-Schnellburger-Error-Code: 0
	Date: Sun, 22 Jun 2014 02:07:37 GMT
	Content-Length: 92

	Missing Header
	---
	You must supply the authorization header "Authorization" to this endpoint


After creating a file and repeating the same curl command, but this time
with the correct header

	ericu@eric-phenom-linux:/tmp$ echo 'Hello Crypto' > /tmp/x
	ericu@eric-phenom-linux:/tmp$ curl -D - -H "Authorization: ADVij+gEOkh2xRqsTAeGcyg=" http://192.168.12.10:8080/x
	HTTP/1.1 200 OK
	Accept-Ranges: bytes
	Content-Length: 13
	Content-Type: text/plain; charset=utf-8
	Last-Modified: Sun, 22 Jun 2014 02:14:01 GMT
	Date: Sun, 22 Jun 2014 02:14:04 GMT

	Hello Crypto

The request is allowed.

The preferred implementation is to use (*Schnellburger).WrapHttpHandler. However, this makes
an in-memory of the body sent by the client. For requests that cannot possibly
have a body, this is of no impact. For requests that have a body, this only
matters if the body is very large. If the body is very large (*Schnellburger).WrapHandler
should be called to add HMAC security. The handler must be of type schnellburger.Handler.
This type requires that the verify closure be called before taking any action on the
request but after reading the body entirely. Any implementation not honoring
this contract results in a call to "Printf" from the "log" package of the caller.
This process allows the handler to write the body of the request to an alternate
location rather than requiring it to be buffered in memory.

*/
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
import "errors"

/*
Returns (nil, nil) if no such key exists.
Returning an error results in that error being show to the
client and a status code of http.StatusInternalServerError
begin returned

*/
type KeyProvider interface {
	GetKey(index uint64) ([]byte, error)
}

/*
Wrapper to allow functions to be used as KeyProvider
*/
type KeyProviderFunc func(index uint64) ([]byte, error)

func (kpf KeyProviderFunc) GetKey(index uint64) ([]byte, error) {
	return kpf(index)
}

type Schnellburger struct {
	//Interface used to lookup keys from key indices. If the client
	//does not provide a key index, the 0'th key is looked up.
	Kp KeyProvider

	//Algorithm used to verify message authenticity
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

/*
A handler as used by this package. The third parameter must be called
before taking any action based off the request but
after req.Body is consumed completely. If false is returned
the implementation must return immediately without taking
any other action. If true is returned the request is authentic
and the handler should proceed as normal.

See:
WrapHandler
WrapHttpHandler
*/
type Handler interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request, verify func() bool)
}

type HandlerFunc func(rw http.ResponseWriter, req *http.Request, verify func() bool)

func (f HandlerFunc) ServeHTTP(rw http.ResponseWriter, req *http.Request, verify func() bool) {
	f(rw, req, verify)
}

/*
Protects a handler with HMAC verification. If the handler only responds
to requests with a body, this is the preferred way to use this package.
*/
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

/*
Protects a traditional http.Handler instance with HMAC verification. If the
handler only responds to requests without a body, this is the preferred
way to use this package.
*/
func (sb Schnellburger) WrapHttpHandler(handler http.Handler) http.Handler {
	return sb.WrapHandler(httpHandlerWrapper{handler})

}

const HMAC_HEADER = "Authorization"

var ErrMissingHeader = errors.New("Missing header")
var ErrHeaderTooShort = errors.New("Header is too short")

var ErrKeyIndexWrongLength = errors.New("Key index is the wrong length")

func (sb Schnellburger) FindHmacHeader(req *http.Request) (uint64, []byte, error) {
	header := req.Header.Get(HMAC_HEADER)
	//If the header is not present, fail
	if len(header) == 0 {
		return 0, nil, ErrMissingHeader
	}

	//If the header cannot be decoded, fail
	headerBinary, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return 0, nil, err
	}

	//If the header doesn't have enough bytes, fail
	if len(headerBinary) < sb.algorithmSize {
		return 0, nil, ErrHeaderTooShort
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
		return 0, nil, ErrKeyIndexWrongLength

	}

	if err != nil {
		return 0, nil, err
	}

	var provided []byte
	provided = make([]byte, sb.algorithmSize)

	//Read in the HMAC sent by the client
	n, err := reader.Read(provided)

	if err != nil {
		return 0, nil, err
	}

	//If the HMAC sent by the client is not
	//equal to HMAC generated by the algorithm
	//then it cannot be an authentic request
	if n != sb.algorithmSize {
		return 0, nil, ErrHeaderTooShort
	}

	return keyIndex, provided, nil

}

func (sb Schnellburger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	keyIndex, provided, err := sb.FindHmacHeader(req)
	switch err {
	case ErrHeaderTooShort:
		HeaderTooShort.Show(rw, req, sb, nil)
		return
	case ErrKeyIndexWrongLength:
		KeyIndexWrongLength.Show(rw, req, sb, nil)
		return
	case ErrMissingHeader:
		MissingHeader.Show(rw, req, sb, nil)
		return
	default:
		InvalidHeader.Show(rw, req, sb, err)
		return
	case nil:
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

	responseWriterWrapper := &checkIfVerifiedResponseWriter{}
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

type checkIfVerifiedResponseWriter struct {
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

func (rw *checkIfVerifiedResponseWriter) verify() bool {
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

func (rw *checkIfVerifiedResponseWriter) handleBadImpl() {
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

func (rw *checkIfVerifiedResponseWriter) Header() http.Header {
	if !rw.ok {
		rw.handleBadImpl()
		return http.Header{}
	}

	return rw.ResponseWriter.Header()
}

func (rw *checkIfVerifiedResponseWriter) WriteHeader(i int) {
	if !rw.ok {
		rw.handleBadImpl()
		return
	}
	rw.ResponseWriter.WriteHeader(i)
}

func (rw *checkIfVerifiedResponseWriter) Write(b []byte) (int, error) {
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
