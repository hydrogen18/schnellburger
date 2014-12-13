package schnellburger

import (
	"testing"

	. "gopkg.in/check.v1"
)
import "net/http/httptest"
import "net/http"
import "io"
import "strconv"
import "crypto/md5"
import "errors"
import "net/url"
import "encoding/base64"
import "encoding/binary"
import "bytes"
import "log"
import "os"
import "io/ioutil"

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type TestSuite struct {
	server      *httptest.Server
	awareServer *httptest.Server
}

var _ = Suite(&TestSuite{})

func (s *TestSuite) client() *http.Client {
	retval := &http.Client{}

	return retval
}

var testalgo = md5.New

func assertMatchesError(resp *http.Response, h *help, c *C) {
	c.Assert(resp.StatusCode, Equals, h.StatusCode)

	errCode, err := strconv.Atoi(resp.Header.Get(ERROR_CODE_HEADER))
	c.Assert(err, IsNil)
	c.Assert(errCode, Equals, h.ErrorCode)
}

func assertOk(response *http.Response, c *C) {
	if response.StatusCode != http.StatusOK {
		for h, v := range response.Header {
			log.Printf("%s: %s", h, v[0])
		}
		io.Copy(os.Stderr, response.Body)
	}

	c.Assert(response.StatusCode, Equals, http.StatusOK)
}

func (s *TestSuite) TestPostAgainst(c *C) {
	t := func(server *httptest.Server) {
		body := make([]byte, 77)
		for i := range body {
			body[i] = byte(i)
		}

		var err error
		client := s.client()

		req := &http.Request{}
		req.Method = "POST"
		const PATH = "/meow/kitty"
		req.URL, err = url.Parse(server.URL + PATH)
		c.Assert(err, IsNil)
		req.Header = http.Header{}

		//Just a signature, 0 key index implied
		SIG := []byte{0xca, 0x88, 0xba, 0x90, 0x2, 0xf0, 0x71, 0x2, 0x7d, 0x30, 0x40, 0x7e, 0xcc, 0x4d, 0x84, 0x6}
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(SIG))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		response, err := client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		//Test the returned body for being identical, to make sure
		//that the Schnellburger didn't molest it
		buf := &bytes.Buffer{}
		_, err = io.Copy(buf, response.Body)
		c.Assert(err, IsNil)
		err = response.Body.Close()
		c.Assert(err, IsNil)
		c.Assert(len(body), Equals, buf.Len())
		c.Assert(bytes.Equal(body, buf.Bytes()), Equals, true)

		//change the path, it should fail
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.URL, err = url.Parse(s.server.URL + PATH + "/fuuuu")
		c.Assert(err, IsNil)
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, NotAuthentic, c)

		//restore the path
		req.URL, err = url.Parse(s.server.URL + PATH)
		c.Assert(err, IsNil)

		//change the body, it should fail
		body[0] += 1
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))

		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, NotAuthentic, c)
	}
	t(s.server)
	t(s.awareServer)

}

func (s *TestSuite) TestGetWithPathRequest(c *C) {
	var err error
	client := s.client()

	req := &http.Request{}
	req.Method = "GET"
	const PATH = "/a/path"
	req.URL, err = url.Parse(s.server.URL + PATH)
	c.Assert(err, IsNil)
	req.Header = http.Header{}

	//Just a signature, 0 key index implied
	SIG := []byte{0x82, 0xf7, 0xc8, 0x9, 0x35, 0x95, 0xcd, 0xc5, 0x6a, 0x65, 0x31, 0x8f, 0x83, 0x33, 0xb7, 0x93}
	req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(SIG))
	response, err := client.Do(req)
	c.Assert(err, IsNil)
	assertOk(response, c)

	//change the path, it should fail
	req.URL, err = url.Parse(s.server.URL + PATH + "/foobar")
	c.Assert(err, IsNil)
	response, err = client.Do(req)
	c.Assert(err, IsNil)
	assertMatchesError(response, NotAuthentic, c)

	//restore the path
	req.URL, err = url.Parse(s.server.URL + PATH)
	c.Assert(err, IsNil)

	//Add a query, it should fail now
	req.URL.RawQuery = "foobar"
	response, err = client.Do(req)
	c.Assert(err, IsNil)
	assertMatchesError(response, NotAuthentic, c)
}

func (s *TestSuite) TestGetWithPathAndQueryRequest(c *C) {
	var err error
	client := s.client()

	req := &http.Request{}
	req.Method = "GET"
	req.URL, err = url.Parse(s.server.URL + "/a/path")
	req.URL.RawQuery = "foo=bar"
	c.Assert(err, IsNil)
	req.Header = http.Header{}

	//Just a signature, 0 key index implied
	SIG := []byte{0x6f, 0xd7, 0x52, 0x7d, 0x32, 0x31, 0x42, 0x5e, 0xc3, 0xbe, 0xee, 0x83, 0x57, 0x10, 0x16, 0xe}
	req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(SIG))
	response, err := client.Do(req)
	c.Assert(err, IsNil)
	assertOk(response, c)

	{
		client := s.client()
		sbrt := SchnellburgerRoundTripper{}
		sbrt.Key = []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
		sbrt.Next = client.Transport
		sbrt.Algorithm = testalgo
		client.Transport = sbrt

		response, err = client.Get(req.URL.String())
		c.Assert(err, IsNil)
		assertOk(response, c)

	}

	//Remove query, it should fail now
	req.URL.RawQuery = ""

	response, err = client.Do(req)
	c.Assert(err, IsNil)
	assertMatchesError(response, NotAuthentic, c)

}

func (s *TestSuite) TestGetRequest(c *C) {
	t := func(server *httptest.Server) {
		client := s.client()
		response, err := client.Get(server.URL)
		c.Assert(err, IsNil)
		assertMatchesError(response, MissingHeader, c)

		req := &http.Request{}
		req.Method = "GET"
		req.URL, err = url.Parse(s.server.URL)
		c.Assert(err, IsNil)
		req.Header = http.Header{}

		req.Header.Set(HMAC_HEADER, "@")
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, InvalidHeader, c)

		req.Header.Set(HMAC_HEADER, "AAAA")
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, HeaderTooShort, c)

		//Just a signature, 0 key index implied
		v := testalgo().Sum(nil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(v))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, NotAuthentic, c)

		//Just a signature, 0 key index implied
		SIG := []byte{0x52, 0x63, 0x9f, 0x51, 0x35, 0x17, 0x57, 0x8a, 0xdb, 0xc2, 0x41, 0x5, 0x4e, 0x87, 0xfa, 0x77}
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(SIG))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		buf := &bytes.Buffer{}

		//Explicitly specify the 0 key
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint8(0))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		//Explicitly specify the 0 key
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint16(0))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		//Explicitly specify the 0 key
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint32(0))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		//Explicitly specify the 0 key
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint64(0))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertOk(response, c)

		//Send a 3-byte key, not allowed
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint16(0))
		c.Assert(err, IsNil)
		_, err = buf.Write([]byte{0x0})
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, KeyIndexWrongLength, c)

		//Send a missing key with valid signature,
		//should fail without any explicit notice
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint64(MISSING_KEY_INDEX))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, NotAuthentic, c)

		//Send a key that causes lookup failure, but a valid signature
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint64(ERROR_KEY_INDEX))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, KeyLookupFailure, c)

		//Send an extra byte to trigger the wrong size signature
		//This actually is caught by KeyIndexWrongLength
		buf.Reset()
		err = binary.Write(buf, binary.BigEndian, uint64(0))
		c.Assert(err, IsNil)
		_, err = buf.Write(SIG)
		c.Assert(err, IsNil)
		_, err = buf.Write([]byte{0x0})
		c.Assert(err, IsNil)
		req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(buf.Bytes()))
		response, err = client.Do(req)
		c.Assert(err, IsNil)
		assertMatchesError(response, KeyIndexWrongLength, c)
	}
	t(s.server)
	t(s.awareServer)
}

func (s *TestSuite) TestPanicOnNoVerify(c *C) {
	sb := Schnellburger{}
	sb.Algorithm = testalgo
	sb.Kp = KeyProviderFunc(testKeyProvider)

	h := sb.WrapHandler(HandlerFunc(DoesntVerifyHandler))

	server := httptest.NewServer(h)
	defer server.Close()

	req := &http.Request{}
	req.Method = "GET"
	var err error
	req.URL, err = url.Parse(server.URL)
	c.Assert(err, IsNil)
	req.Header = http.Header{}

	//Just a signature, 0 key index implied
	SIG := []byte{0x52, 0x63, 0x9f, 0x51, 0x35, 0x17, 0x57, 0x8a, 0xdb, 0xc2, 0x41, 0x5, 0x4e, 0x87, 0xfa, 0x77}
	req.Header.Set(HMAC_HEADER, base64.StdEncoding.EncodeToString(SIG))
	client := s.client()
	response, err := client.Do(req)
	c.Assert(err, IsNil)
	c.Assert(response.StatusCode, Equals, http.StatusInternalServerError)

}

func EchoHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, err := io.Copy(rw, req.Body)
	if err != nil {
		panic(err)
	}
}

func AwareEchoHandler(rw http.ResponseWriter, req *http.Request, verify func() bool) {

	buf := &bytes.Buffer{}
	_, err := io.Copy(buf, req.Body)
	if err != nil {
		panic(err)
	}

	if !verify() {
		return
	}

	rw.WriteHeader(http.StatusOK)
	_, err = io.Copy(rw, buf)
	if err != nil {
		panic(err)
	}
}

//this is an example of how not to write a verifying handler
func DoesntVerifyHandler(rw http.ResponseWriter, req *http.Request, verify func() bool) {
	rw.WriteHeader(http.StatusOK)
}

const MISSING_KEY_INDEX = 42
const ERROR_KEY_INDEX = 43

//Never use this outside of these unit tests
func testKeyProvider(keyIndex uint64) ([]byte, error) {
	if keyIndex == MISSING_KEY_INDEX {
		return nil, nil
	}

	if keyIndex == ERROR_KEY_INDEX {
		return nil, errors.New("Kaboom")
	}

	key := []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	return key, nil
}

func (s *TestSuite) SetUpSuite(c *C) {
	sb := Schnellburger{}
	sb.Algorithm = testalgo
	sb.Kp = KeyProviderFunc(testKeyProvider)

	h := sb.WrapHttpHandler(http.HandlerFunc(EchoHandler))
	s.server = httptest.NewServer(h)

	h = sb.WrapHandler(HandlerFunc(AwareEchoHandler))
	s.awareServer = httptest.NewServer(h)

}

func (s *TestSuite) TearDownSuite(c *C) {
	s.server.Close()
	s.awareServer.Close()
}
