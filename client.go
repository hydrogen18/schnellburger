package schnellburger

import "net/http"
import "hash"
import "io"

import "strings"
import "crypto/hmac"
import "bytes"
import "encoding/binary"
import "encoding/base64"

type SchnellburgerRoundTripper struct {
	Next      http.RoundTripper
	Key       []byte
	KeyId     uint64
	Algorithm func() hash.Hash
}

func (this SchnellburgerRoundTripper) RoundTrip(originalRequest *http.Request) (*http.Response, error) {

	//This cannot be manipulated according to the spiec but can be copied
	var req *http.Request
	req = &http.Request{}
	*req = *originalRequest

	//This member is shallow copied by the above code.
	//Perform a full duplication to avoid mutation of the
	//original request
	req.Header = http.Header{}
	for k, v := range originalRequest.Header {
		dup := make([]string, len(v))
		for i, entry := range v {
			dup[i] = entry
		}
		req.Header[k] = dup
	}

	const SIGNATURE_HEADER = "Authorization"
	//Sign the request if a key is configured
	if this.Key != nil {
		//Create a checksum
		h := hmac.New(this.Algorithm, this.Key)

		//Sign the method
		method := strings.ToUpper(req.Method)
		_, err := io.WriteString(h, method)
		if err != nil {
			return nil, err
		}

		//Sign the path
		path := req.URL.Path

		if len(path) == 0 {
			path = "/"
		}
		_, err = io.WriteString(h, path)
		if err != nil {
			return nil, err
		}

		//If the request has a query, sign that
		if len(req.URL.RawQuery) != 0 {
			_, err = io.WriteString(h, "?")
			if err != nil {
				return nil, err
			}
			_, err = io.WriteString(h, req.URL.RawQuery)
			if err != nil {
				return nil, err
			}
		}
		//If the request has a body, sign it
		if req.Body != nil {
			//Make a copy of the body
			var replacement echoer
			replacement.Buffer = &bytes.Buffer{}

			//If the content length is known, resize the buffer
			if req.ContentLength > 0 {
				replacement.Buffer.Grow(int(req.ContentLength))
			}

			//Proxy the call to to Close()
			replacement.closeMe = req.Body

			//Copy the whole body, writing a copy into the HMAC
			teeReader := io.TeeReader(req.Body, h)
			_, err = io.Copy(replacement, teeReader)
			if err != nil {
				return nil, err
			}

			//Replace the original body
			req.Body = &replacement
		}

		signature := &bytes.Buffer{}
		signature.Grow(4 + 64)
		err = binary.Write(signature, binary.BigEndian, this.KeyId)
		if err != nil {
			return nil, err
		}

		_, err = signature.Write(h.Sum(nil))
		if err != nil {
			return nil, err
		}

		sigb64 := base64.StdEncoding.EncodeToString(signature.Bytes())
		if req.Header == nil {
			req.Header = http.Header{}
		}
		req.Header.Set(SIGNATURE_HEADER, sigb64)
	}
	if this.Next != nil {
		return this.Next.RoundTrip(req)
	} else {
		return http.DefaultTransport.RoundTrip(req)
	}
}

type echoer struct {
	*bytes.Buffer
	closeMe io.Closer
}

func (e echoer) Close() error {
	if e.closeMe != nil {
		return e.closeMe.Close()
	}
	return nil
}
