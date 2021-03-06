package schnellburger

import "net/http"
import "fmt"

type help struct {
	StatusCode int
	ErrorCode  int
	Message    string
	Title      string
}

var helpErrCodeCounter = 0

func newHelp(sc int, title string, message string) *help {
	r := &help{}
	r.StatusCode = sc
	r.Title = title
	r.Message = message
	r.ErrorCode = helpErrCodeCounter
	helpErrCodeCounter++

	return r
}

//Header returned to clients to indicate what algorithm to sign requests with
const ALGORITHM_HEADER = "X-Schnellburger-Algo"

//Header returned to clients to indicate the error message, if any
const ERROR_HEADER = "X-Schnellburger-Error"

//Header returned to client to idnicate the type of the error, if any
const ERROR_TYPE_HEADER = "X-Schnellburger-Error-Type"

//Header returned to clients to uniquely identify this error
const ERROR_CODE_HEADER = "X-Schnellburger-Error-Code"

//Header returned to clients to link to documentation
const DOCUMENTATION_URL_HEADER = "X-Schnellburger-Doc"
const DOCUMENTATION_URL = "http://godoc.org/github.com/hydrogen18/schnellburger"

func (h *help) Show(rw http.ResponseWriter, req *http.Request, sb Schnellburger, err error) {
	rw.Header().Add(ERROR_CODE_HEADER, fmt.Sprintf("%d", h.ErrorCode))
	rw.Header().Add(DOCUMENTATION_URL_HEADER, DOCUMENTATION_URL)
	rw.Header().Add(ALGORITHM_HEADER, fmt.Sprintf("%T", sb.Algorithm()))

	if err != nil {
		rw.Header().Add(ERROR_TYPE_HEADER, fmt.Sprintf("%T", err))
		rw.Header().Add(ERROR_HEADER, fmt.Sprintf("%v", err))
	}
	rw.Header().Add("Content-Type", "text/plain")
	rw.WriteHeader(h.StatusCode)
	fmt.Fprintf(rw, "%s\n---\n%s", h.Title, h.Message)
}

var MissingHeader = newHelp(http.StatusForbidden, "Missing Header",
	fmt.Sprintf("You must supply the authorization header %q to this endpoint", HMAC_HEADER))

var InvalidHeader = newHelp(http.StatusForbidden, "Invalid Header",
	fmt.Sprintf("The value supplied as the header %q must the base64 encoding of a signature", HMAC_HEADER))

var HeaderTooShort = newHelp(http.StatusForbidden, "Header Too Short",
	fmt.Sprintf("The value supplied as the header %q did not have enough bytes after base64 decoding", HMAC_HEADER))

var KeyIndexWrongLength = newHelp(http.StatusForbidden, "Key Index Wrong Length",
	"The key index at the beginning of the authorization bytes must be exactly 0,2,4, or 8 bytes representing an unsigned integer")

var SignatureWrongSize = newHelp(http.StatusForbidden, "Signature Wrong Size",
	"The bytes after the key index must exactly match the output of the algorithm in use")

var NotAuthentic = newHelp(http.StatusForbidden, "Not Authentic",
	"The request you have made is not authentic")

var KeyLookupFailure = newHelp(http.StatusInternalServerError, "Key Lookup Failure",
	"Failure while attempting to lookup the key by index")
