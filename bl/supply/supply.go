package supply

import (
	"errors"
	"io"
	"net/http"
)

const TAB = 9
const LF = 10
const SHE = 35
const DOT = 46

const oneKB = 1024

const IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

func Fetch() (*http.Response, error) {
	req, err := http.NewRequest("GET", IPSUM_URL, nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		return nil, errors.New("got non-2xx response code")
	}

	return resp, nil
}

func Parse(resp *http.Response, setbit_func func(int, int)) error {
	buf := make([]byte, oneKB)

	// 4 octets, with up to 3 digits each
	ip := make([]byte, 3*4)

	bytesRead := 0

	i := 0          // the current seen digit index
	octet := 0      // the current seen octet index
	ignore := false // the commented line is found, or line is not interested anymore
	for {
		n, err := resp.Body.Read(buf)
		bytesRead += n

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		for _, b := range buf {
			switch {
			case b == SHE:
				ignore = true
			case b == LF:
				ignore = false
			case !ignore && (b >= 48 && b <= 57):
				ip[(octet*3)+i] = b
				i = i + 1
			case !ignore && (b == DOT):
				value := atoi(ip[(octet*3)+0 : (octet*3)+i])

				setbit_func(octet, int(value))

				i = 0
				octet = octet + 1
			case !ignore && (b == TAB):
				value := atoi(ip[(octet*3)+0 : (octet*3)+i])

				setbit_func(octet, int(value))

				i = 0
				octet = 0
				ignore = true
			}
		}
	}
	return nil
	// TODO: check what happens when stream of bytes will be less then content-type
}

func atoi(xs []byte) (b byte) {
	for _, c := range xs {
		b = b*10 + (c - '0')
	}
	return
}
