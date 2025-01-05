package http

import (
	"bytes"
	"encoding/json"
	"io"
	netHttp "net/http"

	"github.com/arqut/common/system"
)

func Get(url string, out interface{}, headers ...string) (err error) {
	return Request("GET", url, nil, out, headers...)
}

func Post(url string, data interface{}, out interface{}, headers ...string) (err error) {
	return Request("POST", url, data, out, headers...)
}

func Put(url string, data interface{}, out interface{}, headers ...string) (err error) {
	return Request("PUT", url, data, out, headers...)
}

func Delete(url string, out interface{}, headers ...string) (err error) {
	return Request("DELETE", url, nil, out, headers...)
}

func Request(method string, url string, data interface{}, out interface{}, headers ...string) (err error) {
	system.Logger.Infof("http[%s] %s", method, url)

	var req *netHttp.Request
	client := &netHttp.Client{}

	var in io.Reader
	var body []byte

	if data != nil {
		var raw []byte
		raw, err = json.Marshal(data)
		in = bytes.NewBuffer(raw)
		if err != nil {
			return
		}
	}

	req, err = netHttp.NewRequest(method, url, in)
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/json")

	hl := len(headers)
	if hl > 0 && hl%2 == 0 {
		for i := 0; i < hl; i += 2 {
			req.Header.Add(headers[i], headers[i+1])
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, out)

	return
}
