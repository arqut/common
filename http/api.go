package http

import (
	"bytes"
	"encoding/json"
	"io"
	netHttp "net/http"
	"time"
)

var client *netHttp.Client

func SetClient(c *netHttp.Client) {
	client = c
}

func Get(url string, out any, headers ...string) (err error) {
	return Request("GET", url, nil, out, headers...)
}

func Post(url string, data any, out any, headers ...string) (err error) {
	return Request("POST", url, data, out, headers...)
}

func Put(url string, data any, out any, headers ...string) (err error) {
	return Request("PUT", url, data, out, headers...)
}

func Delete(url string, out any, headers ...string) (err error) {
	return Request("DELETE", url, nil, out, headers...)
}

func Request(method string, url string, data any, out any, headers ...string) (err error) {
	var req *netHttp.Request

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

	resp, err := httpClient().Do(req)
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

func httpClient() *netHttp.Client {
	if client == nil {
		client = &netHttp.Client{
			Timeout: 10 * time.Second, // Adjust as needed
		}
	}
	return client
}
