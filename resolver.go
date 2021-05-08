package main

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type Packet interface {
	Print()
}

type StreamResolver interface {
	Read() (Packet, error)
}

type ReqStreamResolver struct{ buf *bufio.Reader }
type RspStreamResolver struct{ buf *bufio.Reader }
type Req struct{ Val *http.Request }
type Rsp struct{ Val *http.Response }

func (r Req) Print() {
	r.Val.ParseMultipartForm(defaultMaxMemory)

	log.Printf("[%s]request:%s\n", Gid(), printRequest(r.Val))
	printBody(r.Val.Header, r.Val.Body)
}

func (r Rsp) Print() {
	log.Printf("[%s]response:%s\n", Gid(), printResponse(r.Val))
	printBody(r.Val.Header, r.Val.Body)
}

func (r *ReqStreamResolver) Read() (Packet, error) {
	req, err := http.ReadRequest(r.buf)
	if err != nil {
		return nil, err
	}

	return &Req{Val: req}, nil
}

func (r *RspStreamResolver) Read() (Packet, error) {
	resp, err := http.ReadResponse(r.buf, nil)
	if err != nil {
		return nil, err
	}

	return &Rsp{Val: resp}, nil
}

func printBody(header http.Header, body io.ReadCloser) {
	defer body.Close()

	r, err := decompressBody(header, body)
	if err != nil {
		log.Printf("decompressBody error: %v\n", err)
		return
	}

	ct := header.Get("Content-Type")
	if contains(ct, "application/json", "application/xml", "text/html", "text/plain") {
		bodyBytes, err := ioutil.ReadAll(r)
		log.Printf("[%s]body size:%d, body:%s, error:%v\n", Gid(), len(bodyBytes), bodyBytes, err)
	} else {
		log.Printf("[%s]body size:%d\n", Gid(), tcpreader.DiscardBytesToEOF(r))
	}
}

func contains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func printRequest(r *http.Request) string {
	s := "\n"
	s += fmt.Sprintf("HOST %s\n", r.Host)
	s += fmt.Sprintf("%s %s %s\n", r.Method, r.RequestURI, r.Proto)
	s += printMapStrings(r.Header)
	s += printMapStrings(r.Form)
	s += printMapStrings(r.PostForm)
	if r.MultipartForm != nil {
		s += printMapStrings(r.MultipartForm.Value)
	}
	return s
}

func printResponse(resp *http.Response) string {
	s := "\n"
	s += fmt.Sprintf("%s %s\n", resp.Proto, resp.Status)
	s += printMapStrings(resp.Header)
	return s
}

func printMapStrings(m map[string][]string) string {
	if len(m) == 0 {
		return ""
	}

	var s string
	for k, v := range m {
		if len(v) == 1 {
			s += fmt.Sprintf("%s: %s\n", k, v[0])
		} else {
			s += fmt.Sprintf("%s: %s\n", k, v)
		}
	}

	return s
}

func decompressBody(header http.Header, r io.ReadCloser) (io.ReadCloser, error) {
	ce := header.Get("Content-Encoding")
	if ce == "" {
		return r, nil
	}

	if strings.Contains(ce, "gzip") {
		return gzip.NewReader(r)
	}

	if strings.Contains(ce, "deflate") {
		return zlib.NewReader(r)
	}

	return r, nil
}
