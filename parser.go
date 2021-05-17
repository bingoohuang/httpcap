package main

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/bingoohuang/gometrics/metric"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// PacketProcessor defines the http packet processor interface.
type PacketProcessor interface {
	Process()
}

// PacketReader reads http packet.
type PacketReader interface {
	Read() (PacketProcessor, error)
}

// RequestReader reads http request packet.
type RequestReader struct {
	buf      *bufio.Reader
	replayer requestReplayer
	conf     *Conf
}

// ResponseReader reads http response packet.
type ResponseReader struct {
	buf       *bufio.Reader
	printBody bool
}

// Req is the rsp processor.
type Req struct {
	Val      *http.Request
	replayer requestReplayer
	conf     *Conf
}

// Rsp is the rsp processor.
type Rsp struct {
	Val       *http.Response
	printBody bool
}

// Process processes the req.
func (r Req) Process() {
	req := r.Val

	keys := r.conf.MetricsKeys
	if len(keys) > 0 {
		key1 := SliceItem(keys, 0, "httpcap")
		key2 := SliceItem(keys, 1, "req")
		metric.QPS(key1, key2, req.Method).Record(1)
	}

	_ = req.ParseMultipartForm(defaultMaxMemory)

	log.Printf("{PRE}Request: %s", printRequest(req))

	body, bodyLen, err := parseBody(req.Header, req.Body, true)
	relayCount := r.replayer(req.Method, req.RequestURI, req.Header, body)

	if relayCount != 0 {
		log.Printf("{PRE}Body size: %d, body: %s, error: %v", bodyLen, body, err)
	}
}

// Process processes the rsp.
func (r Rsp) Process() {
	log.Printf("{PRE}Response: %s", printResponse(r.Val))
	body, bodyLen, err := parseBody(r.Val.Header, r.Val.Body, r.printBody)
	log.Printf("{PRE}Body size: %d, body: %s, error: %v", bodyLen, body, err)
}

// Read reads a request.
func (r *RequestReader) Read() (PacketProcessor, error) {
	req, err := http.ReadRequest(r.buf)
	if err != nil {
		return nil, err
	}

	return &Req{Val: req, replayer: r.replayer, conf: r.conf}, nil
}

func (r *ResponseReader) Read() (PacketProcessor, error) {
	resp, err := http.ReadResponse(r.buf, nil)
	if err != nil {
		return nil, err
	}

	return &Rsp{Val: resp, printBody: r.printBody}, nil
}

func parseBody(header http.Header, body io.ReadCloser, printBody bool) ([]byte, int, error) {
	defer body.Close()

	r, err := decompressBody(header, body)
	if err != nil {
		log.Printf("DecompressBody error: %v", err)
		return nil, 0, err
	}

	ct := header.Get("Content-Type")
	if printBody && contains(ct, "application/json", "application/xml", "text/html", "text/plain") {
		data, err := ioutil.ReadAll(r)
		return data, len(data), err
	}

	return []byte("(ignored)"), tcpreader.DiscardBytesToEOF(r), nil
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
	switch ce := header.Get("Content-Encoding"); {
	case ce == "":
		return r, nil
	case strings.Contains(ce, "gzip"):
		return gzip.NewReader(r)
	case strings.Contains(ce, "deflate"):
		return zlib.NewReader(r)
	default:
		return r, nil
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
