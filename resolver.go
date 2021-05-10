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

type (
	// PacketProcessor defines the http packet processor interface.
	PacketProcessor interface {
		Process()
	}

	// PacketReader reads http packet.
	PacketReader interface {
		Read() (PacketProcessor, error)
	}

	// ReqPacketReader reads http request packet.
	ReqPacketReader struct {
		buf     *bufio.Reader
		relayer requestRelayer
		conf    *Conf
	}

	// RspReqPacketReader reads http response packet.
	RspReqPacketReader struct {
		buf *bufio.Reader
	}
	// Req is the rsp processor.
	Req struct {
		Val     *http.Request
		relayer requestRelayer
		conf    *Conf
	}
	// Rsp is the rsp processor.
	Rsp struct {
		Val *http.Response
	}
)

// Process processes the req.
func (r Req) Process() {
	req := r.Val

	keys := r.conf.MetricsKeys
	if len(keys) > 0 {
		key1 := SliceItem(keys, 0, "httpcap")
		key2 := SliceItem(keys, 1, "req")
		metric.QPS(key1, key2, req.Method)
		log.Printf("{PRE}metric.QPS(%s, %s, %s)", key1, key2, req.Method)
	}

	_ = req.ParseMultipartForm(defaultMaxMemory)

	log.Printf("{PRE}Request: %s", printRequest(req))

	body, bodyLen, err := parseBody(req.Header, req.Body)
	if r.relayer(req.Method, req.RequestURI, req.Header, body) {
		log.Printf("{PRE}Body size: %d, body: %s, error: %v", bodyLen, body, err)
	}
}

// Process processes the rsp.
func (r Rsp) Process() {
	log.Printf("{PRE}Response: %s", printResponse(r.Val))
	body, bodyLen, err := parseBody(r.Val.Header, r.Val.Body)
	log.Printf("{PRE}Body size: %d, body: %s, error: %v", bodyLen, body, err)
}

// Read reads a request.
func (r *ReqPacketReader) Read() (PacketProcessor, error) {
	req, err := http.ReadRequest(r.buf)
	if err != nil {
		return nil, err
	}

	return &Req{Val: req, relayer: r.relayer, conf: r.conf}, nil
}

func (r *RspReqPacketReader) Read() (PacketProcessor, error) {
	resp, err := http.ReadResponse(r.buf, nil)
	if err != nil {
		return nil, err
	}

	return &Rsp{Val: resp}, nil
}

func parseBody(header http.Header, body io.ReadCloser) ([]byte, int, error) {
	defer body.Close()

	r, err := decompressBody(header, body)
	if err != nil {
		log.Printf("DecompressBody error: %v", err)
		return nil, 0, err
	}

	ct := header.Get("Content-Type")
	if contains(ct, "application/json", "application/xml", "text/html", "text/plain") {
		data, err := ioutil.ReadAll(r)
		return data, len(data), err
	}

	return nil, tcpreader.DiscardBytesToEOF(r), nil
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
