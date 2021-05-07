package main

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// from https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go
var iface = flag.String("i", "lo", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65535, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and dst port 8080", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hs.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hs.r
}

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			log.Printf("Received from stream [%s] [%s]\n", h.net, h.transport)
			printReq(req)
		}
	}
}

func printReq(req *http.Request) {
	// https://github.com/asmcos/sniffer/blob/master/sniffer.go
	req.ParseMultipartForm(defaultMaxMemory)
	defer req.Body.Close()

	r, ok := decompressBody(req.Header, req.Body)
	if ok {
		defer r.Close()
	}

	contentType := req.Header.Get("Content-Type")
	log.Printf("contentType:%s\n", contentType)
	log.Printf("request:%s\n", printRequest(req))
	if contains(contentType, "application/json", "application/xml", "text/html") {
		bodyBytes, err := ioutil.ReadAll(r)
		log.Printf("body size:%d, body:%s, error:%v\n", len(bodyBytes), bodyBytes, err)
	} else {
		bodyLen := tcpreader.DiscardBytesToEOF(r)
		log.Printf("body size:%d\n", bodyLen)
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

func printRequest(req *http.Request) string {
	logbuf := fmt.Sprintf("\n")
	logbuf += fmt.Sprintf("Host %s\n", req.Host)
	logbuf += fmt.Sprintf("%s %s %s\n", req.Method, req.RequestURI, req.Proto)
	logbuf += printHeader(req.Header)
	logbuf += printForm(req.Form)
	logbuf += printForm(req.PostForm)
	if req.MultipartForm != nil {
		logbuf += printForm(req.MultipartForm.Value)
	}
	return logbuf
}

func printHeader(h http.Header) string {
	var logbuf string

	for k, v := range h {
		if len(v) == 1 {
			logbuf += fmt.Sprintf("%s: %s\n", k, v[0])
		} else {
			logbuf += fmt.Sprintf("%s: %s\n", k, v)
		}
	}
	return logbuf
}

// url.Values map[string][]string
func printForm(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	var logbuf string

	logbuf += fmt.Sprint("\n**************\n")
	for k, data := range v {
		if len(data) == 1 {
			logbuf += fmt.Sprintf("%s: %s\n", k, data[0])
		} else {
			logbuf += fmt.Sprintf("%s: %s\n", k, data)
		}
	}
	logbuf += fmt.Sprint("**************\n")

	return logbuf
}

func decompressBody(header http.Header, r io.ReadCloser) (io.ReadCloser, bool) {
	contentEncoding := header.Get("Content-Encoding")
	if contentEncoding == "" {
		return r, false
	}

	var nr io.ReadCloser
	var err error
	if strings.Contains(contentEncoding, "gzip") {
		nr, err := gzip.NewReader(r)
		if err != nil {
			return r, false
		}
		return nr, true
	}

	if strings.Contains(contentEncoding, "deflate") {
		nr, err = zlib.NewReader(r)
		if err != nil {
			return r, false
		}
		return nr, true
	}

	return r, false
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
