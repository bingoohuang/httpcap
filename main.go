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
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	port int
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	port           string
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		port:      fmt.Sprintf("%d", h.port),
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hs.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hs.r
}

const defaultMaxMemory = 32 << 20 // 32 MB

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	src := fmt.Sprintf("%v", h.transport.Src())
	log.Printf("[%s]src:%s", Gid(), src)

	var resolver StreamResolver
	if src == h.port {
		resolver = &RspStreamResolver{buf: buf}
	} else {
		resolver = &ReqStreamResolver{buf: buf}
	}

	for {
		log.Printf("[%s]Start to  [%s]:[%s]", Gid(), h.net, h.transport)
		r, err := resolver.Read()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Printf("[%s]EOF [%s]:[%s]", Gid(), h.net, h.transport)
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("[%s]Error reading stream [%s]:[%s], error: %v", Gid(), h.net, h.transport, err)
			continue
		}

		log.Printf("[%s]Received from stream [%s]:[%s]", Gid(), h.net, h.transport)
		r.Print()
	}

}

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var iface = f.String("i", "lo", "Interface to get packets or filename to read")
	var port = f.Int("p", 8080, "tcp port")
	var logAllPackets = f.Bool("v", false, "Logs every packet in great detail")
	// Ignore errors; f is set for ExitOnError.
	_ = f.Parse(os.Args[1:])

	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	name := *iface
	if v, e := os.Stat(name); e == nil && !v.IsDir() {
		log.Printf("Reading from pcap dump %q", name)
		handle, err = pcap.OpenOffline(name)
	} else {
		log.Printf("Starting capture on interface %q", name)
		handle, err = pcap.OpenLive(name, 65535, false, pcap.BlockForever)
	}

	if err != nil {
		log.Fatal(err)
	}

	filter := fmt.Sprintf("tcp and port %d", *port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{port: *port}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case p := <-packets:
			// A nil packet indicates the end of a pcap file.
			if p == nil {
				return
			}
			if *logAllPackets {
				log.Println(p)
			}
			if p.NetworkLayer() == nil || p.TransportLayer() == nil || p.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := p.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(p.NetworkLayer().NetworkFlow(), tcp, p.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

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

	log.Printf("request:%s\n", printRequest(r.Val))
	printBody(r.Val.Header, r.Val.Body)
}
func (r Rsp) Print() {
	log.Printf("response:%s\n", printResponse(r.Val))
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
		log.Printf("body size:%d, body:%s, error:%v\n", len(bodyBytes), bodyBytes, err)
	} else {
		log.Printf("body size:%d\n", tcpreader.DiscardBytesToEOF(r))
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
	s := "\n"
	s += fmt.Sprintf("HOST %s\n", req.Host)
	s += fmt.Sprintf("%s %s %s\n", req.Method, req.RequestURI, req.Proto)
	s += printMapStrings(req.Header)
	s += printMapStrings(req.Form)
	s += printMapStrings(req.PostForm)
	if req.MultipartForm != nil {
		s += printMapStrings(req.MultipartForm.Value)
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

func Gid() string {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	return strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
}
