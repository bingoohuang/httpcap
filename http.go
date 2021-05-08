package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
)

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	port    int
	relayer RequestRelayer
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	port           string
	relayer        RequestRelayer
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		port:      fmt.Sprintf("%d", h.port),
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		relayer:   h.relayer,
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
		resolver = &ReqStreamResolver{buf: buf, relayer: h.relayer}
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
		r.Process()
	}

}
