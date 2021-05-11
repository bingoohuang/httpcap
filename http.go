package main

import (
	"bufio"
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	port      int
	relayer   requestRelayer
	conf      *Conf
	printBody bool
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	port           string
	relayer        requestRelayer
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		port:      fmt.Sprintf("%d", h.port),
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		relayer:   h.relayer,
	}
	go hs.run(h.conf, h.printBody) // Important... we must guarantee that data from the reader stream is read.

	return &hs.r
}

const defaultMaxMemory = 32 << 20 // 32 MB

func (h *httpStream) run(conf *Conf, printBody bool) {
	buf := bufio.NewReader(&h.r)
	src := fmt.Sprintf("%v", h.transport.Src())
	log.Printf("Transport src: %s", src)

	var resolver PacketReader
	if src == h.port {
		resolver = &RspReqPacketReader{buf: buf, printBody: printBody}
	} else {
		resolver = &ReqPacketReader{buf: buf, relayer: h.relayer, conf: conf}
	}

	for {
		log.Printf("Start to [%s:%s]", h.net, h.transport)
		r, err := resolver.Read()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Printf("EOF [%s:%s]", h.net, h.transport)
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("E! Reading stream [%s:%s], error: %v", h.net, h.transport, err)
			continue
		}

		log.Printf("Received from stream [%s:%s]", h.net, h.transport)
		r.Process()
	}
}
