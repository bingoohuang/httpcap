package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	bpf       string
	relayer   requestRelayer
	conf      *Conf
	printBody bool
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	bpf            string
	relayer        requestRelayer
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		bpf:       fmt.Sprintf("%d", h.bpf),
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
	dst := fmt.Sprintf("%v", h.transport.Dst())
	log.Printf("Transport dst: %s", dst)

	var resolver PacketReader
	if strings.Contains(h.bpf, dst) {
		resolver = &ReqPacketReader{buf: buf, relayer: h.relayer, conf: conf}
	} else {
		resolver = &RspReqPacketReader{buf: buf, printBody: printBody}
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
