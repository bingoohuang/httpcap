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
	bpf       string
	replayer  requestRelayer
	conf      *Conf
	printBody bool
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	r       tcpreader.ReaderStream
	bpf     string
	relayer requestRelayer
}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		bpf:     fmt.Sprintf("%d", h.bpf),
		r:       tcpreader.NewReaderStream(),
		relayer: h.replayer,
	}
	go hs.run(netFlow, tcpFlow, h.conf, h.printBody) // Important... we must guarantee that data from the reader stream is read.

	return &hs.r
}

const defaultMaxMemory = 32 << 20 // 32 MB

func (h *httpStream) run(netFlow, tcpFlow gopacket.Flow, conf *Conf, printBody bool) {
	buf := bufio.NewReader(&h.r)
	log.Printf("Start to [%s:%s]", netFlow, tcpFlow)

	peek, _ := buf.Peek(5)

	var resolver PacketReader

	if string(peek) == "HTTP/" {
		resolver = &ResponsePacketReader{buf: buf, printBody: printBody}
	} else {
		resolver = &RequestPacketReader{buf: buf, relayer: h.relayer, conf: conf}
	}

	for {
		r, err := resolver.Read()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Printf("EOF [%s:%s]", netFlow, tcpFlow)
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("E! Reading stream [%s:%s], error: %v", netFlow, tcpFlow, err)
			continue
		}

		log.Printf("Received from stream [%s:%s]", netFlow, tcpFlow)
		r.Process()
	}
}
