package main

import (
	"bufio"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
)

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	replayer  requestReplayer
	conf      *Conf
	printBody bool
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	r        tcpreader.ReaderStream
	replayer requestReplayer
}

func (h *httpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		r:        tcpreader.NewReaderStream(),
		replayer: h.replayer,
	}
	// Important... we must guarantee that data from the reader stream is read.
	go hs.run(netFlow, tcpFlow, h.conf, h.printBody)

	return &hs.r
}

const defaultMaxMemory = 32 << 20 // 32 MB

func (h *httpStream) run(netFlow, tcpFlow gopacket.Flow, conf *Conf, printBody bool) {
	buf := bufio.NewReader(&h.r)
	log.Printf("Start to [%s:%s]", netFlow, tcpFlow)

	peek, _ := buf.Peek(5)

	var reader PacketReader

	if string(peek) == "HTTP/" {
		reader = &ResponseReader{buf: buf, printBody: printBody}
	} else {
		reader = &RequestReader{buf: buf, replayer: h.replayer, conf: conf}
	}

	for {
		r, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("EOF [%s:%s]", netFlow, tcpFlow)
				return // We must read until we see an EOF... very important!
			}

			log.Printf("E! Reading stream [%s:%s], error: %v", netFlow, tcpFlow, err)
			continue
		}

		log.Printf("Received from stream [%s:%s]", netFlow, tcpFlow)
		r.Process()
	}
}
