package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"sync"
)

type StreamKey struct {
	NetFlow, TcpFlow gopacket.Flow
}

type UniStreams struct {
	Map  map[StreamKey]bool
	Lock sync.Mutex
}

func NewUniStreams() *UniStreams {
	return &UniStreams{Map: make(map[StreamKey]bool)}
}

func (u *UniStreams) Check(netFlow, tcpFlow gopacket.Flow) (func(), bool) {
	reverseKey := StreamKey{NetFlow: netFlow.Reverse(), TcpFlow: tcpFlow.Reverse()}

	u.Lock.Lock()
	if _, ok := u.Map[reverseKey]; ok {
		delete(u.Map, reverseKey)
		u.Lock.Unlock()
		return func() {}, true
	}

	key := StreamKey{NetFlow: netFlow, TcpFlow: tcpFlow}
	u.Map[key] = true
	u.Lock.Unlock()

	return func() {
		u.Lock.Lock()
		delete(u.Map, key)
		u.Lock.Unlock()
	}, false
}

// httpStreamFactory implements tcpassembly.StreamFactory.
type httpStreamFactory struct {
	bpf        string
	relayer    requestRelayer
	conf       *Conf
	printBody  bool
	uniStreams *UniStreams
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
		relayer: h.relayer,
	}
	go hs.run(h.uniStreams, netFlow, tcpFlow, h.conf, h.printBody) // Important... we must guarantee that data from the reader stream is read.

	return &hs.r
}

const defaultMaxMemory = 32 << 20 // 32 MB

func (h *httpStream) run(uniStreams *UniStreams, netFlow, tcpFlow gopacket.Flow, conf *Conf, printBody bool) {
	buf := bufio.NewReader(&h.r)
	dst := fmt.Sprintf("%v", tcpFlow.Dst())
	log.Printf("Transport dst: %s", dst)

	var resolver PacketReader
	f, ok := uniStreams.Check(netFlow, tcpFlow)
	if ok {
		resolver = &RspReqPacketReader{buf: buf, printBody: printBody}
	} else {
		resolver = &ReqPacketReader{buf: buf, relayer: h.relayer, conf: conf}
		defer f()
	}

	for {
		log.Printf("Start to [%s:%s]", netFlow, tcpFlow)
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
