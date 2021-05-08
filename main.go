package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces
func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var iface = f.String("i", "lo", "Interface to get packets or filename to read")
	var port = f.Int("p", 8080, "TCP port")
	var logAllPackets = f.Bool("v", false, "Logs every packet in great detail")
	_ = f.Parse(os.Args[1:]) // Ignore errors; f is set for ExitOnError.

	handle := createPcapHandle(*iface, *port)
	process(handle, *port, *logAllPackets)
}

func process(handle *pcap.Handle, port int, logAllPackets bool) {
	log.Println("reading in packets")
	ticker := time.Tick(time.Minute)
	// Read in packets, pass to assembler.
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	// Set up assembly
	as := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&httpStreamFactory{port: port}))
	for {
		select {
		case p := <-packets:
			if p == nil { // A nil packet indicates the end of a pcap file.
				return
			}
			if logAllPackets {
				log.Println(p)
			}

			pn := p.NetworkLayer()
			pt := p.TransportLayer()
			if pn == nil || pt == nil || pt.LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			as.AssembleWithTimestamp(pn.NetworkFlow(), pt.(*layers.TCP), p.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			as.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func createPcapHandle(name string, port int) *pcap.Handle {
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
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

	filter := fmt.Sprintf("tcp and port %d", port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	return handle
}
