package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bingoohuang/gg/pkg/ctl"
	"github.com/bingoohuang/golog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

//go:embed initassets
//go:embed initassets/.env
var initAssets embed.FS

const defaultConfFile = "httpcap.yml"

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces
func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	ifaces := f.String("i", "", "Interfaces to get packets or filename to read, default to loopback interface, comma separated for multiple")
	confFile := f.String("c", "", "Filename of configuration in yaml format, default to "+defaultConfFile)
	ports := f.String("p", "", "TCP ports, comma separated for multiple")
	printRspBody := f.Bool("resp", false, "Print HTTP response body")
	logAllPackets := f.Bool("V", false, "Logs every packet in great detail")
	initing := f.Bool("init", false, "init sample httpcap.yml/ctl/.env and then exit")
	version := f.Bool("v", false, "show version info and exit")
	_ = f.Parse(os.Args[1:]) // Ignore errors; f is set for ExitOnError.

	ctl.Config{
		Initing:      *initing,
		PrintVersion: *version,
		VersionInfo:  "httpcap v0.0.2",
		InitFiles:    initAssets,
	}.ProcessInit()

	golog.SetupLogrus()

	conf := ParseConfFile(*confFile, *ports, *ifaces)
	for _, iface := range conf.Ifaces {
		for _, port := range conf.Ports {
			handle := createPcapHandle(iface, port)
			go process(handle, port, *logAllPackets, *printRspBody, conf)
		}
	}

	select {}
}

func process(handle *pcap.Handle, port int, logAllPackets, printRspBody bool, conf *Conf) {
	log.Println("Reading in packets")
	ticker := time.Tick(time.Minute)
	// Read in packets, pass to assembler.
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	// Set up assembly
	relayer := conf.createRequestReplayer()
	factory := &httpStreamFactory{conf: conf, port: port, relayer: relayer, printBody: printRspBody}
	as := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
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
	handle, err := pcapOpen(name)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and port %d", port)); err != nil {
		log.Fatal(err)
	}

	return handle
}

func pcapOpen(name string) (*pcap.Handle, error) {
	// Set up pcap packet capture
	if v, e := os.Stat(name); e == nil && !v.IsDir() {
		log.Printf("Reading from pcap dump %q", name)
		return pcap.OpenOffline(name)
	}

	log.Printf("Starting capture on interface %q", name)
	return pcap.OpenLive(name, 65535, false, pcap.BlockForever)
}
