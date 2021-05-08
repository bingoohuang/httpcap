package main

import (
	"flag"
	"fmt"
	"github.com/bingoohuang/gg/pkg/ctl"
	"github.com/bingoohuang/golog"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces
func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	ifaces := f.String("i", "", "Interfaces to get packets or filename to read, default to loopback interface, comma separated for multiple")
	confFile := f.String("c", "", "Filename of configuration in yaml format")
	ports := f.String("p", "", "TCP ports, comma separated for multiple")
	printRsp := f.Bool("resp", false, "Print HTTP response")
	logAllPackets := f.Bool("V", false, "Logs every packet in great detail")
	initing := f.Bool("init", false, "init sample conf.yaml/ctl and then exit")
	version := f.Bool("v", false, "show version info and exit")
	_ = f.Parse(os.Args[1:]) // Ignore errors; f is set for ExitOnError.

	ctl.Config{
		Initing:      *initing,
		PrintVersion: *version,
		VersionInfo:  "httpcap v0.0.1",
		ConfTemplate: confTemplate,
		ConfFileName: "conf.yml",
	}.ProcessInit()

	golog.SetupLogrus()

	conf := ParseConfFile(*confFile, *ports, *ifaces)
	for _, iface := range conf.Ifaces {
		for _, port := range conf.Ports {
			handle := createPcapHandle(iface, port, *printRsp)
			go process(handle, port, *logAllPackets, conf.ReplayRequest())
		}
	}

	select {}
}

func SplitInt(s string) (ret []int) {
	for _, sub := range strings.Split(s, ",") {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			v, err := strconv.Atoi(sub)
			if err != nil {
				log.Fatalf("E! %s is invalid", sub)
			}
			ret = append(ret, v)
		}
	}

	return ret
}
func Split(s string) (ret []string) {
	for _, sub := range strings.Split(s, ",") {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			ret = append(ret, sub)
		}
	}

	return ret
}

func process(handle *pcap.Handle, port int, logAllPackets bool, relayer RequestRelayer) {
	log.Println("reading in packets")
	ticker := time.Tick(time.Minute)
	// Read in packets, pass to assembler.
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	// Set up assembly
	as := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&httpStreamFactory{port: port, relayer: relayer}))
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

func createPcapHandle(name string, port int, printRsp bool) *pcap.Handle {
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

	filter := ""
	if printRsp {
		filter = fmt.Sprintf("tcp and port %d", port)
	} else {
		filter = fmt.Sprintf("tcp and dst port %d", port)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	return handle
}
