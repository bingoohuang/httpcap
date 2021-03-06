package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bingoohuang/gg/pkg/ctl"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	_ "net/http/pprof" // Comment this line to disable pprof endpoint.
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
	bpf := f.String("bpf", "", "bpf like 'dst host 192.158.77.11 and dst port 9000'")
	printRspBody := f.Bool("resp", false, "Print HTTP response body")
	initing := f.Bool("init", false, "init sample httpcap.yml/ctl/.env and then exit")
	version := f.Bool("v", false, "show version info and exit")
	pprofAddr := f.String("pprof", "", "pprof address to listen on, not activate pprof if empty, eg localhost:6060")
	_ = f.Parse(os.Args[1:]) // Ignore errors; f is set for ExitOnError.

	ctl.Config{
		Initing:      *initing,
		PrintVersion: *version,
		VersionInfo:  "httpcap v0.0.7",
		InitFiles:    initAssets,
	}.ProcessInit()

	setupPprof(*pprofAddr)

	//golog.SetupLogrus()

	conf := ParseConfFile(*confFile, *bpf, *ifaces)
	var wg sync.WaitGroup
	for _, iface := range conf.Ifaces {
		for _, b := range conf.Bpfs {
			wg.Add(1)
			go process(&wg, createPcapHandle(iface, b), *printRspBody, conf)
		}
	}

	wg.Wait()
}

func setupPprof(pprofAddr string) {
	if pprofAddr == "" {
		return
	}

	pprofHostPort := pprofAddr
	parts := strings.Split(pprofHostPort, ":")
	if len(parts) == 2 && parts[0] == "" {
		pprofHostPort = fmt.Sprintf("localhost:%s", parts[1])
	}
	pprofHostPort = "http://" + pprofHostPort + "/debug/pprof"
	log.Printf("I! Starting pprof HTTP server at: %s", pprofHostPort)

	go func() {
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			log.Fatal("E! " + err.Error())
		}
	}()
}

func process(wg *sync.WaitGroup, handle *pcap.Handle, printRspBody bool, conf *Conf) {
	log.Println("Reading in packets")
	defer wg.Done()

	replayer := conf.createRequestReplayer()
	factory := &httpStreamFactory{conf: conf, replayer: replayer, printBody: printRspBody}
	as := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	loop(as, handle)
	as.FlushAll()
}

func loop(as *tcpassembly.Assembler, handle *pcap.Handle) {
	ticker := time.Tick(time.Minute)
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for {
		select {
		case p := <-packets:
			if p == nil { // A nil packet indicates the end of a pcap file.
				return
			}

			pn, pt := p.NetworkLayer(), p.TransportLayer()
			if pn == nil || pt == nil || pt.LayerType() != layers.LayerTypeTCP {
				continue
			}
			as.AssembleWithTimestamp(pn.NetworkFlow(), pt.(*layers.TCP), p.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			as.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func createPcapHandle(name, bpf string) *pcap.Handle {
	handle, err := pcapOpen(name)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(bpf); err != nil {
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
