package main

import (
	"encoding/json"
	"fmt"
	"github.com/bingoohuang/gg/pkg/fn"
	"github.com/bingoohuang/gg/pkg/rest"
	"github.com/goccy/go-yaml"
	"log"
	"net/http"
	"os"
)

import (
	_ "embed" // "embed"
)

//go:embed assets/conf.yml
var confTemplate []byte

type ReplayCondition struct {
	Not            bool     `yaml:"not"`
	MethodPatterns []string `yaml:"methodPatterns"`
	UrlPatterns    []string `yaml:"urlPatterns"`
}

func (c *ReplayCondition) MatchMethod(method string) bool {
	if len(c.MethodPatterns) == 0 {
		return true
	}

	for _, m := range c.MethodPatterns {
		if fn.Match(m, method, fn.WithCaseSensitive(true)) {
			return true
		}
	}

	return false
}

func (c *ReplayCondition) MatchUrl(uri string) bool {
	if len(c.UrlPatterns) == 0 {
		return true
	}

	for _, m := range c.UrlPatterns {
		if fn.Match(m, uri, fn.WithCaseSensitive(true)) {
			return true
		}
	}

	return false
}

func (c *ReplayCondition) MatchMethodUrl(method string, uri string, headers http.Header) bool {
	return c.MatchMethod(method) && c.MatchUrl(uri)
}

type Replay struct {
	Addrs      []string          `yaml:"addrs"`
	Conditions []ReplayCondition `yaml:"conditions"`
}

func (r *Replay) Relay(method string, uri string, headers http.Header, body []byte) bool {
	if !r.Matches(method, uri, headers) {
		return false
	}

	pairs := make(map[string]string)
	for k, v := range headers {
		pairs[k] = v[0]
	}

	for _, addr := range r.Addrs {
		u := fmt.Sprintf("http://%s%s", addr, uri)
		r, err := rest.Rest{Method: method, Addr: u, Headers: pairs, Body: body}.Do()
		if err != nil {
			log.Printf("E! Replay %s %s error:%v", method, u, err)
		}
		if r != nil {
			log.Printf("Replay %s %s status: %d, message: %s", method, u, r.Status, r.Body)
		}
	}

	return true
}

func (r *Replay) Matches(method string, uri string, headers http.Header) bool {
	matches1 := 0
	matches2 := 0
	for _, cond := range r.Conditions {
		if cond.MatchMethodUrl(method, uri, headers) {
			if cond.Not {
				matches2++
			} else {
				matches1++
			}
		}
	}

	switch {
	case matches1 == 0 && matches2 == 0:
		return true
	case matches2 > 0:
		return false
	default:
		return true
	}
}

type Conf struct {
	Ifaces []string `yaml:"ifaces"`
	Ports  []int    `yaml:"ports"`
	Relays []Replay `yaml:"relays"`
}

type RequestRelayer func(method, requestURI string, headers http.Header, body []byte) bool

func (c *Conf) CreateRequestReplayer() RequestRelayer {
	if len(c.Relays) == 0 {
		return func(method, requestURI string, headers http.Header, body []byte) bool {
			return false
		}
	}

	return func(method, requestURI string, headers http.Header, body []byte) bool {
		found := false
		for _, relay := range c.Relays {
			if v := relay.Relay(method, requestURI, headers, body); v {
				found = true
			}
		}

		return found
	}
}

// UnmarshalConfFile parses the conf yaml file.
func UnmarshalConfFile(confFile string) (*Conf, error) {
	confBytes, err := os.ReadFile(confFile)
	if err != nil {
		return nil, fmt.Errorf("read conf file %s error: %q", confFile, err)
	}

	ci := &Conf{}
	if err := yaml.Unmarshal(confBytes, ci); err != nil {
		return nil, fmt.Errorf("decode conf file %s error:%q", confFile, err)
	}

	return ci, nil
}

// ParseConfFile parses conf yaml file and flags to *Conf.
func ParseConfFile(confFile, ports, ifaces string) *Conf {
	var err error
	var conf *Conf

	if confFile != "" {
		if conf, err = UnmarshalConfFile(confFile); err != nil {
			log.Fatal(err)
		}
	}

	if conf == nil {
		conf = &Conf{}
	}

	if ports != "" {
		conf.Ports = SplitInt(ports)
	}

	if ifaces != "" {
		conf.Ifaces = Split(ifaces)
	}

	if len(conf.Ports) == 0 {
		log.Fatal("At least one TCP port should be specified")
	}

	conf.fixIfaces()

	confJSON, _ := json.Marshal(conf)
	log.Printf("Configuration: %s", confJSON)

	return conf
}

func (c *Conf) fixIfaces() {
	hasAny := len(c.Ifaces) == 0
	if hasAny {
		c.Ifaces = []string{"any"}
		return
	}

	availIfaces := ListIfaces()
	usedIfaces := make([]string, 0, len(c.Ifaces))
	for _, ifa := range c.Ifaces {
		if ifa == "any" {
			c.Ifaces = []string{"any"}
			return
		}

		if _, ok := availIfaces[ifa]; ok {
			usedIfaces = append(usedIfaces, ifa)
		} else {
			log.Printf("W! iface name %s is unknown, it will be ignored", ifa)
		}
	}

	if len(usedIfaces) == 0 {
		log.Fatalf("E! at least one valid iface name should be specified")
	}

	c.Ifaces = usedIfaces
}
