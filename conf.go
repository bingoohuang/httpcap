package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bingoohuang/gg/pkg/fn"
	"github.com/bingoohuang/gg/pkg/rest"
	"github.com/goccy/go-yaml"

	_ "embed"
)

// "embed"

//go:embed assets/conf.yml
var confTemplate []byte

// ReplayCondition is the condition which should be specified for replay requests.
type ReplayCondition struct {
	Not            bool     `yaml:"not"`
	MethodPatterns []string `yaml:"methodPatterns"`
	URLPatterns    []string `yaml:"urlPatterns"`
}

// MatchMethod tests the HTTP method matches the specified pattern.
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

// MatchURI tests the HTTP RequestURI matches the specified pattern.
func (c *ReplayCondition) MatchURI(uri string) bool {
	if len(c.URLPatterns) == 0 {
		return true
	}

	for _, m := range c.URLPatterns {
		if fn.Match(m, uri, fn.WithCaseSensitive(true)) {
			return true
		}
	}

	return false
}

// Matches test the http request matches the replay condition or not.
func (c *ReplayCondition) Matches(method string, uri string, headers http.Header) bool {
	return c.MatchMethod(method) && c.MatchURI(uri)
}

// Replay defines the replay action in configuration.
type Replay struct {
	Addrs      []string          `yaml:"addrs"`
	Conditions []ReplayCondition `yaml:"conditions"`
}

// Relay relays the http requests.
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

// Matches tests the request matches the replay's specified conditions or not.
// If matches not condition, return false directly.
// If no yes conditions defined, returns true.
// Or if any yes conditions matches, return true.
// Else return false.
func (r *Replay) Matches(method string, uri string, headers http.Header) bool {
	yesConditions := 0
	notConditions := 0
	matches1 := 0
	for _, cond := range r.Conditions {
		if cond.Not {
			notConditions++
		} else {
			yesConditions++
		}
		if cond.Matches(method, uri, headers) {
			if cond.Not {
				return false
			}

			matches1++
		}
	}

	return yesConditions == 0 || matches1 > 0
}

// Conf defines the structure to unmrshal the configuration yaml file.
type Conf struct {
	Ifaces []string `yaml:"ifaces"`
	Ports  []int    `yaml:"ports"`
	Relays []Replay `yaml:"relays"`
}

type requestRelayer func(method, requestURI string, headers http.Header, body []byte) bool

func (c *Conf) createRequestReplayer() requestRelayer {
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

	var availIfaces map[string]Iface

	usedIfaces := make([]string, 0, len(c.Ifaces))
	for _, ifa := range c.Ifaces {
		if ifa == "any" {
			c.Ifaces = []string{"any"}
			return
		}

		if availIfaces == nil {
			availIfaces = ListIfaces()
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
