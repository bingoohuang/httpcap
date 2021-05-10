package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bingoohuang/golog/pkg/rotate"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"

	"github.com/bingoohuang/gg/pkg/fn"
	"github.com/bingoohuang/gg/pkg/rest"
	"github.com/bingoohuang/jj"
	"github.com/goccy/go-yaml"

	_ "embed"
)

// Conf defines the structure to unmrshal the configuration yaml file.
type Conf struct {
	Ifaces      []string `yaml:"ifaces"`
	Ports       []int    `yaml:"ports"`
	MetricsKeys []string `yaml:"metricsKeys"`
	Relays      []Replay `yaml:"relays"`
}

//go:embed assets/conf.yml
var confTemplate []byte

// ReplayCondition is the condition which should be specified for replay requests.
type ReplayCondition struct {
	MethodPatterns []string `yaml:"methodPatterns"`
	URLPatterns    []string `yaml:"urlPatterns"`
}

// MatchMethod tests the HTTP method matches the specified pattern.
func (c *ReplayCondition) MatchMethod(method string) bool {
	if len(c.MethodPatterns) == 0 {
		return true
	}

	for _, m := range c.MethodPatterns {
		yes := !strings.HasPrefix(m, "!")
		if !yes {
			m = m[1:]
		}

		if yes == fn.Match(m, method, fn.WithCaseSensitive(true)) {
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
		yes := !strings.HasPrefix(m, "!")
		if !yes {
			m = m[1:]
		}
		if yes == fn.Match(m, uri, fn.WithCaseSensitive(true)) {
			return true
		}
	}

	return false
}

// Matches test the http request matches the replay condition or not.
func (c *ReplayCondition) Matches(method string, uri string, _ http.Header) bool {
	return c.MatchMethod(method) && c.MatchURI(uri)
}

// Replay defines the replay action in configuration.
type Replay struct {
	Addrs       []string          `yaml:"addrs"`
	Conditions  []ReplayCondition `yaml:"conditions"`
	RecordFails []RecordFail      `yaml:"recordFails"`
	FailLogFile string            `yaml:"failLogFile"`

	failLog *rotate.Rotate
}

func (r *Replay) setup() {
	if r.FailLogFile == "" {
		return
	}

	var err error
	r.failLog, err = rotate.New(r.FailLogFile)
	if err != nil {
		log.Fatalf("failed to create rotate log file %s, error: %v", r.FailLogFile, err)
	}
}

// RecordFail defines the structure of RecordFail.
type RecordFail struct {
	Key  string `yaml:"key"`
	Path string `yaml:"path"`
}

// Relay relays the http requests.
func (r *Replay) Relay(method string, uri string, headers http.Header, body []byte) (matches bool) {
	if !r.Matches(method, uri, headers) {
		return false
	}

	pairs := make(map[string]string)
	for k, v := range headers {
		pairs[k] = v[0]
	}

	errMsgs := make([]string, 0, len(r.Addrs))
	for _, addr := range r.Addrs {
		u := fmt.Sprintf("http://%s%s", addr, uri)
		r, err := rest.Rest{Method: method, Addr: u, Headers: pairs, Body: body}.Do()
		if err != nil {
			log.Printf("E! Replay %s %s error:%v", method, u, err)
			errMsgs = append(errMsgs, fmt.Sprintf("write %s fail:%v", u, err))
		} else if r != nil {
			log.Printf("Replay %s %s status: %d, message: %s", method, u, r.Status, r.Body)
			if r.Status < 200 || r.Status >= 300 {
				errMsgs = append(errMsgs, fmt.Sprintf("write %s status:%v", u, r.Status))
			}
		}
	}

	if len(errMsgs) == 0 {
		return true
	}

	vm := r.recordReqValues(headers, body)
	vmJSON, _ := json.Marshal(struct {
		Time   string
		Keys   map[string]string
		Errors []string
	}{
		Time:   time.Now().Format(`2006-01-02 15:04:05.000`),
		Keys:   vm,
		Errors: errMsgs,
	})
	log.Printf("Records failed request: %s", vmJSON)

	if r.failLog != nil {
		_, _ = r.failLog.Write(vmJSON)
		_, _ = r.failLog.Write([]byte("\n"))
	}

	return true
}

func (r *Replay) recordReqValues(headers http.Header, body []byte) map[string]string {
	switch contentType := headers.Get("Content-Type"); {
	case strings.Contains(contentType, "application/xml"):
		return r.recordXMLValues(body)
	case strings.Contains(contentType, "application/json"):
		return r.recordJSONValues(body)
	}

	return nil
}

func (r *Replay) recordJSONValues(b []byte) map[string]string {
	vm := make(map[string]string, len(r.RecordFails))
	for _, xp := range r.RecordFails {
		value := jj.GetBytes(b, xp.Path)
		vm[xp.Key] = value.String()
	}
	return vm
}

func (r *Replay) recordXMLValues(b []byte) map[string]string {
	doc, err := xmlquery.Parse(bytes.NewReader(b))
	if err != nil {
		log.Printf("E! failed to parse xml %s, errors: %v", b, err)
		return nil
	}

	vm := make(map[string]string, len(r.RecordFails))
	for _, xp := range r.RecordFails {
		l := xmlquery.Find(doc, xp.Path)
		values := make([]string, len(l))
		for i, n := range l {
			values[i] = n.Data
		}
		vm[xp.Key] = strings.Join(values, ",")
	}
	return vm
}

// Matches tests the request matches the replay's specified conditions or not.
// If matches not condition, return false directly.
// If no yes conditions defined, returns true.
// Or if any yes conditions matches, return true.
// Else return false.
func (r *Replay) Matches(method string, uri string, headers http.Header) bool {
	if len(r.Conditions) == 0 {
		return true
	}
	for _, cond := range r.Conditions {
		if cond.Matches(method, uri, headers) {
			return true
		}
	}

	return false
}

// requestRelayer defines the func prototype to replay a request.
// return -1: no relays defined, or number of replays applied.
type requestRelayer func(method, requestURI string, headers http.Header, body []byte) int

func (c *Conf) createRequestReplayer() requestRelayer {
	if len(c.Relays) == 0 {
		return func(_, _ string, _ http.Header, _ []byte) int { return -1 }
	}

	return func(method, requestURI string, headers http.Header, body []byte) int {
		found := 0
		for _, relay := range c.Relays {
			if relay.Relay(method, requestURI, headers, body) {
				found++
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

	conf.setup()

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

func (c *Conf) setup() {
	for i := range c.Relays {
		c.Relays[i].setup()
	}
}
