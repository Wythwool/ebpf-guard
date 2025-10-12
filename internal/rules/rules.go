package rules

import (
	"os"
	"regexp"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

type Match struct {
	CommRe string `yaml:"comm_re"`
	PathRe string `yaml:"path_re"`
	IPRe   string `yaml:"ip_re"`
	PortIn []int  `yaml:"port_in"`
	UIDIn  []int  `yaml:"uid_in"`
}

type Rule struct {
	Name   string `yaml:"name"`
	Match  Match  `yaml:"match"`
	Action string `yaml:"action"` // allow|deny|alert
	Reason string `yaml:"reason"`
}

type Compiled struct {
	R Rule
	comm *regexp.Regexp
	path *regexp.Regexp
	ip   *regexp.Regexp
	port map[int]struct{}
	uid  map[int]struct{}
}

type Set struct {
	rules []Compiled
	rev   atomic.Uint64
}

func Compile(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var rs []Rule
	if err := yaml.Unmarshal(b, &rs); err != nil { return nil, err }
	out := make([]Compiled, 0, len(rs))
	for _, r := range rs {
		c := Compiled{R: r, port: map[int]struct{}{}, uid: map[int]struct{}{}}
		if r.Match.CommRe != "" { c.comm = regexp.MustCompile(r.Match.CommRe) }
		if r.Match.PathRe != "" { c.path = regexp.MustCompile(r.Match.PathRe) }
		if r.Match.IPRe   != "" { c.ip   = regexp.MustCompile(r.Match.IPRe) }
		for _, p := range r.Match.PortIn { c.port[p] = struct{}{} }
		for _, u := range r.Match.UIDIn  { c.uid[u]  = struct{}{} }
		out = append(out, c)
	}
	s := &Set{rules: out}
	s.rev.Store(1)
	return s, nil
}

type EventMeta struct {
	Type string
	Comm string
	Path string
	IP   string
	Port int
	UID  int
}

type Decision struct {
	Matched bool
	Rule    string
	Action  string
	Reason  string
}

func (s *Set) Decide(ev EventMeta) Decision {
	// order: deny -> allow -> alert (first match wins)
	first := func(action string) (Decision, bool) {
		for _, c := range s.rules {
			if c.R.Action != action { continue }
			if c.comm != nil && !c.comm.MatchString(ev.Comm) { continue }
			if c.path != nil && ev.Path != "" && !c.path.MatchString(ev.Path) { continue }
			if c.ip   != nil && ev.IP   != "" && !c.ip.MatchString(ev.IP) { continue }
			if len(c.port) > 0 {
				if _, ok := c.port[ev.Port]; !ok { continue }
			}
			if len(c.uid) > 0 {
				if _, ok := c.uid[ev.UID]; !ok { continue }
			}
			return Decision{Matched: true, Rule: c.R.Name, Action: c.R.Action, Reason: c.R.Reason}, true
		}
		return Decision{}, false
	}
	if d, ok := first("deny"); ok { return d }
	if d, ok := first("allow"); ok { return d }
	if d, ok := first("alert"); ok { return d }
	return Decision{Matched: false, Action: "observe"}
}
