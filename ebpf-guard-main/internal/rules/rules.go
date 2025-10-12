package rules

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"gopkg.in/yaml.v3"
)

type Action string

const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionAlert   Action = "alert"
	ActionObserve Action = "observe"
)

var actionOrder = []Action{ActionDeny, ActionAllow, ActionAlert, ActionObserve}

type fileRule struct {
	Name   string      `yaml:"name"`
	Match  matchConfig `yaml:"match"`
	Action string      `yaml:"action"`
	Reason string      `yaml:"reason"`
}

type matchConfig struct {
	CommRE string `yaml:"comm_re"`
	PathRE string `yaml:"path_re"`
	IPRE   string `yaml:"ip_re"`
	PortIn []int  `yaml:"port_in"`
	UIDIn  []int  `yaml:"uid_in"`
}

type compiledRule struct {
	name   string
	action Action
	reason string

	comm *regexp.Regexp
	path *regexp.Regexp
	ip   *regexp.Regexp

	ports map[int]struct{}
	uids  map[int]struct{}
}

type Engine struct {
	mu    sync.RWMutex
	rules map[Action][]compiledRule
}

type MatchResult struct {
	Matched  bool
	RuleName string
	Action   Action
	Reason   string
}

type ExecEvent struct {
	Timestamp uint64
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      string
	Filename  string
}

type OpenEvent struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Comm      string
	Path      string
	Flags     int
}

type ConnectEvent struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Comm      string
	Family    uint16
	Dport     uint16
	DaddrV4   uint32
	DaddrV6   [16]byte
}

func NewEngineFromFile(path string) (*Engine, error) {
	rules, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rules}, nil
}

func (e *Engine) Reload(path string) error {
	rules, err := loadFile(path)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	return nil
}

func (e *Engine) MatchExec(evt ExecEvent) MatchResult {
	matcher := func(r compiledRule) bool {
		if r.comm != nil && !r.comm.MatchString(evt.Comm) {
			return false
		}
		if r.path != nil && !r.path.MatchString(evt.Filename) {
			return false
		}
		if len(r.uids) > 0 {
			if _, ok := r.uids[int(evt.UID)]; !ok {
				return false
			}
		}
		return true
	}
	return e.match(matcher)
}

func (e *Engine) MatchOpen(evt OpenEvent) MatchResult {
	matcher := func(r compiledRule) bool {
		if r.comm != nil && !r.comm.MatchString(evt.Comm) {
			return false
		}
		if r.path != nil && !r.path.MatchString(evt.Path) {
			return false
		}
		if len(r.uids) > 0 {
			if _, ok := r.uids[int(evt.UID)]; !ok {
				return false
			}
		}
		return true
	}
	return e.match(matcher)
}

func (e *Engine) MatchConnect(evt ConnectEvent) MatchResult {
	ipString := ""
	switch evt.Family {
	case uint16(syscall.AF_INET):
		raw := []byte{byte(evt.DaddrV4 >> 24), byte(evt.DaddrV4 >> 16), byte(evt.DaddrV4 >> 8), byte(evt.DaddrV4)}
		ipString = net.IP(raw).String()
	case uint16(syscall.AF_INET6):
		ipString = net.IP(evt.DaddrV6[:]).String()
	}
	matcher := func(r compiledRule) bool {
		if r.comm != nil && !r.comm.MatchString(evt.Comm) {
			return false
		}
		if len(r.uids) > 0 {
			if _, ok := r.uids[int(evt.UID)]; !ok {
				return false
			}
		}
		if len(r.ports) > 0 {
			if _, ok := r.ports[int(evt.Dport)]; !ok {
				return false
			}
		}
		if r.ip != nil {
			if ipString == "" || !r.ip.MatchString(ipString) {
				return false
			}
		}
		return true
	}
	return e.match(matcher)
}

func (e *Engine) match(fn func(compiledRule) bool) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, action := range actionOrder {
		rules := e.rules[action]
		for _, r := range rules {
			if fn(r) {
				return MatchResult{Matched: true, RuleName: r.name, Action: r.action, Reason: r.reason}
			}
		}
	}
	return MatchResult{Matched: false, Action: ActionObserve}
}

func loadFile(path string) (map[Action][]compiledRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []fileRule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	rules := make(map[Action][]compiledRule)
	for _, action := range actionOrder {
		rules[action] = []compiledRule{}
	}
	for i, fr := range raw {
		action := parseAction(fr.Action)
		cr, err := compileRule(fr, action)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, fr.Name, err)
		}
		rules[action] = append(rules[action], cr)
	}
	return rules, nil
}

func parseAction(raw string) Action {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "allow":
		return ActionAllow
	case "deny":
		return ActionDeny
	case "alert":
		return ActionAlert
	case "observe", "":
		return ActionObserve
	default:
		return Action(v)
	}
}

func compileRule(fr fileRule, action Action) (compiledRule, error) {
	if fr.Name == "" {
		return compiledRule{}, errors.New("missing name")
	}
	switch action {
	case ActionAllow, ActionDeny, ActionAlert, ActionObserve:
	default:
		return compiledRule{}, fmt.Errorf("unknown action %q", action)
	}
	cr := compiledRule{
		name:   fr.Name,
		action: action,
		reason: fr.Reason,
		ports:  map[int]struct{}{},
		uids:   map[int]struct{}{},
	}
	if fr.Match.CommRE != "" {
		re, err := regexp.Compile(fr.Match.CommRE)
		if err != nil {
			return compiledRule{}, fmt.Errorf("comm_re: %w", err)
		}
		cr.comm = re
	}
	if fr.Match.PathRE != "" {
		re, err := regexp.Compile(fr.Match.PathRE)
		if err != nil {
			return compiledRule{}, fmt.Errorf("path_re: %w", err)
		}
		cr.path = re
	}
	if fr.Match.IPRE != "" {
		re, err := regexp.Compile(fr.Match.IPRE)
		if err != nil {
			return compiledRule{}, fmt.Errorf("ip_re: %w", err)
		}
		cr.ip = re
	}
	for _, p := range fr.Match.PortIn {
		cr.ports[p] = struct{}{}
	}
	for _, u := range fr.Match.UIDIn {
		cr.uids[u] = struct{}{}
	}
	return cr, nil
}
