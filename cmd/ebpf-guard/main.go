package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"gopkg.in/yaml.v3"
)

// Events must align with C structs
type ExecEvt struct {
	Ts       uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}
type OpenEvt struct {
	Ts    uint64
	Pid   uint32
	Uid   uint32
	Flags int32
	Comm  [16]byte
	Path  [256]byte
}
type ConnEvt struct {
	Ts       uint64
	Pid      uint32
	Uid      uint32
	Family   uint16
	Dport    uint16
	DaddrV4  uint32
	Comm     [16]byte
}

type Rule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`   // exec|open|connect|any
	CommRe   string   `yaml:"proc_comm_re"`
	PathRe   string   `yaml:"path_re"`
	ArgvRe   string   `yaml:"argv_re"` // not populated in MVP, reserved
	PortIn   []int    `yaml:"port_in"`
	IPRe     string   `yaml:"ip_re"`
	UIDIn    []int    `yaml:"uid_in"`
}

type compiledRule struct {
	r Rule
	comm *regexp.Regexp
	path *regexp.Regexp
	ip   *regexp.Regexp
	portset map[int]struct{}
	uidset  map[int]struct{}
}

func b2s(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 { i = len(b) }
	return string(b[:i])
}

// minimal metrics
var (
	eventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ebg", Name: "events_total", Help: "events"},
		[]string{"type"})
	alertsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ebg", Name: "alerts_total", Help: "alerts"},
		[]string{"rule","type"})
)

func mustRegister() {
	prometheus.MustRegister(eventsTotal, alertsTotal)
}

func loadObj(path string) (*ebpf.CollectionSpec, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	return spec, err
}

func attachTracepoint(coll *ebpf.Collection, cat, name string, progName string) (link.Link, error) {
	prog := coll.Programs[progName]
	if prog == nil { return nil, fmt.Errorf("program not found: %s", progName) }
	return link.Tracepoint(cat, name, prog, nil)
}

func compileRules(path string) ([]compiledRule, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var rs []Rule
	if err := yaml.Unmarshal(b, &rs); err != nil { return nil, err }
	out := make([]compiledRule, 0, len(rs))
	for _, r := range rs {
		cr := compiledRule{r: r, portset: map[int]struct{}{}, uidset: map[int]struct{}{}}
		if r.CommRe != "" { cr.comm = regexp.MustCompile(r.CommRe) }
		if r.PathRe != "" { cr.path = regexp.MustCompile(r.PathRe) }
		if r.IPRe   != "" { cr.ip   = regexp.MustCompile(r.IPRe) }
		for _, p := range r.PortIn { cr.portset[p]=struct{}{} }
		for _, u := range r.UIDIn  { cr.uidset[u]=struct{}{} }
		out = append(out, cr)
	}
	return out, nil
}

func (cr compiledRule) matchExec(e ExecEvt) bool {
	if cr.r.Type != "" && cr.r.Type != "exec" && cr.r.Type != "any" { return false }
	if cr.comm != nil && !cr.comm.MatchString(b2s(e.Comm[:])) { return false }
	if cr.path != nil && !cr.path.MatchString(b2s(e.Filename[:])) { return false }
	if len(cr.uidset)>0 { if _,ok:=cr.uidset[int(e.Uid)]; !ok { return false } }
	return true
}
func (cr compiledRule) matchOpen(e OpenEvt) bool {
	if cr.r.Type != "" && cr.r.Type != "open" && cr.r.Type != "any" { return false }
	if cr.comm != nil && !cr.comm.MatchString(b2s(e.Comm[:])) { return false }
	if cr.path != nil && !cr.path.MatchString(b2s(e.Path[:])) { return false }
	if len(cr.uidset)>0 { if _,ok:=cr.uidset[int(e.Uid)]; !ok { return false } }
	return true
}
func (cr compiledRule) matchConn(e ConnEvt) bool {
	if cr.r.Type != "" && cr.r.Type != "connect" && cr.r.Type != "any" { return false }
	if cr.comm != nil && !cr.comm.MatchString(b2s(e.Comm[:])) { return false }
	if len(cr.uidset)>0 { if _,ok:=cr.uidset[int(e.Uid)]; !ok { return false } }
	if len(cr.portset)>0 { if _,ok:=cr.portset[int(e.Dport)]; !ok { return false } }
	if cr.ip != nil {
		ip := net.IPv4(byte(e.DaddrV4), byte(e.DaddrV4>>8), byte(e.DaddrV4>>16), byte(e.DaddrV4>>24)).String()
		if !cr.ip.MatchString(ip) { return false }
	}
	return true
}

type alert struct {
	Time   string `json:"time"`
	Type   string `json:"type"`
	RuleID string `json:"rule_id"`
	Rule   string `json:"rule"`
	Pid    uint32 `json:"pid"`
	Uid    uint32 `json:"uid"`
	Comm   string `json:"comm"`
	Detail any    `json:"detail"`
}

func emitAlert(w *os.File, a alert) {
	j,_ := json.Marshal(a)
	fmt.Fprintln(w, string(j))
	alertsTotal.WithLabelValues(a.RuleID, a.Type).Inc()
}

func main() {
	var rulesPath, addr, jsonOut, bpfDir string
	flag.StringVar(&rulesPath, "rules", "./rules/default_rules.yaml", "rules yaml")
	flag.StringVar(&addr, "addr", ":9100", "prometheus listen addr")
	flag.StringVar(&jsonOut, "json-out", "", "write alerts to file")
	flag.StringVar(&bpfDir, "bpf-dir", "./build", "dir with bpf .o objects")
	flag.Parse()

	mustRegister()
	http.Handle("/metrics", promhttp.Handler())
	go func(){
		log.Printf("metrics %s", addr)
		log.Fatal(http.ListenAndServe(addr, nil))
	}()

	rules, err := compileRules(rulesPath)
	if err != nil { log.Fatalf("rules: %v", err) }
	var outFile *os.File = os.Stdout
	if jsonOut != "" {
		outFile, err = os.OpenFile(jsonOut, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil { log.Fatalf("json-out: %v", err) }
	}

	// load BPF objs
	load := func(name string) (*ebpf.Collection, error) {
		spec, err := loadObj(filepath.Join(bpfDir, name))
		if err != nil { return nil, err }
		coll, err := ebpf.NewCollection(spec)
		if err != nil { return nil, err }
		return coll, nil
	}

	execColl, err := load("exec.bpf.o")
	if err != nil { log.Fatalf("load exec: %v", err) }
	openColl, err := load("open.bpf.o")
	if err != nil { log.Fatalf("load open: %v", err) }
	connColl, err := load("connect.bpf.o")
	if err != nil { log.Fatalf("load connect: %v", err) }

	links := []link.Link{}
	defer func(){ for _,l := range links { l.Close() } }()

	lx, err := attachTracepoint(execColl, "sched", "sched_process_exec", "tp_exec")
	if err != nil { log.Fatalf("attach exec: %v", err) }
	links = append(links, lx)
	lo, err := attachTracepoint(openColl, "syscalls", "sys_enter_openat", "tp_open")
	if err != nil { log.Fatalf("attach open: %v", err) }
	links = append(links, lo)
	lc, err := attachTracepoint(connColl, "syscalls", "sys_enter_connect", "tp_connect")
	if err != nil { log.Fatalf("attach connect: %v", err) }
	links = append(links, lc)

	rxExec, err := ringbuf.NewReader(execColl.Maps["events_exec"])
	if err != nil { log.Fatalf("ring exec: %v", err) }
	defer rxExec.Close()
	rxOpen, err := ringbuf.NewReader(openColl.Maps["events_open"])
	if err != nil { log.Fatalf("ring open: %v", err) }
	defer rxOpen.Close()
	rxConn, err := ringbuf.NewReader(connColl.Maps["events_connect"])
	if err != nil { log.Fatalf("ring connect: %v", err) }
	defer rxConn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handleExec := func(e ExecEvt){
		eventsTotal.WithLabelValues("exec").Inc()
		for _, r := range rules {
			if r.matchExec(e) {
				emitAlert(outFile, alert{
					Time: time.Now().UTC().Format(time.RFC3339Nano),
					Type: "exec", RuleID: r.r.ID, Rule: r.r.Name,
					Pid: e.Pid, Uid: e.Uid, Comm: b2s(e.Comm[:]),
					Detail: map[string]any{"filename": b2s(e.Filename[:])},
				})
			}
		}
	}
	handleOpen := func(e OpenEvt){
		eventsTotal.WithLabelValues("open").Inc()
		for _, r := range rules {
			if r.matchOpen(e) {
				emitAlert(outFile, alert{
					Time: time.Now().UTC().Format(time.RFC3339Nano),
					Type: "open", RuleID: r.r.ID, Rule: r.r.Name,
					Pid: e.Pid, Uid: e.Uid, Comm: b2s(e.Comm[:]),
					Detail: map[string]any{"path": b2s(e.Path[:]), "flags": e.Flags},
				})
			}
		}
	}
	handleConn := func(e ConnEvt){
		eventsTotal.WithLabelValues("connect").Inc()
		var ip string
		if e.Family == 2 {
			ip = net.IPv4(byte(e.DaddrV4), byte(e.DaddrV4>>8), byte(e.DaddrV4>>16), byte(e.DaddrV4>>24)).String()
		}
		for _, r := range rules {
			if r.matchConn(e) {
				emitAlert(outFile, alert{
					Time: time.Now().UTC().Format(time.RFC3339Nano),
					Type: "connect", RuleID: r.r.ID, Rule: r.r.Name,
					Pid: e.Pid, Uid: e.Uid, Comm: b2s(e.Comm[:]),
					Detail: map[string]any{"dport": e.Dport, "ip": ip},
				})
			}
		}
	}

	// readers
	go func(){
		var e ExecEvt
		for {
			rec, err := rxExec.Read()
			if err != nil { if ctx.Err()!=nil { return }; continue }
			buf := bytes.NewReader(rec.RawSample); _ = binary.Read(buf, binary.LittleEndian, &e)
			rec.Done()
			handleExec(e)
		}
	}()
	go func(){
		var e OpenEvt
		for {
			rec, err := rxOpen.Read()
			if err != nil { if ctx.Err()!=nil { return }; continue }
			buf := bytes.NewReader(rec.RawSample); _ = binary.Read(buf, binary.LittleEndian, &e)
			rec.Done()
			handleOpen(e)
		}
	}()
	go func(){
		var e ConnEvt
		for {
			rec, err := rxConn.Read()
			if err != nil { if ctx.Err()!=nil { return }; continue }
			buf := bytes.NewReader(rec.RawSample); _ = binary.Read(buf, binary.LittleEndian, &e)
			rec.Done()
			handleConn(e)
		}
	}()

	<-ctx.Done()
}
