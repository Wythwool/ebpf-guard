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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/wythwool/ebpf-guard/internal/exporter"
	"github.com/wythwool/ebpf-guard/internal/rules"
)

type ExecEvt struct {
	Ts       uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Comm     [16]byte
	Filename [512]byte
}
type OpenEvt struct {
	Ts   uint64
	Pid  uint32
	Uid  uint32
	Flags int32
	Comm [16]byte
	Path [512]byte
}
type ConnEvt struct {
	Ts      uint64
	Pid     uint32
	Uid     uint32
	Family  uint16
	Dport   uint16
	DaddrV4 uint32
	DaddrV6 [16]byte
	Comm    [16]byte
}

func cstr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 { n = len(b) }
	return string(b[:n])
}

func must[T any](v T, err error) T {
	if err != nil { log.Fatal(err) }
	return v
}

func loadAndAttach(fp string, sec string, progName string) (*ebpf.Collection, link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(fp)
	if err != nil { return nil, nil, fmt.Errorf("load spec %s: %w", fp, err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { return nil, nil, fmt.Errorf("new collection: %w", err) }
	prog := coll.Programs[progName]
	if prog == nil { coll.Close(); return nil, nil, fmt.Errorf("program %q not found", progName) }
	l, err := link.Tracepoint(sec[:bytes.IndexByte([]byte(sec), '/')], sec[bytes.IndexByte([]byte(sec), '/')+1:], prog, nil)
	if err != nil { coll.Close(); return nil, nil, fmt.Errorf("attach tracepoint %s: %w", sec, err) }
	return coll, l, nil
}

func main() {
	var (
		rulesPath = flag.String("rules", "configs/rules.sample.yaml", "rules yaml path")
		listen    = flag.String("listen", ":9108", "http listen addr")
		enableJSON= flag.Bool("json", true, "enable /events stream")
		enableProm= flag.Bool("prom", true, "enable /metrics")
		dryRun    = flag.Bool("dry-run", false, "do not load BPF, only HTTP")
		logLevel  = flag.String("log", "info", "info|warn|error")
	)
	flag.Parse()
	log.SetFlags(0)

	m := exporter.NewMetrics()

	// Rules
	set := must(rules.Compile(*rulesPath,))

	// Reload on SIGHUP
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if s, err := rules.Compile(*rulesPath); err == nil {
				set = s
				log.Printf("rules reloaded")
			} else {
				log.Printf("rules reload error: %v", err)
			}
		}
	}()

	eventsCh := make(chan any, 4096)
	defer close(eventsCh)

	// HTTP
	mux := http.NewServeMux()
	if *enableProm {
		mux.Handle("/metrics", promhttp.Handler())
	}
	if *enableJSON {
		mux.Handle("/events", exporter.NewStream(eventsCh))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{ Addr: *listen, Handler: mux }

	go func(){
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()
	log.Printf("listening on %s", *listen)

	// Attach sensors
	var (
		cExec *ebpf.Collection
		cOpen *ebpf.Collection
		cConn *ebpf.Collection
		lExec link.Link
		lOpen link.Link
		lConn link.Link
		rExec *ringbuf.Reader
		rOpen *ringbuf.Reader
		rConn *ringbuf.Reader
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !*dryRun {
		// Build artifacts expected at build/*.o
		execObj := filepath.Join("build","exec.o")
		openObj := filepath.Join("build","open.o")
		connObj := filepath.Join("build","connect.o")

		var err error
		cExec, lExec, err = loadAndAttach(execObj, "sched/sched_process_exec", "tp_exec")
		if err != nil { log.Fatalf("exec attach: %v", err) }
		cOpen, lOpen, err = loadAndAttach(openObj, "syscalls/sys_enter_openat", "tp_open")
		if err != nil { log.Fatalf("open attach: %v", err) }
		cConn, lConn, err = loadAndAttach(connObj, "syscalls/sys_enter_connect", "tp_connect")
		if err != nil { log.Fatalf("connect attach: %v", err) }

		// Ringbuffers
		if mapp := cExec.Maps["events_exec"]; mapp != nil {
			rExec, err = ringbuf.NewReader(mapp)
			if err == nil { go readExec(ctx, rExec, set, m, eventsCh) }
		}
		if mapp := cOpen.Maps["events_open"]; mapp != nil {
			rOpen, err = ringbuf.NewReader(mapp)
			if err == nil { go readOpen(ctx, rOpen, set, m, eventsCh) }
		}
		if mapp := cConn.Maps["events_connect"]; mapp != nil {
			rConn, err = ringbuf.NewReader(mapp)
			if err == nil { go readConn(ctx, rConn, set, m, eventsCh) }
		}

		m.SensorsAttached.WithLabelValues("exec").Set(1)
		m.SensorsAttached.WithLabelValues("open").Set(1)
		m.SensorsAttached.WithLabelValues("connect").Set(1)
	} else {
		log.Printf("dry-run: sensors not attached")
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	if rExec != nil { rExec.Close() }
	if rOpen != nil { rOpen.Close() }
	if rConn != nil { rConn.Close() }
	if lExec != nil { _ = lExec.Close() }
	if lOpen != nil { _ = lOpen.Close() }
	if lConn != nil { _ = lConn.Close() }
	if cExec != nil { cExec.Close() }
	if cOpen != nil { cOpen.Close() }
	if cConn != nil { cConn.Close() }
}

func readExec(ctx context.Context, r *ringbuf.Reader, set *rules.Set, m *exporter.Metrics, out chan<- any) {
	var ev ExecEvt
	for {
		rec, err := r.Read()
		if err != nil {
			if ctx.Err()!=nil { return }
			continue
		}
		if len(rec.RawSample) < binary.Size(ev) { rec.Done(); continue }
		_ = binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev)
		rec.Done()
		meta := rules.EventMeta{Type:"exec", Comm:cstr(ev.Comm[:]), Path:cstr(ev.Filename[:]), UID:int(ev.Uid)}
		dec := set.Decide(meta)
		m.EventsTotal.WithLabelValues("exec").Inc()
		if dec.Matched { m.RuleMatchesTotal.WithLabelValues(dec.Rule, dec.Action).Inc() }
		out <- map[string]any{
			"type":"exec","pid":ev.Pid,"ppid":ev.Ppid,"uid":ev.Uid,"comm":meta.Comm,"filename":meta.Path,
			"decision": dec,
		}
	}
}

func readOpen(ctx context.Context, r *ringbuf.Reader, set *rules.Set, m *exporter.Metrics, out chan<- any) {
	var ev OpenEvt
	for {
		rec, err := r.Read()
		if err != nil {
			if ctx.Err()!=nil { return }
			continue
		}
		if len(rec.RawSample) < binary.Size(ev) { rec.Done(); continue }
		_ = binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev)
		rec.Done()
		meta := rules.EventMeta{Type:"open", Comm:cstr(ev.Comm[:]), Path:cstr(ev.Path[:]), UID:int(ev.Uid)}
		dec := set.Decide(meta)
		m.EventsTotal.WithLabelValues("open").Inc()
		if dec.Matched { m.RuleMatchesTotal.WithLabelValues(dec.Rule, dec.Action).Inc() }
		out <- map[string]any{
			"type":"open","pid":ev.Pid,"uid":ev.Uid,"comm":meta.Comm,"path":meta.Path,"flags":ev.Flags,
			"decision": dec,
		}
	}
}

func ipString(fam uint16, v4 uint32, v6 [16]byte) string {
	if fam == syscall.AF_INET {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, v4)
		return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
	}
	return net.IP(v6[:]).String()
}

func readConn(ctx context.Context, r *ringbuf.Reader, set *rules.Set, m *exporter.Metrics, out chan<- any) {
	var ev ConnEvt
	for {
		rec, err := r.Read()
		if err != nil {
			if ctx.Err()!=nil { return }
			continue
		}
		if len(rec.RawSample) < binary.Size(ev) { rec.Done(); continue }
		_ = binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev)
		rec.Done()
		ip := ipString(ev.Family, ev.DaddrV4, ev.DaddrV6)
		meta := rules.EventMeta{Type:"connect", Comm:cstr(ev.Comm[:]), IP:ip, Port:int(ev.Dport), UID:int(ev.Uid)}
		dec := set.Decide(meta)
		m.EventsTotal.WithLabelValues("connect").Inc()
		if dec.Matched { m.RuleMatchesTotal.WithLabelValues(dec.Rule, dec.Action).Inc() }
		out <- map[string]any{
			"type":"connect","pid":ev.Pid,"uid":ev.Uid,"comm":meta.Comm,"ip":ip,"port":ev.Dport,
			"decision": dec,
		}
	}
}
