package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/wythwool/ebpf-guard/internal/exporter"
	"github.com/wythwool/ebpf-guard/internal/rules"
)

type execEvent struct {
	Ts       uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Comm     [16]byte
	Filename [512]byte
}

type openEvent struct {
	Ts    uint64
	Pid   uint32
	Uid   uint32
	Flags int32
	Comm  [16]byte
	Path  [512]byte
}

type connectEvent struct {
	Ts      uint64
	Pid     uint32
	Uid     uint32
	Family  uint16
	Dport   uint16
	DaddrV4 uint32
	DaddrV6 [16]byte
	Comm    [16]byte
}

type sensorSpec struct {
	name     string
	object   string
	prog     string
	category string
	point    string
	ring     string
}

type sensorRuntime struct {
	spec   sensorSpec
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader
}

const (
	defaultListenAddr = ":9108"
	defaultRulesPath  = "configs/rules.sample.yaml"
)

const sampleRules = `- name: "block_netcat"
  match:
    comm_re: "^nc$"
    port_in: [4444, 5555]
  action: deny
  reason: "nc to forbidden ports"

- name: "alert_sensitive_open"
  match:
    path_re: "^/etc/(shadow|passwd)$"
    uid_in: [0]
  action: alert
  reason: "root reading sensitive file"

- name: "allow_package_mgr"
  match:
    comm_re: "^(apt|dnf|yum|pacman)$"
  action: allow
`

type logLevel int

const (
	levelInfo logLevel = iota
	levelWarn
	levelError
)

type logger struct {
	lvl logLevel
}

func newLogger(level string) *logger {
	switch strings.ToLower(level) {
	case "info":
		return &logger{lvl: levelInfo}
	case "warn":
		return &logger{lvl: levelWarn}
	case "error":
		return &logger{lvl: levelError}
	default:
		return &logger{lvl: levelInfo}
	}
}

func (l *logger) logf(target logLevel, format string, args any) {
	if target < l.lvl {
		return
	}
	prefix := "INFO"
	switch target {
	case levelWarn:
		prefix = "WARN"
	case levelError:
		prefix = "ERROR"
	}
	fmt.Fprintf(os.Stderr, "%s %s %s\n", time.Now().UTC().Format(time.RFC3339Nano), prefix, fmt.Sprintf(format, args))
}

func (l *logger) Infof(format string, args any) {
	l.logf(levelInfo, format, args)
}

func (l *logger) Warnf(format string, args any) {
	l.logf(levelWarn, format, args)
}

func (l *logger) Errorf(format string, args any) {
	l.logf(levelError, format, args)
}

type outputEvent struct {
	Timestamp time.Time      `json:"ts"`
	Type      string         `json:"type"`
	PID       uint32         `json:"pid"`
	UID       uint32         `json:"uid"`
	Comm      string         `json:"comm"`
	PPID      uint32         `json:"ppid,omitempty"`
	Data      map[string]any `json:"data"`
	Rule      string         `json:"rule,omitempty"`
	Action    string         `json:"action"`
	Reason    string         `json:"reason,omitempty"`
}

func ensureSampleRules(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if path != defaultRulesPath {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sampleRules), 0o644)
}

func cString(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		return string(buf[:i])
	}
	return string(bytes.TrimRight(buf, "\x00"))
}

func ipv4String(raw uint32) string {
	b := []byte{byte(raw >> 24), byte(raw >> 16), byte(raw >> 8), byte(raw)}
	return net.IP(b).String()
}

func ipv6String(raw [16]byte) string {
	return net.IP(raw[:]).String()
}

func runSensors(ctx context.Context, specs []sensorSpec, log *logger, metrics *exporter.Metrics, engine *rules.Engine, stream *exporter.Stream) ([]*sensorRuntime, error) {
	runtimes := make([]*sensorRuntime, 0, len(specs))

	for _, spec := range specs {
		coll, reader, lk, err := attachSensor(spec, metrics, log)
		if err != nil {
			for _, rt := range runtimes {
				rt.reader.Close()
				rt.link.Close()
				rt.coll.Close()
			}
			return nil, err
		}
		metrics.SetSensorAttached(spec.name, 1)
		rt := &sensorRuntime{spec: spec, coll: coll, link: lk, reader: reader}
		runtimes = append(runtimes, rt)
		go consumeSensor(ctx, rt, engine, stream, metrics, log)
	}
	return runtimes, nil
}

func attachSensor(spec sensorSpec, metrics *exporter.Metrics, log *logger) (*ebpf.Collection, *ringbuf.Reader, link.Link, error) {
	objPath := filepath.Join("build", spec.object)
	coll, err := loadCollection(objPath)
	if err != nil {
		metrics.IncAttachError(spec.name)
		return nil, nil, nil, fmt.Errorf("load %s: %w", spec.name, err)
	}
	prog := coll.Programs[spec.prog]
	if prog == nil {
		coll.Close()
		metrics.IncAttachError(spec.name)
		return nil, nil, nil, fmt.Errorf("program %s missing", spec.prog)
	}
	lk, err := link.Tracepoint(spec.category, spec.point, prog, nil)
	if err != nil {
		coll.Close()
		metrics.IncAttachError(spec.name)
		return nil, nil, nil, fmt.Errorf("attach %s: %w", spec.name, err)
	}
	reader, err := ringbuf.NewReader(coll.Maps[spec.ring])
	if err != nil {
		lk.Close()
		coll.Close()
		metrics.IncAttachError(spec.name)
		return nil, nil, nil, fmt.Errorf("ringbuf %s: %w", spec.name, err)
	}
	log.Infof("sensor %s attached", spec.name)
	return coll, reader, lk, nil
}

func loadCollection(path string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	return ebpf.NewCollection(spec)
}

func consumeSensor(ctx context.Context, rt *sensorRuntime, engine *rules.Engine, stream *exporter.Stream, metrics *exporter.Metrics, log *logger) {
	defer metrics.SetSensorAttached(rt.spec.name, 0)
	defer rt.reader.Close()
	defer rt.link.Close()
	defer rt.coll.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			rt.reader.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		record, err := rt.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			log.Warnf("sensor %s read: %v", rt.spec.name, err)
			continue
		}
		if record.LostSamples > 0 {
			metrics.AddRingbufDropped(rt.spec.name, record.LostSamples)
			record.Done()
			continue
		}
		data := make([]byte, len(record.RawSample))
		copy(data, record.RawSample)
		record.Done()
		handleSample(data, rt.spec.name, engine, stream, metrics, log)
		if ctx.Err() != nil {
			return
		}
	}
}

func handleSample(data []byte, sensor string, engine *rules.Engine, stream *exporter.Stream, metrics *exporter.Metrics, log *logger) {
	switch sensor {
	case "exec":
		var evt execEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			log.Warnf("decode exec: %v", err)
			return
		}
		metrics.IncEvent("exec")
		result := engine.MatchExec(rules.ExecEvent{
			Timestamp: evt.Ts,
			PID:       evt.Pid,
			PPID:      evt.Ppid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			Filename:  cString(evt.Filename[:]),
		})
		emitOutput(stream, metrics, log, result, outputEvent{
			Timestamp: time.Unix(0, int64(evt.Ts)),
			Type:      "exec",
			PID:       evt.Pid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			PPID:      evt.Ppid,
			Data: map[string]any{
				"filename": cString(evt.Filename[:]),
			},
		})
	case "open":
		var evt openEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			log.Warnf("decode open: %v", err)
			return
		}
		metrics.IncEvent("open")
		result := engine.MatchOpen(rules.OpenEvent{
			Timestamp: evt.Ts,
			PID:       evt.Pid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			Path:      cString(evt.Path[:]),
			Flags:     int(evt.Flags),
		})
		emitOutput(stream, metrics, log, result, outputEvent{
			Timestamp: time.Unix(0, int64(evt.Ts)),
			Type:      "open",
			PID:       evt.Pid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			Data: map[string]any{
				"path":  cString(evt.Path[:]),
				"flags": evt.Flags,
			},
		})
	case "connect":
		var evt connectEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			log.Warnf("decode connect: %v", err)
			return
		}
		metrics.IncEvent("connect")
		destIP := ""
		if evt.Family == uint16(syscall.AF_INET) {
			destIP = ipv4String(evt.DaddrV4)
		} else if evt.Family == uint16(syscall.AF_INET6) {
			destIP = ipv6String(evt.DaddrV6)
		}
		result := engine.MatchConnect(rules.ConnectEvent{
			Timestamp: evt.Ts,
			PID:       evt.Pid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			Family:    evt.Family,
			Dport:     evt.Dport,
			DaddrV4:   evt.DaddrV4,
			DaddrV6:   evt.DaddrV6,
		})
		emitOutput(stream, metrics, log, result, outputEvent{
			Timestamp: time.Unix(0, int64(evt.Ts)),
			Type:      "connect",
			PID:       evt.Pid,
			UID:       evt.Uid,
			Comm:      cString(evt.Comm[:]),
			Data: map[string]any{
				"family": evt.Family,
				"dport":  evt.Dport,
				"ip":     destIP,
			},
		})
	}
}

func emitOutput(stream *exporter.Stream, metrics *exporter.Metrics, log *logger, result rules.MatchResult, evt outputEvent) {
	evt.Action = string(result.Action)
	if result.Matched {
		evt.Rule = result.RuleName
		evt.Reason = result.Reason
		metrics.IncRuleMatch(result.RuleName, string(result.Action))
		if result.Action == rules.ActionDeny || result.Action == rules.ActionAlert {
			log.Warnf("%s action=%s rule=%s reason=%s pid=%d", evt.Type, result.Action, result.RuleName, result.Reason, evt.PID)
		}
	}
	if stream != nil {
		if data, err := json.Marshal(evt); err == nil {
			stream.Publish(data)
		} else {
			log.Warnf("marshal %s: %v", evt.Type, err)
		}
	}
}

func main() {
	var (
		rulesPath  string
		listenAddr string
		enableJSON bool
		enableProm bool
		dryRun     bool
		logLevel   string
	)

	flag.StringVar(&rulesPath, "rules", defaultRulesPath, "rules file path")
	flag.StringVar(&listenAddr, "listen", defaultListenAddr, "http listen address")
	flag.BoolVar(&enableJSON, "json", false, "enable /events JSON stream")
	flag.BoolVar(&enableProm, "prom", true, "enable /metrics endpoint")
	flag.BoolVar(&dryRun, "dry-run", false, "skip eBPF loading")
	flag.StringVar(&logLevel, "log", "info", "log level (info|warn|error)")
	flag.Parse()

	log := newLogger(logLevel)
	log.Infof("ebpf-guard %s starting", version)

	if err := ensureSampleRules(rulesPath); err != nil {
		log.Errorf("rules init: %v", err)
		os.Exit(1)
	}

	engine, err := rules.NewEngineFromFile(rulesPath)
	if err != nil {
		log.Errorf("load rules: %v", err)
		os.Exit(1)
	}

	reg := prometheus.DefaultRegisterer
	metrics := exporter.NewMetrics(reg)

	var stream *exporter.Stream
	if enableJSON {
		stream = exporter.NewStream()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if enableProm {
		mux.Handle("/metrics", promhttp.Handler())
	} else {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	if enableJSON && stream != nil {
		mux.Handle("/events", stream)
	} else {
		mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	srv := &http.Server{Addr: listenAddr, Handler: mux}
	srvErr := make(chan error, 1)
	go func() {
		log.Infof("http listen %s", listenAddr)
		srvErr <- srv.ListenAndServe()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if dryRun {
		log.Warnf("dry-run enabled, skipping eBPF attach")
	} else {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Errorf("set rlimit: %v", err)
			os.Exit(1)
		}
	}

	specs := []sensorSpec{
		{name: "exec", object: "exec.bpf.o", prog: "handle_exec", category: "sched", point: "sched_process_exec", ring: "events_exec"},
		{name: "open", object: "open.bpf.o", prog: "handle_open", category: "syscalls", point: "sys_enter_openat", ring: "events_open"},
		{name: "connect", object: "connect.bpf.o", prog: "handle_connect", category: "syscalls", point: "sys_enter_connect", ring: "events_connect"},
	}

	for _, spec := range specs {
		metrics.SetSensorAttached(spec.name, 0)
	}

	var runtimes []*sensorRuntime
	if !dryRun {
		runtimes, err = runSensors(ctx, specs, log, metrics, engine, stream)
		if err != nil {
			log.Errorf("sensor setup: %v", err)
			os.Exit(1)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				log.Infof("reload rules")
				if err := engine.Reload(rulesPath); err != nil {
					log.Errorf("reload rules: %v", err)
				} else {
					log.Infof("rules reloaded")
				}
			case syscall.SIGINT, syscall.SIGTERM:
				cancel()
				if !dryRun {
					for _, rt := range runtimes {
						metrics.SetSensorAttached(rt.spec.name, 0)
					}
				}
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = srv.Shutdown(shutdownCtx)
				shutdownCancel()
				return
			}
		case err := <-srvErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Errorf("http server: %v", err)
			}
			return
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutdownCtx)
			shutdownCancel()
			return
		}
	}
}
