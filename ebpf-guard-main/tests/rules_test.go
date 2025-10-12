package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wythwool/ebpf-guard/internal/rules"
)

func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return path
}

func TestExecRulePriority(t *testing.T) {
	cfg := `- name: allow_nc
  match:
    comm_re: "^nc$"
  action: allow
- name: deny_nc
  match:
    comm_re: "^nc$"
  action: deny
`
	path := writeRules(t, cfg)
	engine, err := rules.NewEngineFromFile(path)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	res := engine.MatchExec(rules.ExecEvent{Comm: "nc", Filename: "/bin/nc"})
	if !res.Matched {
		t.Fatalf("expected match")
	}
	if res.Action != rules.ActionDeny {
		t.Fatalf("expected deny, got %s", res.Action)
	}
	if res.RuleName != "deny_nc" {
		t.Fatalf("unexpected rule %s", res.RuleName)
	}
}

func TestConnectRuleMatch(t *testing.T) {
	cfg := `- name: block_port
  match:
    comm_re: "^curl$"
    port_in: [443]
    ip_re: "^1\\.1\\.1\\.1$"
  action: alert
`
	path := writeRules(t, cfg)
	engine, err := rules.NewEngineFromFile(path)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	evt := rules.ConnectEvent{
		Comm:    "curl",
		Family:  2,
		Dport:   443,
		DaddrV4: 0x01010101,
	}
	res := engine.MatchConnect(evt)
	if !res.Matched {
		t.Fatalf("expected match")
	}
	if res.Action != rules.ActionAlert {
		t.Fatalf("expected alert, got %s", res.Action)
	}
	if res.RuleName != "block_port" {
		t.Fatalf("unexpected rule %s", res.RuleName)
	}
}

func TestObserveWhenNoMatch(t *testing.T) {
	cfg := `- name: observe_all
  action: observe
`
	path := writeRules(t, cfg)
	engine, err := rules.NewEngineFromFile(path)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	res := engine.MatchOpen(rules.OpenEvent{Comm: "bash", Path: "/tmp/file"})
	if !res.Matched {
		t.Fatalf("expected match")
	}
	if res.Action != rules.ActionObserve {
		t.Fatalf("expected observe, got %s", res.Action)
	}
}
