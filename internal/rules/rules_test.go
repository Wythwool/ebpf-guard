package rules

import "testing"

func TestDecideOrder(t *testing.T) {
	cfg := []byte(`
- name: d1
  match: { comm_re: "^evil$" }
  action: deny
- name: a1
  match: { comm_re: "^evil$" }
  action: allow
- name: al1
  match: { comm_re: "^evil$" }
  action: alert
`)
	tmp := t.TempDir() + "/r.yaml"
	if err := os.WriteFile(tmp, cfg, 0644); err != nil { t.Fatal(err) }
	set, err := Compile(tmp)
	if err != nil { t.Fatal(err) }
	dec := set.Decide(EventMeta{Type:"exec", Comm:"evil"})
	if !dec.Matched || dec.Action!="deny" || dec.Rule!="d1" { t.Fatalf("bad decide: %+v", dec) }
}
