package sig

import "testing"

func TestConvertNuclei(t *testing.T) {
	tpl := `id: grafana-detect
info:
  name: Grafana Login Panel
  severity: info
  tags: panel,grafana
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "grafana-app"
      - type: status
        status:
          - 200
---
id: post-thing
info:
  name: Exploit
  severity: high
http:
  - method: POST
    path: ["{{BaseURL}}/x"]
    body: "a=b"
    matchers:
      - type: word
        words: ["ok"]
`
	r, err := Convert([]byte(tpl), "t.yaml")
	if err != nil || r.Format != "nuclei" || len(r.Signatures) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	m := r.Signatures[0].Matchers[0]
	if m.Type != "path" || m.Path != "/login" || len(m.Status) != 1 || r.Signatures[0].Category != "admin-panel" {
		t.Fatalf("%+v", r.Signatures[0])
	}
	if r.Skipped != 1 {
		t.Fatalf("POST powinien być pominięty: %+v", r)
	}
	in := Input{PathHits: map[string]PathResponse{"/login": {Status: 200, Body: `<div class="grafana-app">`}}}
	if _, ok := Eval(&r.Signatures[0], in); !ok {
		t.Fatal("brak dopasowania")
	}
}

func TestConvertWappalyzer(t *testing.T) {
	j := `{"technologies":{"Nginx":{"cats":[22],"headers":{"Server":"nginx(?:/([\\d.]+))?\\;version:\\1"}},
"WordPress":{"cats":[1],"meta":{"generator":"^WordPress ?([\\d.]+)?\\;version:\\1"},"html":"<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/"},
"OnlyJS":{"cats":[59],"js":{"x":""}}}}`
	r, err := Convert([]byte(j), "technologies.json")
	if err != nil || r.Format != "wappalyzer" || len(r.Signatures) != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	in := Input{Headers: map[string][]string{"server": {"nginx/1.25.3"}}}
	for _, s := range r.Signatures {
		if s.Name == "Nginx" {
			d, ok := Eval(&s, in)
			if !ok || s.Category != "server" {
				t.Fatalf("nginx %+v", d)
			}
		}
	}
}

func TestConvertCSVAndASI(t *testing.T) {
	c := "name,type,pattern,category,interest,header,path,status\nMoja App,header,MojaApp,interesting,20,x-app,,\nMoja App,path,ok,,,,/health,200\nPanel X,title,Panel X,admin-panel,25,,,\n"
	r, err := Convert([]byte(c), "s.csv")
	if err != nil || len(r.Signatures) != 2 || len(r.Signatures[0].Matchers) != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	b, err := Convert(BuiltinYAML, "builtin.yaml")
	if err != nil || b.Format != "asi-yaml" || len(b.Signatures) < 60 {
		t.Fatalf("asi %v", err)
	}
}
