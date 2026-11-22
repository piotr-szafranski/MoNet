package sig

import "testing"

func TestBuiltinCompiles(t *testing.T) {
	sigs, err := ParseYAML(BuiltinYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) < 40 {
		t.Fatalf("za mało sygnatur: %d", len(sigs))
	}
	e := NewEngine(sigs)
	in := Input{Headers: map[string][]string{"server": {"nginx/1.25.3"}, "x-powered-by": {"PHP/8.2.1"}},
		Body: `<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">`, Cookies: []string{"PHPSESSID"},
		Hostname: "staging.lab.local"}
	got := map[string]Detection{}
	for _, d := range e.Evaluate(in) {
		got[d.ID] = d
	}
	if got["wordpress"].Version != "6.4.2" || got["nginx"].Version != "1.25.3" || got["php"].Version != "8.2.1" {
		t.Fatalf("wersje: %+v", got)
	}
	if _, ok := got["staging-hostname"]; !ok {
		t.Fatal("brak staging")
	}
	t.Logf("sygnatur: %d, ścieżek: %d", len(sigs), len(e.Paths(0)))
}
