package ports

import "testing"

func TestParse(t *testing.T) {
	s, err := Parse("22, 80,443,8000-8003,U:53")
	if err != nil {
		t.Fatal(err)
	}
	if s.NmapArg() != "T:22,80,443,8000-8003,U:53" || !s.Contains("udp", 53) || s.Contains("tcp", 53) {
		t.Fatalf("%+v %s", s, s.NmapArg())
	}
	for _, bad := range []string{"0", "70000", "80-20", "abc"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("powinien odrzucić %q", bad)
		}
	}
	if p, _ := Parse("web"); p.Count() < 10 {
		t.Fatal("preset")
	}
}
