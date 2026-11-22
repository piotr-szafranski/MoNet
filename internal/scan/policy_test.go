package scan

import "testing"

func TestPolicy(t *testing.T) {
	p := Policy{AllowCIDRs: []string{"10.66.0.0/18", " 192.168.1.5 "}, MaxRate: 500, MaxWorkers: 2}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !p.Allowed("10.66.8.20") || !p.Allowed("192.168.1.5") || p.Allowed("10.66.64.1") || p.Allowed("8.8.8.8") {
		t.Fatalf("zła ocena sieci: %v", p.AllowCIDRs)
	}
	if p.CheckIPs([]string{"10.66.0.2", "1.1.1.1"}) == nil {
		t.Fatal("adres spoza sieci przeszedł")
	}
	c := Config{Rate: 5000, Workers: 8, HTTPRPS: 30}
	if ch := p.Clamp(&c); len(ch) != 2 || c.Rate != 500 || c.Workers != 2 || c.HTTPRPS != 30 {
		t.Fatalf("zły clamp: %+v %v", c, ch)
	}
	bad := Policy{AllowCIDRs: []string{"10.66.8.300/24"}}
	if bad.Normalize() == nil {
		t.Fatal("niepoprawna sieć przeszła")
	}
}

func TestPolicyTargetsAndDefault(t *testing.T) {
	p := DefaultPolicy()
	if !p.AllowedTarget("10.66.0.0/18", "cidr") || p.AllowedTarget("192.0.2.10", "ip") || p.AllowedTarget("10.0.0.0/7", "cidr") {
		t.Fatal("zła ocena celów w polityce domyślnej")
	}
	if !p.AllowedTarget("192.168.1.1-192.168.1.9", "range") || p.AllowedTarget("192.168.255.250-192.169.0.5", "range") {
		t.Fatal("zła ocena zakresów")
	}
}
