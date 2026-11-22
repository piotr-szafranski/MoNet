package nmap

import (
	"strings"
	"testing"
	"time"
)

const sample = `<?xml version="1.0"?>
<nmaprun args="nmap -sS" start="1700000000" version="7.94">
<host><status state="up" reason="syn-ack"/>
<address addr="10.66.8.50" addrtype="ipv4"/><address addr="02:42:0A:42:08:32" addrtype="mac" vendor="Docker"/>
<hostnames><hostname name="ssh.lab" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port></ports>
<times srtt="512"/></host>
<runstats><finished elapsed="1.23" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`

func TestParse(t *testing.T) {
	r, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hosts) != 1 {
		t.Fatalf("hosty: %d", len(r.Hosts))
	}
	h := r.Hosts[0]
	if h.IP() != "10.66.8.50" || h.Hostname() != "ssh.lab" {
		t.Fatalf("adres/nazwa: %s %s", h.IP(), h.Hostname())
	}
	if mac, vendor := h.MAC(); mac == "" || vendor != "Docker" {
		t.Fatalf("MAC: %s %s", mac, vendor)
	}
	if len(h.Ports) != 2 || h.Ports[0].PortID != 22 {
		t.Fatalf("porty: %+v", h.Ports)
	}
	if _, err := Parse(strings.NewReader("<nie-xml")); err == nil {
		t.Fatal("uszkodzony XML przyjęty")
	}
}

// Limity tempa i timeout z konfiguracji muszą trafić do argumentów nmapa (bezpieczeństwo skanowania).
func TestCommonArgs(t *testing.T) {
	a := strings.Join(common(Options{MaxRate: 500, Retries: 1, HostTimeout: 90 * time.Second}), " ")
	for _, want := range []string{"--max-rate 500", "--host-timeout 90s", "--max-retries 1", "-oX -", "--unprivileged"} {
		if !strings.Contains(a, want) {
			t.Errorf("brak %q w %q", want, a)
		}
	}
	if strings.Contains(strings.Join(common(Options{}), " "), "--max-rate") {
		t.Error("--max-rate bez limitu")
	}
}
