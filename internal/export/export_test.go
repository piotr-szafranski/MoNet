package export

import "testing"

const nmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.0/30" start="1" version="7.94">
<host><status state="up" reason="arp-response"/><address addr="10.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="gw.lab" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
</nmaprun>`

func TestNmapImport(t *testing.T) {
	p, err := ParseResults([]byte(nmapXML), "scan.xml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "nmap-xml" || len(p.Alive) != 1 || len(p.Obs) != 2 {
		t.Fatalf("%s alive=%d obs=%d", p.Format, len(p.Alive), len(p.Obs))
	}
	if p.Alive["10.0.0.1"] != "gw.lab" || p.Obs[1].Product != "nginx" {
		t.Fatalf("%+v", p.Obs[1])
	}
}

func TestCSVAndJSONImport(t *testing.T) {
	p, err := ParseResults([]byte("ip,port,proto,service,product,version,title,server\n10.1.1.1,80,tcp,http,nginx,1.25,Panel,nginx/1.25\n10.1.1.2,,,,,,,\n"), "x.csv")
	if err != nil || len(p.Alive) != 2 || len(p.Obs) != 1 || p.Obs[0].Data.HTTP.Title != "Panel" {
		t.Fatalf("csv %v %+v", err, p)
	}
	j, err := ParseResults([]byte(`{"format":"asi-results/1","live_hosts":["10.2.2.2"],"records":[{"ip":"10.2.2.3","port":443,"proto":"tcp","service":"https"}]}`), "x.json")
	if err != nil || len(j.Alive) != 2 || len(j.Obs) != 1 {
		t.Fatalf("json %v %+v", err, j)
	}
}
