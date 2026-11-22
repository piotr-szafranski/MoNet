package diff

import (
	"path/filepath"
	"testing"

	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/store"
)

// Trzy skany jednej sieci: znikająca, nowa, zmieniona i powracająca usługa oraz znikający host.
func TestCompute(t *testing.T) {
	box, _ := secure.NewBox(make([]byte, 32))
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	scanWith := func(id int64, hosts []string, obs ...*scan.Observation) {
		t.Helper()
		if _, err := st.DB.Exec(`INSERT INTO scans(id,name,status,ports) VALUES(?,?,'completed','')`, id, "s"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB.Exec(`INSERT INTO scan_blocks(scan_id,idx,ips,status) VALUES(?,0,?,'done')`, id, "10.0.0.1\n10.0.0.2"); err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			if _, err := st.DB.Exec(`INSERT INTO scan_hosts(scan_id,ip,alive) VALUES(?,?,1)`, id, h); err != nil {
				t.Fatal(err)
			}
		}
		for _, o := range obs {
			o.Fingerprint = o.ComputeFingerprint()
			if err := scan.InsertObservation(st.DB, st, id, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	svc := func(ip string, port int, product string) *scan.Observation {
		return &scan.Observation{IP: ip, Port: port, Proto: "tcp", State: "open", Service: "x", Product: product}
	}
	scanWith(1, []string{"10.0.0.1", "10.0.0.2"}, svc("10.0.0.1", 22, "OpenSSH 8"), svc("10.0.0.1", 80, "nginx"), svc("10.0.0.2", 80, "Apache"))
	scanWith(2, []string{"10.0.0.1"}, svc("10.0.0.1", 22, "OpenSSH 9"), svc("10.0.0.1", 443, "nginx"))
	scanWith(3, []string{"10.0.0.1"}, svc("10.0.0.1", 22, "OpenSSH 9"), svc("10.0.0.1", 443, "nginx"), svc("10.0.0.1", 80, "nginx"))

	r, err := Compute(st, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"hosts_gone": 1, "services_gone": 2, // 10.0.0.1:80 i usługa znikającego hosta
		"services_new": 1, "services_changed": 1}
	for k, v := range want {
		if r.Summary[k] != v {
			t.Errorf("1→2 %s = %d, oczekiwano %d (całość %v)", k, r.Summary[k], v, r.Summary)
		}
	}
	r, err = Compute(st, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary["services_returned"] != 1 || r.Summary["services_new"] != 0 {
		t.Errorf("2→3: powrót usługi 80 nierozpoznany: %v", r.Summary)
	}
}
