package scan

import (
	"errors"
	"net/netip"
	"time"

	"github.com/asi-agh/asi/internal/ports"
	"github.com/asi-agh/asi/internal/store"
)

// ImportResults: zapisuje zewnętrzne wyniki (XML nmapa, JSON/CSV) jako skan typu „import”. Są przetwarzane
// tak samo jak wyniki własne: sygnatury, ocena ciekawości, stany hostów, diff, eksport.
func (e *Engine) ImportResults(name, user, format, portsStr string, alive map[string]string, obs []*Observation, inScope func(string) bool) (int64, int, error) {
	if len(alive) == 0 && len(obs) == 0 {
		return 0, 0, errors.New("plik nie zawiera hostów ani usług")
	}
	for ip := range alive {
		if _, err := netip.ParseAddr(ip); err != nil {
			return 0, 0, errors.New("niepoprawny adres IP w danych: " + ip)
		}
	}
	sp, err := ports.Parse(portsStr)
	if err != nil {
		sp = ports.Spec{}
	}
	skipped := 0
	if inScope != nil {
		for ip := range alive {
			if !inScope(ip) {
				delete(alive, ip)
				skipped++
			}
		}
		kept := obs[:0]
		for _, o := range obs {
			if _, ok := alive[o.IP]; ok {
				kept = append(kept, o)
			}
		}
		obs = kept
	}
	now := store.Now()
	tx, err := e.S.DB.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO scans(config_id,name,status,ports,total_ips,done_ips,created_at,started_at,triggered_by,source,config_snapshot)
VALUES(0,?,?,?,?,?,?,?,?,'import',?)`, name, "importing", sp.String(), len(alive), len(alive), now, now, user, store.ToJSON(map[string]string{"format": format}))
	if err != nil {
		return 0, 0, err
	}
	id, _ := res.LastInsertId()
	for ip, hn := range alive {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO scan_hosts(scan_id,ip,alive,hostname,reason) VALUES(?,?,1,?,'import')`, id, ip, hn); err != nil {
			return 0, 0, err
		}
	}
	ensurePortRules(e.S.DB, obs)
	ovs, _ := LoadOverrides(e.S.DB)
	for _, o := range obs {
		o.Data.Detections = e.Sigs.Evaluate(SigInput(o))
		o.Finalize()
		Score(o)
		if x, ok := ovs[SvcEntity(o.IP, o.Port, o.Proto)]; ok {
			x.Apply(o)
		}
		if err := InsertObservation(tx, e.S, id, o); err != nil {
			return 0, 0, err
		}
	}
	scope := make([]string, 0, len(alive))
	hosts := map[string]*hostRes{}
	for ip, hn := range alive {
		scope = append(scope, ip)
		hosts[ip] = &hostRes{ip: ip, alive: true, hostname: hn}
	}
	if err := updateInventory(tx, id, scope, hosts, obs, sp, 3, time.Now().Hour(), now, false); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(`UPDATE scans SET status='completed', finished_at=?, live_hosts=?, open_services=? WHERE id=?`, now, len(alive), len(obs), id); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return id, skipped, nil
}
