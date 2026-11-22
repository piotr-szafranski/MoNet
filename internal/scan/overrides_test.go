package scan

import (
	"path/filepath"
	"testing"

	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/store"
)

// Wymaganie 14: poprawka analityka nakłada się na nowe obserwacje tej samej usługi; fałszywy alarm wypada z eksportu.
func TestOverridesSurviveRescan(t *testing.T) {
	box, err := secure.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	ent := SvcEntity("10.0.0.5", 80, "tcp")
	if _, err := st.DB.Exec(`INSERT INTO annotations(entity,tech_override,false_positive,updated_by) VALUES(?,?,0,'analityk')`,
		ent, `{"product":"Apache (poprawione)","version":"2.4.99","interest":77}`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO annotations(entity,false_positive) VALUES(?,1)`, SvcEntity("10.0.0.6", 22, "tcp")); err != nil {
		t.Fatal(err)
	}
	// „nowy skan”: świeże obserwacje z wartościami z nmapa
	fresh := []*Observation{
		{IP: "10.0.0.5", Port: 80, Proto: "tcp", Product: "Apache httpd", Version: "2.4.62", Interest: 10},
		{IP: "10.0.0.6", Port: 22, Proto: "tcp", Product: "OpenSSH"},
	}
	ApplyOverrides(st.DB, fresh)
	o := fresh[0]
	if o.Product != "Apache (poprawione)" || o.Version != "2.4.99" || o.Interest != 77 || !o.Edited || o.EditedBy != "analityk" {
		t.Fatalf("poprawka nie została nałożona: %+v", o)
	}
	if fresh[1].Edited {
		t.Fatal("usługa bez poprawki nie powinna być oznaczona jako edytowana")
	}
	out := WithoutFalsePositives(st.DB, fresh)
	if len(out) != 1 || out[0].IP != "10.0.0.5" {
		t.Fatalf("fałszywy alarm nie został wykluczony: %d", len(out))
	}
}

// Poprawka produktu przestaje obowiązywać, gdy skaner widzi nową wersję (zmiana ma być widoczna w diffie).
func TestOverrideStaleOnRealChange(t *testing.T) {
	v := 60
	ov := Override{Product: "Apache (poprawione)", Interest: &v, HasBase: true, BaseService: "http", BaseProduct: "Apache httpd", BaseVersion: "2.4.62", By: "analityk"}
	same := &Observation{Service: "http", Product: "Apache httpd", Version: "2.4.62"}
	ov.Apply(same)
	if same.Product != "Apache (poprawione)" || same.Interest != 60 {
		t.Fatalf("poprawka nie nałożona: %+v", same)
	}
	upd := &Observation{Service: "http", Product: "Apache httpd", Version: "2.4.63"}
	ov.Apply(upd)
	if upd.Product != "Apache httpd" || upd.Version != "2.4.63" {
		t.Fatalf("poprawka ukryła prawdziwą zmianę wersji: %+v", upd)
	}
	if upd.Interest != 60 {
		t.Fatal("klasa ustawiona przez analityka powinna zostać")
	}
}

// Poprawka technologii wygasa, gdy skaner wykryje inny zestaw technologii.
func TestOverrideTechsStale(t *testing.T) {
	ov := Override{Techs: []Tech{{ID: "analityk-x", Name: "X"}}, BaseTechs: TechIDs([]Tech{{ID: "nginx", Version: "1.24"}}), By: "a"}
	same := &Observation{Techs: []Tech{{ID: "nginx", Version: "1.24"}}}
	ov.Apply(same)
	if len(same.Techs) != 1 || same.Techs[0].ID != "analityk-x" {
		t.Fatalf("poprawka technologii nie nałożona: %+v", same.Techs)
	}
	changed := &Observation{Techs: []Tech{{ID: "nginx", Version: "1.25"}}}
	ov.Apply(changed)
	if changed.Techs[0].ID != "nginx" {
		t.Fatalf("poprawka ukryła zmianę technologii: %+v", changed.Techs)
	}
}
