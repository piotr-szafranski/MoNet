// MoNet (Monitoring Network), prototyp systemu cyklicznego discovery scan dużej infrastruktury.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/asi-agh/asi/internal/api"
	"github.com/asi-agh/asi/internal/auth"
	"github.com/asi-agh/asi/internal/dojo"
	"github.com/asi-agh/asi/internal/nmap"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/scheduler"
	"github.com/asi-agh/asi/internal/secure"
	"github.com/asi-agh/asi/internal/sig"
	"github.com/asi-agh/asi/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", env("ASI_ADDR", ":8080"), "adres nasłuchu HTTP")
	dataDir := flag.String("data", env("ASI_DATA", "./data"), "katalog danych (baza, klucz)")
	health := flag.Bool("healthcheck", false, "sprawdź, czy serwer odpowiada (dla Dockera)")
	flag.Parse()
	if *health {
		port := (*addr)[strings.LastIndex(*addr, ":")+1:]
		r, err := http.Get("http://127.0.0.1:" + port + "/api/health")
		if err != nil || r.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	lg := log.New(os.Stdout, "asi ", log.LstdFlags|log.Lmsgprefix)
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		lg.Fatal(err)
	}
	keyFile := env("ASI_MASTER_KEY_FILE", filepath.Join(*dataDir, "master.key"))
	master, generated, err := secure.LoadKey(os.Getenv("ASI_MASTER_KEY"), keyFile, env("ASI_ALLOW_KEYGEN", "1") == "1")
	if err != nil {
		lg.Fatal(err)
	}
	if generated {
		lg.Printf("UWAGA: wygenerowano nowy klucz główny %s, w produkcji podaj ASI_MASTER_KEY lub docker secret", keyFile)
	}
	box, err := secure.NewBox(master)
	if err != nil {
		lg.Fatal(err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "asi.db"), box)
	if err != nil {
		lg.Fatal(err)
	}

	jwtSecret := []byte(os.Getenv("ASI_JWT_SECRET"))
	if len(jwtSecret) == 0 {
		m := hmac.New(sha256.New, master)
		m.Write([]byte("asi-jwt"))
		jwtSecret = m.Sum(nil)
	}
	as := auth.New(st, jwtSecret)
	adminPass := env("ASI_ADMIN_PASSWORD", "")
	if adminPass == "" {
		adminPass = "admin123!"
	}
	created, err := as.Seed(env("ASI_ADMIN_USER", "admin"), adminPass, env("ASI_DEMO_USERS", "1") == "1")
	if err != nil {
		lg.Fatal(err)
	}
	if len(created) > 0 {
		lg.Printf("utworzono konta: %v (zmień hasła po pierwszym logowaniu)", created)
	}

	sigs := sig.NewEngine(nil)
	if err := api.SyncSignatures(st, sigs); err != nil {
		lg.Fatal(err)
	}
	scan.Opener = box.MustOpen // poprawki analityka są szyfrowane w spoczynku
	eng := scan.NewEngine(st, sigs, lg)
	eng.NmapBin = env("ASI_NMAP", "nmap")
	// katalog technologii (pierwsze/ostatnie wystąpienie) budowany jednorazowo z historii, potem na bieżąco
	if n, err := scan.BackfillTechs(st); err != nil {
		lg.Printf("katalog technologii: %v", err)
	} else if n > 0 {
		lg.Printf("katalog technologii: zbudowano z historii (%d technologii)", n)
	}
	// przeliczenie klasy zapisanych wyników według aktualnych reguł (np. po aktualizacji wersji)
	go func() {
		if n, err := eng.Rescore(); err == nil {
			lg.Printf("reguły klasy: przeliczono %d obserwacji (%d aktywnych reguł)", n, scan.ActiveRules().Enabled())
		}
	}()
	eng.NoARP = env("ASI_NO_ARP", "0") == "1"
	if env("ASI_PRIVILEGED", "") == "0" {
		eng.Privileged = false
	}
	lg.Printf("nmap: %s, tryb uprzywilejowany: %v (root=%v)", eng.NmapBin, eng.Privileged, nmap.IsRoot())

	// automatyczny eksport do DefectDojo po zakończeniu skanu (reimport do stałego testu konfiguracji)
	eng.OnComplete = func(id int64, cfg *scan.Config) {
		if !cfg.DojoAuto {
			return
		}
		var ds dojo.Settings
		if err := json.Unmarshal([]byte(st.GetSetting("dojo")), &ds); err != nil || ds.URL == "" {
			lg.Printf("DefectDojo: brak konfiguracji, pomijam eksport skanu %d", id)
			return
		}
		obs, err := scan.ListObs(st, `WHERE scan_id=? AND interest>=?`, true, id, cfg.DojoMinInterest)
		obs = scan.WithoutFalsePositives(st.DB, obs)
		if err != nil {
			return
		}
		if len(obs) == 0 {
			// pusty reimport zamknąłby w DefectDojo wszystkie findingi testu, więc pomijamy
			lg.Printf("DefectDojo: skan %d nie ma obserwacji z klasą ≥ %d%%, eksport pominięty", id, cfg.DojoMinInterest)
			dojo.Record(st.DB, "automat", id, "reimport (auto)", "MoNet – "+cfg.Name, 0, nil, fmt.Errorf("pominięto: brak obserwacji powyżej progu"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := dojo.Reimport(ctx, ds, obs, "MoNet – "+cfg.Name)
		dojo.Record(st.DB, "automat", id, "reimport (auto)", "MoNet – "+cfg.Name, len(obs), res, err)
		if err != nil {
			lg.Printf("DefectDojo: eksport skanu %d nieudany: %v", id, err)
			return
		}
		st.Audit("system", "dojo.auto", fmt.Sprint(id), map[string]int{"findings": len(obs)})
		lg.Printf("DefectDojo: wysłano %d obserwacji ze skanu %d (reimport)", len(obs), id)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sch := &scheduler.Scheduler{S: st, E: eng, Log: lg}
	go sch.Run(ctx)

	srv := &api.Server{S: st, A: as, E: eng, Sigs: sigs, Log: lg, Secure: env("ASI_COOKIE_SECURE", "0") == "1"}
	hs := &http.Server{Addr: *addr, Handler: srv.Router(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = hs.Shutdown(sctx)
	}()
	lg.Printf("MoNet nasłuchuje na %s", *addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
