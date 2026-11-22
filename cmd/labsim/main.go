// labsim: symulator zróżnicowanej infrastruktury do testów MoNet (TYLKO sieć labu, internal).
// Jeden kontener dodaje setki aliasów IP i na każdym wystawia usługi wg profilu: CMS-y, IoT, panele, staging,
// SSH/FTP/MySQL/Redis/Telnet, hosty niestabilne (znikają co fazę), zależne od pory dnia, zmieniające wersję
// i porty między fazami. /truth zwraca prawdziwy stan (do pomiaru trafności skanera).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type svc struct {
	Port   int    `json:"port"`
	Kind   string `json:"kind"` // http|https|banner|mysql|redis
	Expect string `json:"expect"`
	Phase  int    `json:"phase,omitempty"` // 0 = zawsze, 1 = tylko faza A, 2 = tylko faza B
}

type profile struct {
	Name    string   `json:"name"`
	Weight  int      `json:"-"`
	Svcs    []svc    `json:"services"`
	Techs   []string `json:"expected_techs"`
	Special string   `json:"special,omitempty"` // flap | daytime | changing
}

var profiles = []profile{
	{Name: "nginx-default", Weight: 14, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"nginx", "default-page"}},
	{Name: "apache-php", Weight: 10, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 22, Kind: "banner"}}, Techs: []string{"apache-httpd", "php", "openssh"}},
	{Name: "ssh-only", Weight: 12, Svcs: []svc{{Port: 22, Kind: "banner"}}, Techs: []string{"openssh"}},
	{Name: "wordpress", Weight: 5, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 443, Kind: "https"}}, Techs: []string{"wordpress", "php", "nginx"}},
	{Name: "joomla", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"joomla", "apache-httpd"}},
	{Name: "drupal", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"drupal", "nginx"}},
	{Name: "iis-aspnet", Weight: 3, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 3389, Kind: "banner"}}, Techs: []string{"iis", "aspnet"}},
	{Name: "camera-hik", Weight: 3, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 554, Kind: "banner"}}, Techs: []string{"hikvision", "ip-camera"}},
	{Name: "goahead-iot", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 23, Kind: "banner"}}, Techs: []string{"goahead", "telnet"}},
	{Name: "mikrotik", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 22, Kind: "banner"}}, Techs: []string{"mikrotik"}},
	{Name: "printer", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 9100, Kind: "banner"}}, Techs: []string{"printer"}},
	{Name: "jenkins", Weight: 2, Svcs: []svc{{Port: 8080, Kind: "http"}, {Port: 22, Kind: "banner"}}, Techs: []string{"jenkins", "jetty", "login-form"}},
	{Name: "grafana", Weight: 2, Svcs: []svc{{Port: 3000, Kind: "http"}}, Techs: []string{"grafana", "login-form"}},
	{Name: "tomcat", Weight: 3, Svcs: []svc{{Port: 8080, Kind: "http"}}, Techs: []string{"tomcat", "tomcat-manager"}},
	{Name: "staging-portal", Weight: 3, Svcs: []svc{{Port: 443, Kind: "https"}, {Port: 80, Kind: "http"}}, Techs: []string{"staging-content", "staging-hostname", "nginx"}},
	{Name: "admin-panel", Weight: 3, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 8443, Kind: "https"}}, Techs: []string{"admin-path", "login-form"}},
	{Name: "phpmyadmin", Weight: 1, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 3306, Kind: "mysql"}}, Techs: []string{"phpmyadmin", "mysql"}},
	{Name: "dir-listing", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"directory-listing", "apache-httpd"}},
	{Name: "git-exposed", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"git-exposed", "nginx"}},
	{Name: "env-exposed", Weight: 1, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"env-exposed", "laravel"}},
	{Name: "spring-boot", Weight: 2, Svcs: []svc{{Port: 8080, Kind: "http"}}, Techs: []string{"spring"}},
	{Name: "https-expired", Weight: 3, Svcs: []svc{{Port: 443, Kind: "https"}}, Techs: []string{"nginx"}},
	{Name: "ftp", Weight: 3, Svcs: []svc{{Port: 21, Kind: "banner"}, {Port: 22, Kind: "banner"}}, Techs: []string{"ftp", "openssh"}},
	{Name: "redis-open", Weight: 2, Svcs: []svc{{Port: 6379, Kind: "redis"}}, Techs: []string{"redis"}},
	{Name: "mysql", Weight: 3, Svcs: []svc{{Port: 3306, Kind: "mysql"}, {Port: 22, Kind: "banner"}}, Techs: []string{"mysql", "openssh"}},
	{Name: "elastic-open", Weight: 1, Svcs: []svc{{Port: 9200, Kind: "http"}}, Techs: []string{"elasticsearch"}},
	{Name: "flapping", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"nginx"}, Special: "flap"},
	{Name: "daytime", Weight: 2, Svcs: []svc{{Port: 80, Kind: "http"}}, Techs: []string{"apache-httpd"}, Special: "daytime"},
	{Name: "changing", Weight: 3, Svcs: []svc{{Port: 80, Kind: "http"}, {Port: 8081, Kind: "http", Phase: 1}, {Port: 8443, Kind: "https", Phase: 2}}, Techs: []string{"nginx"}, Special: "changing"},
	{Name: "express-api", Weight: 2, Svcs: []svc{{Port: 3000, Kind: "http"}, {Port: 8000, Kind: "http"}}, Techs: []string{"express", "swagger"}},
}

type host struct {
	IP      string   `json:"ip"`
	Profile string   `json:"profile"`
	Index   int      `json:"-"`
	P       *profile `json:"-"`
	Name    string   `json:"hostname"`
	Svcs    []svc    `json:"-"` // usługi profilu + dodatkowe porty tego hosta
	Techs   []string `json:"-"`
}

// pick: deterministyczna (stała dla danego IP) wartość z listy: hosty jednego profilu się różnią,
// a kolejne skany widzą ten sam host tak samo.
func (h *host) pick(key string, opts ...string) string {
	return opts[h32(key+"|"+h.IP)%uint32(len(opts))]
}

var titles = []string{"Wydział Informatyki", "Biblioteka Główna", "Dziekanat", "Laboratorium Sieci Komputerowych", "Portal pracownika",
	"Rekrutacja 2026", "Katedra Automatyki", "System rezerwacji sal", "Helpdesk IT", "Platforma e-learningowa", "Centrum Karier",
	"Wydział Geologii", "Katedra Energetyki", "Archiwum dokumentów", "Projekt badawczy", "Konferencja naukowa", "Koło naukowe",
	"Akademik – portal mieszkańca", "System ankiet", "Intranet działu kadr"}

func (h *host) nginx() string {
	return "nginx/" + h.pick("nginx", "1.18.0", "1.20.2", "1.22.1", "1.24.0", "1.25.3", "1.26.2", "1.27.1")
}
func (h *host) apache() string {
	return "Apache/" + h.pick("apache", "2.4.41 (Ubuntu)", "2.4.52 (Ubuntu)", "2.4.54 (Debian)", "2.4.57 (Debian)", "2.4.58 (Ubuntu)", "2.4.62 (Debian)")
}
func (h *host) title(prefix string) string { return prefix + h.pick("title", titles...) }

var (
	hosts     []*host
	byIP      = map[string]*host{}
	phaseMin  = 5
	dayFrom   = 1
	dayTo     = 6
	start     = time.Now()
	certValid tls.Certificate
	certExp   tls.Certificate
	certStag  tls.Certificate
	iface     = "eth0"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func h32(s string) uint32 {
	f := fnv.New32a()
	f.Write([]byte(s))
	return f.Sum32()
}

// phase: 0 lub 1, zmienia się co phaseMin minut (zegar ścienny, więc kolejne skany widzą zmiany).
func phase() int { return int(time.Now().Unix()/int64(phaseMin*60)) % 2 }

func hostUp(h *host) bool {
	switch h.P.Special {
	case "flap":
		return (phase()+h.Index)%2 == 0
	case "daytime":
		hr := time.Now().Hour()
		return hr >= dayFrom && hr < dayTo
	}
	return true
}

func svcActive(s svc) bool {
	switch s.Phase {
	case 1:
		return phase() == 0
	case 2:
		return phase() == 1
	}
	return true
}

func main() {
	base := netip.MustParseAddr(env("SIM_BASE", "10.66.8.0"))
	span, _ := strconv.Atoi(env("SIM_SPAN", "14336"))
	count, _ := strconv.Atoi(env("SIM_COUNT", "1500"))
	phaseMin, _ = strconv.Atoi(env("SIM_PHASE_MIN", "5"))
	dayFrom, _ = strconv.Atoi(env("SIM_DAY_FROM", "1"))
	dayTo, _ = strconv.Atoi(env("SIM_DAY_TO", "6"))
	iface = env("SIM_IFACE", "eth0")
	certValid = mkCert("www.lab.local", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))
	certExp = mkCert("old.lab.local", time.Now().Add(-800*24*time.Hour), time.Now().Add(-30*24*time.Hour))
	certStag = mkCert("staging.lab.local", time.Now().Add(-24*time.Hour), time.Now().Add(20*24*time.Hour))

	total := 0
	for _, p := range profiles {
		total += p.Weight
	}
	// deterministyczny wybór adresów i profili (powtarzalna „prawda”)
	step := max(1, span/count)
	for i := 0; i < count; i++ {
		off := i*step + int(h32(fmt.Sprint("off", i))%uint32(max(1, step)))
		a := base
		for j := 0; j < off; j++ {
			a = a.Next()
		}
		w := int(h32(fmt.Sprint("prof", i)) % uint32(total))
		var p *profile
		for k := range profiles {
			if w < profiles[k].Weight {
				p = &profiles[k]
				break
			}
			w -= profiles[k].Weight
		}
		hn := ""
		if strings.HasPrefix(p.Name, "staging") {
			hn = fmt.Sprintf("staging%d.lab.local", i)
		}
		h := &host{IP: a.String(), Profile: p.Name, Index: i, P: p, Name: hn}
		h.Svcs = append([]svc(nil), p.Svcs...)
		h.Techs = append([]string(nil), p.Techs...)
		if p.Name == "nginx-default" && h32("default"+h.IP)%3 != 0 {
			h.Techs = []string{"nginx"} // tylko co trzeci host pokazuje domyślną stronę nginx
		}
		has := func(port int) bool {
			for _, x := range h.Svcs {
				if x.Port == port {
					return true
				}
			}
			return false
		}
		// część hostów ma dodatkowe usługi (zróżnicowana sieć)
		if h32("ssh"+h.IP)%4 == 0 && !has(22) && p.Special == "" {
			h.Svcs = append(h.Svcs, svc{Port: 22, Kind: "banner"})
			h.Techs = append(h.Techs, "openssh")
		}
		if h32("ftp"+h.IP)%17 == 0 && !has(21) && p.Special == "" {
			h.Svcs = append(h.Svcs, svc{Port: 21, Kind: "banner"})
			h.Techs = append(h.Techs, "ftp")
		}
		if h32("mysql"+h.IP)%19 == 0 && !has(3306) && p.Special == "" {
			h.Svcs = append(h.Svcs, svc{Port: 3306, Kind: "mysql"})
			h.Techs = append(h.Techs, "mysql")
		}
		hosts = append(hosts, h)
		byIP[h.IP] = h
	}
	log.Printf("labsim: %d hostów, %d profili, faza co %d min, hosty „dzienne” aktywne %02d-%02d", len(hosts), len(profiles), phaseMin, dayFrom, dayTo)
	go mgmt()
	reconcile()
	for range time.Tick(15 * time.Second) {
		reconcile()
	}
}

// ---- aliasy IP i nasłuchy ----

var (
	mu        sync.Mutex
	upIPs     = map[string]bool{}
	listeners = map[string]net.Listener{}
)

func ipBatch(cmds []string) {
	if len(cmds) == 0 {
		return
	}
	c := exec.Command("ip", "-force", "-batch", "-")
	c.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	if out, err := c.CombinedOutput(); err != nil && len(out) > 0 {
		log.Printf("ip batch: %v %s", err, firstLine(string(out)))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func reconcile() {
	mu.Lock()
	defer mu.Unlock()
	var add, del []string
	for _, h := range hosts {
		want := hostUp(h)
		if want && !upIPs[h.IP] {
			add = append(add, fmt.Sprintf("address add %s/32 dev %s", h.IP, iface))
			upIPs[h.IP] = true
		} else if !want && upIPs[h.IP] {
			del = append(del, fmt.Sprintf("address del %s/32 dev %s", h.IP, iface))
			delete(upIPs, h.IP)
		}
	}
	ipBatch(add)
	ipBatch(del)
	desired := map[string]bool{}
	for _, h := range hosts {
		for _, s := range h.Svcs {
			if svcActive(s) {
				desired[net.JoinHostPort(h.IP, strconv.Itoa(s.Port))] = true
			}
		}
	}
	for k, l := range listeners {
		if !desired[k] {
			l.Close()
			delete(listeners, k)
		}
	}
	opened := 0
	for k := range desired {
		if listeners[k] != nil {
			continue
		}
		ip, ps, _ := net.SplitHostPort(k)
		port, _ := strconv.Atoi(ps)
		l, err := listenFree(k)
		if err != nil {
			continue
		}
		listeners[k] = l
		opened++
		go serve(byIP[ip], port, l)
	}
	if len(add)+len(del)+opened > 0 {
		log.Printf("faza %d: +%d IP, -%d IP, otwarto %d nasłuchów (razem %d)", phase(), len(add), len(del), opened, len(listeners))
	}
}

// listenFree: IP_FREEBIND pozwala nasłuchiwać na adresie, który chwilowo nie jest przypisany (host „zniknął”).
func listenFree(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		_ = c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 15 /* IP_FREEBIND */, 1)
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		return serr
	}}
	return lc.Listen(nil, "tcp", addr)
}

func serve(h *host, port int, l net.Listener) {
	var s svc
	for _, x := range h.Svcs {
		if x.Port == port {
			s = x
		}
	}
	switch s.Kind {
	case "http":
		_ = (&http.Server{Handler: handler(h, port), ReadHeaderTimeout: 5 * time.Second}).Serve(l)
	case "https":
		cert := certValid
		switch h.P.Name {
		case "https-expired":
			cert = certExp
		case "staging-portal":
			cert = certStag
		}
		tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		_ = (&http.Server{Handler: handler(h, port), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(nopW{}, "", 0)}).Serve(tl)
	default:
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go rawConn(h, s, c)
		}
	}
}

type nopW struct{}

func (nopW) Write(p []byte) (int, error) { return len(p), nil }

func rawConn(h *host, s svc, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	switch s.Kind {
	case "mysql":
		_, _ = c.Write(mysqlGreeting(h.pick("mysql", "5.7.44", "8.0.35", "8.0.39", "8.4.2", "10.6.18-MariaDB", "10.11.8-MariaDB")))
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		return
	case "redis":
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			q := strings.ToUpper(string(buf[:n]))
			switch {
			case strings.Contains(q, "PING"):
				_, _ = c.Write([]byte("+PONG\r\n"))
			case strings.Contains(q, "INFO"):
				info := "# Server\r\nredis_version:" + h.pick("redis", "6.2.14", "7.0.15", "7.2.4") + "\r\nredis_mode:standalone\r\nos:Linux\r\n"
				_, _ = c.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)))
			default:
				_, _ = c.Write([]byte("-ERR unknown command\r\n"))
			}
		}
	}
	var banner string
	switch s.Port {
	case 22:
		switch h.P.Name {
		case "mikrotik":
			banner = "SSH-2.0-ROSSSH\r\n"
		case "jenkins":
			banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"
		default:
			banner = "SSH-2.0-" + h.pick("ssh", "OpenSSH_7.4", "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
				"OpenSSH_9.2p1 Debian-2+deb12u3", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "OpenSSH_8.4p1 Debian-5+deb11u3") + "\r\n"
		}
	case 21:
		banner = h.pick("ftp", "220 (vsFTPd 3.0.3)\r\n", "220 (vsFTPd 3.0.5)\r\n", "220 ProFTPD Server (ProFTPD) ["+h.IP+"]\r\n")
	case 23:
		banner = "\r\nBusyBox v1.24.1 (embedded)\r\nIPCam login: "
	case 554:
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Hikvision-Webs RTSP\r\nWWW-Authenticate: Basic realm=\"IP Camera\"\r\n\r\n"))
		return
	case 3389:
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00})
		return
	case 9100:
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("@PJL INFO ID\r\n\"HP LaserJet M404\"\r\n"))
		return
	}
	_, _ = c.Write([]byte(banner))
	buf := make([]byte, 256)
	_, _ = c.Read(buf)
}

func mysqlGreeting(ver string) []byte {
	var p []byte
	p = append(p, 0x0a)
	p = append(p, []byte(ver)...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, 42)
	p = append(p, []byte("abcdefgh")...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint16(p, 0xffff)
	p = append(p, 0xff)
	p = binary.LittleEndian.AppendUint16(p, 0x0002)
	p = binary.LittleEndian.AppendUint16(p, 0xdfff)
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, []byte("ijklmnopqrst")...)
	p = append(p, 0)
	p = append(p, []byte("caching_sha2_password")...)
	p = append(p, 0)
	hdr := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}
	return append(hdr, p...)
}

// ---- HTTP wg profilu ----

func page(title, body string) string {
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + title + "</title></head><body>" + body + "</body></html>"
}

const loginForm = `<form method="post" action="/login"><input name="username"><input type="password" name="password"><button>Zaloguj</button></form>`

func handler(h *host, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		p := r.URL.Path
		send := func(code int, server, title, body string) {
			if server != "" {
				hd.Set("Server", server)
			}
			hd.Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(page(title, body)))
		}
		notFound := func(server string) { send(404, server, "404 Not Found", "<h1>Not Found</h1>") }
		switch h.P.Name {
		case "nginx-default", "flapping":
			if p != "/" {
				notFound(h.nginx())
				return
			}
			if h32("default"+h.IP)%3 == 0 {
				send(200, h.nginx(), "Welcome to nginx!", "<h1>Welcome to nginx!</h1>")
			} else {
				send(200, h.nginx(), h.title(""), "<p>Serwis jednostki</p>")
			}
		case "changing":
			ver, title := "1.22.1", "Intranet portal"
			if phase() == 1 {
				ver, title = "1.25.3", "Intranet portal v2 (beta)"
			}
			if port == 8081 {
				send(200, "nginx/"+ver, "Legacy API", `{"status":"ok"}`)
				return
			}
			if port == 8443 {
				send(200, "nginx/"+ver, "Nowy panel administracyjny", loginForm)
				return
			}
			send(200, "nginx/"+ver, title, "<p>Portal pracowniczy</p>")
		case "apache-php", "daytime":
			hd.Set("X-Powered-By", "PHP/"+h.pick("php", "7.2.34", "7.4.33", "8.0.30", "8.1.29", "8.2.20", "8.3.9"))
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "s" + strconv.Itoa(h.Index), Path: "/"})
			if p != "/" {
				notFound(h.apache())
				return
			}
			send(200, h.apache(), h.title(""), "<p>Witamy</p>")
		case "wordpress":
			hd.Set("Link", `<http://`+r.Host+`/wp-json/>; rel="https://api.w.org/"`)
			hd.Set("X-Powered-By", "PHP/"+h.pick("php", "7.4.33", "8.1.27", "8.2.20", "8.3.9"))
			http.SetCookie(w, &http.Cookie{Name: "wordpress_test_cookie", Value: "WP Cookie check", Path: "/"})
			if p == "/wp-login.php" {
				send(200, h.nginx(), "Log In ‹ "+h.pick("title", titles...), `<form id="loginform"><input id="user_login"><input type="password"><input id="wp-submit" type="submit"></form>`)
				return
			}
			if p != "/" {
				notFound(h.nginx())
				return
			}
			send(200, h.nginx(), h.title("Blog – "), `<meta name="generator" content="WordPress `+h.pick("wp", "5.8.10", "6.2.6", "6.4.2", "6.5.5", "6.6.2")+`" /><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">`)
		case "joomla":
			if strings.HasPrefix(p, "/administrator") {
				send(200, h.apache(), "Administracja", `<div id="mod-login">Joomla! Administrator Login</div>`+loginForm)
				return
			}
			send(200, h.apache(), h.title(""), `<meta name="generator" content="Joomla! - Open Source Content Management" /><script src="/media/jui/js/jquery.min.js"></script>`)
		case "drupal":
			hd.Set("X-Generator", "Drupal "+h.pick("drupal", "7", "9", "10")+" (https://www.drupal.org)")
			hd.Set("X-Drupal-Cache", "HIT")
			send(200, h.nginx(), h.title(""), `<script>drupalSettings={}</script><link href="/sites/default/files/css/a.css">`)
		case "iis-aspnet":
			hd.Set("X-AspNet-Version", "4.0.30319")
			hd.Set("X-Powered-By", "ASP.NET")
			http.SetCookie(w, &http.Cookie{Name: "ASP.NET_SessionId", Value: "x", Path: "/", HttpOnly: true})
			send(200, "Microsoft-IIS/"+h.pick("iis", "8.5", "10.0"), h.title(""), `<input type="hidden" name="__VIEWSTATE" value="x">`)
		case "camera-hik":
			if p == "/doc/page/login.asp" || p == "/" {
				send(200, "App-webs/", "Network Camera", `<script>location.href="/doc/page/login.asp"</script>`+loginForm)
				return
			}
			notFound("App-webs/")
		case "goahead-iot":
			send(200, "GoAhead-Webs", "Web Viewer", "<p>IP Camera</p>"+loginForm)
		case "mikrotik":
			send(200, "", "RouterOS router configuration page", "<h1>RouterOS</h1>mikrotik")
		case "printer":
			send(200, "HP HTTP Server; HP LaserJet M404 - W1A52A", "HP LaserJet M404", "<p>Status drukarki</p>")
		case "jenkins":
			hd.Set("X-Jenkins", h.pick("jenkins", "2.346.3", "2.401.3", "2.426.1", "2.452.3", "2.462.1"))
			hd.Set("X-Hudson", "1.395")
			if p == "/" || p == "/login" {
				send(200, "Jetty(10.0.18)", "Sign in [Jenkins]", loginForm)
				return
			}
			notFound("Jetty(10.0.18)")
		case "grafana":
			if p == "/api/health" {
				hd.Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"commit":"abc","database":"ok","version":"` + h.pick("grafana", "8.5.27", "9.5.2", "10.2.3", "10.4.5", "11.1.0") + `"}`))
				return
			}
			send(200, "", "Grafana", `<div class="grafana-app"></div>`+loginForm)
		case "tomcat":
			if p == "/manager/html" {
				hd.Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
				send(401, "", "401 Unauthorized", "<p>Tomcat manager</p>")
				return
			}
			tv := h.pick("tomcat", "8.5.100", "9.0.80", "9.0.91", "10.1.26")
			send(200, "", "Apache Tomcat/"+tv, "<h1>Apache Tomcat/"+tv+"</h1><p>If you're seeing this, you've successfully installed Tomcat.</p>")
		case "staging-portal":
			hd.Set("X-Environment", "staging")
			send(200, h.nginx(), "STAGING – "+h.pick("title", titles...)+" (środowisko testowe)", "<p>DEBUG = True</p>")
		case "admin-panel":
			if p == "/admin" || p == "/admin/" || port == 8443 {
				send(200, h.nginx(), "Panel administracyjny – "+h.pick("title", titles...), loginForm)
				return
			}
			if p != "/" {
				notFound(h.nginx())
				return
			}
			send(200, h.nginx(), h.title(""), `<a href="/admin">admin</a>`)
		case "phpmyadmin":
			http.SetCookie(w, &http.Cookie{Name: "phpMyAdmin", Value: "x", Path: "/", HttpOnly: true})
			send(200, h.apache(), "phpMyAdmin", loginForm)
		case "dir-listing":
			if p != "/" {
				notFound(h.apache())
				return
			}
			send(200, h.apache(), "Index of /", `<h1>Index of /</h1><a href="backup.zip">backup.zip</a>`)
		case "git-exposed":
			if p == "/.git/HEAD" {
				hd.Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("ref: refs/heads/main\n"))
				return
			}
			if p != "/" {
				notFound(h.nginx())
				return
			}
			send(200, h.nginx(), h.title(""), "<p>OK</p>")
		case "env-exposed":
			http.SetCookie(w, &http.Cookie{Name: "laravel_session", Value: "x", Path: "/", HttpOnly: true})
			if p == "/.env" {
				hd.Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("APP_NAME=Rekrutacja\nAPP_ENV=production\nDB_HOST=10.0.0.5\n"))
				return
			}
			send(200, h.nginx(), h.title(""), "<p>Laravel</p>")
		case "spring-boot":
			if p == "/actuator/health" {
				hd.Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"UP"}`))
				return
			}
			send(404, "", "Error", "<h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p>")
		case "https-expired":
			send(200, "nginx/"+h.pick("oldnginx", "1.10.3", "1.12.2", "1.14.0", "1.16.1"), h.title("Archiwum – "), "<p>Archiwum</p>")
		case "elastic-open":
			hd.Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"node-1","cluster_name":"` + h.pick("cluster", "logs", "siem", "monitoring", "search") + `","version":{"number":"` + h.pick("es", "6.8.23", "7.10.2", "7.17.22", "8.14.3") + `"},"tagline":"You Know, for Search"}`))
		case "express-api":
			hd.Set("X-Powered-By", "Express")
			if port == 8000 {
				send(200, "", "Swagger UI", `<div id="swagger-ui"></div>`)
				return
			}
			hd.Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"api":"v1"}`))
		default:
			send(200, "", "OK", "")
		}
	})
}

// ---- zarządzanie: /truth ----

func mgmt() {
	mux := http.NewServeMux()
	mux.HandleFunc("/truth", func(w http.ResponseWriter, r *http.Request) {
		type th struct {
			IP       string   `json:"ip"`
			Profile  string   `json:"profile"`
			Hostname string   `json:"hostname,omitempty"`
			Up       bool     `json:"up"`
			Ports    []int    `json:"open_ports"`
			Techs    []string `json:"expected_techs"`
			Special  string   `json:"special,omitempty"`
		}
		var out []th
		for _, h := range hosts {
			t := th{IP: h.IP, Profile: h.Profile, Hostname: h.Name, Up: hostUp(h), Techs: h.Techs, Special: h.P.Special}
			for _, s := range h.Svcs {
				if svcActive(s) {
					t.Ports = append(t.Ports, s.Port)
				}
			}
			sort.Ints(t.Ports)
			out = append(out, t)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"phase": phase(), "generated_at": time.Now().Format(time.RFC3339), "hosts": out})
	})
	addr := env("SIM_MGMT", ":9999")
	log.Printf("labsim: zarządzanie na %s/truth", addr)
	_ = http.ListenAndServe(addr, mux)
}

func mkCert(cn string, nb, na time.Time) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn, Organization: []string{"Lab MoNet"}},
		NotBefore: nb, NotAfter: na, DNSNames: []string{cn}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
