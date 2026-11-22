// Package export: eksport wyników (JSON/CSV) i import wyników (nasz JSON/CSV oraz XML nmapa).
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/asi-agh/asi/internal/httpprobe"
	"github.com/asi-agh/asi/internal/nmap"
	"github.com/asi-agh/asi/internal/scan"
	"github.com/asi-agh/asi/internal/store"
)

const FormatVersion = "asi-results/1"

// Record: płaski rekord wymiany danych (format importu/eksportu, opisany w docs/FORMATY.md).
type Record struct {
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname,omitempty"`
	Port        int      `json:"port,omitempty"`
	Proto       string   `json:"proto,omitempty"`
	State       string   `json:"state,omitempty"`
	Service     string   `json:"service,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	TLS         bool     `json:"tls,omitempty"`
	CertSubject string   `json:"cert_subject,omitempty"`
	CertExpires string   `json:"cert_not_after,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	Interest    int      `json:"interest,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Cookies     []string `json:"cookies,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Note        string   `json:"note,omitempty"`
}

type Document struct {
	Format     string   `json:"format"`
	ExportedAt string   `json:"exported_at"`
	Scan       any      `json:"scan,omitempty"`
	Hosts      []string `json:"live_hosts"`
	Records    []Record `json:"records"`
}

func ToRecord(o *scan.Observation) Record {
	r := Record{IP: o.IP, Hostname: o.Data.Hostname, Port: o.Port, Proto: o.Proto, State: o.State, Service: o.Service, Product: o.Product,
		Version: o.Version, HTTPStatus: o.HTTPStatus, TLS: o.TLS, Flags: o.Flags, Interest: o.Interest}
	for _, t := range o.Techs {
		s := t.Name
		if t.Version != "" {
			s += " " + t.Version
		}
		r.Technologies = append(r.Technologies, fmt.Sprintf("%s (%d%%)", s, t.Confidence))
	}
	if h := o.Data.HTTP; h != nil {
		r.Title = h.Title
		r.Headers = map[string]string{}
		for k, v := range h.Headers {
			r.Headers[k] = strings.Join(v, ", ")
		}
		if v := h.Headers["server"]; len(v) > 0 {
			r.Server = v[0]
		}
		for _, c := range h.Cookies {
			flags := ""
			if c.Secure {
				flags += ";Secure"
			}
			if c.HttpOnly {
				flags += ";HttpOnly"
			}
			r.Cookies = append(r.Cookies, c.Name+flags)
		}
		if h.TLS != nil {
			r.CertSubject = h.TLS.Subject
			r.CertExpires = h.TLS.NotAfter.Format("2006-01-02")
		}
	}
	return r
}

var csvHeader = []string{"ip", "hostname", "port", "proto", "state", "service", "product", "version", "http_status", "title", "server",
	"tls", "cert_subject", "cert_not_after", "technologies", "flags", "interest", "cookies", "tags", "note"}

func WriteCSV(w io.Writer, recs []Record) error {
	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader)
	for _, r := range recs {
		_ = cw.Write(SafeRow([]string{r.IP, r.Hostname, itoa(r.Port), r.Proto, r.State, r.Service, r.Product, r.Version, itoa(r.HTTPStatus), r.Title,
			r.Server, strconv.FormatBool(r.TLS), r.CertSubject, r.CertExpires, strings.Join(r.Technologies, "|"), strings.Join(r.Flags, "|"),
			itoa(r.Interest), strings.Join(r.Cookies, "|"), strings.Join(r.Tags, "|"), r.Note}))
	}
	cw.Flush()
	return cw.Error()
}

func itoa(i int) string {
	if i == 0 {
		return ""
	}
	return strconv.Itoa(i)
}

// ---- import ----

// Parsed: wynik parsowania pliku z wynikami (niezależnie od formatu).
type Parsed struct {
	Format string
	Alive  map[string]string // ip → hostname
	Obs    []*scan.Observation
	Ports  string
	Notes  []string
}

// ParseResults rozpoznaje format po treści: XML nmapa, nasz JSON (dokument albo tablica rekordów) lub CSV.
func ParseResults(data []byte, filename string) (*Parsed, error) {
	t := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	switch {
	case len(t) == 0:
		return nil, errors.New("pusty plik")
	case bytes.HasPrefix(t, []byte("<?xml")) || bytes.Contains(t[:min(len(t), 512)], []byte("<nmaprun")):
		return fromNmap(t)
	case t[0] == '{' || t[0] == '[':
		return fromJSON(t)
	default:
		return fromCSV(t)
	}
}

func fromNmap(data []byte) (*Parsed, error) {
	run, err := nmap.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	p := &Parsed{Format: "nmap-xml", Alive: map[string]string{}}
	seen := map[string]bool{}
	var portList []string
	for _, h := range run.Hosts {
		if h.Status.State != "up" && len(h.Ports) == 0 {
			continue
		}
		ip := h.IP()
		p.Alive[ip] = h.Hostname()
		for _, pt := range h.Ports {
			k := pt.Protocol + ":" + strconv.Itoa(pt.PortID)
			if !seen[k] {
				seen[k] = true
				pre := "T:"
				if pt.Protocol == "udp" {
					pre = "U:"
				}
				portList = append(portList, pre+strconv.Itoa(pt.PortID))
			}
			if pt.State.State != "open" {
				continue
			}
			o := &scan.Observation{IP: ip, Port: pt.PortID, Proto: pt.Protocol, State: "open", Service: pt.Service.Name,
				Product: pt.Service.Product, Version: pt.Service.Version}
			o.Data.Hostname = h.Hostname()
			o.Data.Banner = scan.Banner{Product: pt.Service.Product, Version: pt.Service.Version, ExtraInfo: pt.Service.ExtraInfo,
				Tunnel: pt.Service.Tunnel, Method: pt.Service.Method, Conf: pt.Service.Conf, CPE: pt.Service.CPE}
			p.Obs = append(p.Obs, o)
		}
	}
	p.Ports = strings.Join(portList, ",")
	p.Notes = append(p.Notes, "nmap "+run.Version+": "+run.Args)
	return p, nil
}

func fromRecords(recs []Record, format string) *Parsed {
	p := &Parsed{Format: format, Alive: map[string]string{}}
	seen := map[string]bool{}
	var portList []string
	for _, r := range recs {
		if strings.TrimSpace(r.IP) == "" {
			continue
		}
		p.Alive[r.IP] = r.Hostname
		if r.Port == 0 {
			continue
		}
		if r.Proto == "" {
			r.Proto = "tcp"
		}
		k := r.Proto + ":" + strconv.Itoa(r.Port)
		if !seen[k] {
			seen[k] = true
			pre := "T:"
			if r.Proto == "udp" {
				pre = "U:"
			}
			portList = append(portList, pre+strconv.Itoa(r.Port))
		}
		if r.State != "" && r.State != "open" {
			continue
		}
		o := &scan.Observation{IP: r.IP, Port: r.Port, Proto: r.Proto, State: "open", Service: r.Service, Product: r.Product, Version: r.Version}
		o.Data.Hostname = r.Hostname
		o.Data.Banner = scan.Banner{Product: r.Product, Version: r.Version}
		o.Data.Note = r.Note
		if r.HTTPStatus > 0 || r.Title != "" || len(r.Headers) > 0 {
			o.Data.HTTP = recordHTTP(r)
		}
		p.Obs = append(p.Obs, o)
	}
	p.Ports = strings.Join(portList, ",")
	return p
}

func fromJSON(data []byte) (*Parsed, error) {
	var recs []Record
	if data[0] == '{' {
		var d Document
		if err := json.Unmarshal(data, &d); err != nil {
			return nil, err
		}
		recs = d.Records
		p := fromRecords(recs, "asi-json")
		for _, h := range d.Hosts {
			if _, ok := p.Alive[h]; !ok {
				p.Alive[h] = ""
			}
		}
		return p, nil
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, err
	}
	return fromRecords(recs, "asi-json"), nil
}

func fromCSV(data []byte) (*Parsed, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	if bytes.Count(data[:min(len(data), 2048)], []byte(";")) > bytes.Count(data[:min(len(data), 2048)], []byte(",")) {
		cr.Comma = ';'
	}
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 1 {
		return nil, errors.New("pusty CSV")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	if _, ok := col["ip"]; !ok {
		return nil, errors.New("CSV musi mieć kolumnę 'ip' (patrz docs/FORMATY.md)")
	}
	get := func(r []string, k string) string {
		if i, ok := col[k]; ok && i < len(r) {
			return strings.TrimSpace(r[i])
		}
		return ""
	}
	var recs []Record
	for _, r := range rows[1:] {
		port, _ := strconv.Atoi(get(r, "port"))
		st, _ := strconv.Atoi(get(r, "http_status"))
		rec := Record{IP: get(r, "ip"), Hostname: get(r, "hostname"), Port: port, Proto: get(r, "proto"), State: get(r, "state"),
			Service: get(r, "service"), Product: get(r, "product"), Version: get(r, "version"), HTTPStatus: st, Title: get(r, "title"),
			Server: get(r, "server"), Note: get(r, "note")}
		if rec.Server != "" {
			rec.Headers = map[string]string{"server": rec.Server}
		}
		recs = append(recs, rec)
	}
	return fromRecords(recs, "asi-csv"), nil
}

var _ = time.Now
var _ = store.Now

func recordHTTP(r Record) *httpprobe.Result {
	h := &httpprobe.Result{Status: r.HTTPStatus, Title: r.Title, Headers: map[string][]string{}}
	for k, v := range r.Headers {
		h.Headers[strings.ToLower(k)] = []string{v}
	}
	if r.Server != "" && h.Headers["server"] == nil {
		h.Headers["server"] = []string{r.Server}
	}
	for _, c := range r.Cookies {
		h.Cookies = append(h.Cookies, httpprobe.Cookie{Name: strings.SplitN(c, ";", 2)[0]})
	}
	return h
}

// SafeRow: ochrona przed wstrzyknięciem formuł do arkusza (CSV injection). Tytuły stron i banery pochodzą od
// skanowanych hostów, więc komórka zaczynająca się od = + - @ (albo tab/CR) dostaje prefiks apostrofu.
func SafeRow(row []string) []string {
	for i, v := range row {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			if _, err := strconv.ParseFloat(v, 64); err == nil {
				continue // liczby ujemne zostają liczbami
			}
			row[i] = "'" + v
		}
	}
	return row
}
