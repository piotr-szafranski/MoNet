// Package nmap: uruchamianie nmapa (discovery i wykrywanie usług) z limitem tempa i parsowanie wyniku XML.
package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Run struct {
	XMLName  xml.Name `xml:"nmaprun"`
	Args     string   `xml:"args,attr"`
	Start    int64    `xml:"start,attr"`
	Version  string   `xml:"version,attr"`
	Hosts    []Host   `xml:"host"`
	RunStats struct {
		Finished struct {
			Elapsed string `xml:"elapsed,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts struct {
			Up, Down, Total int `xml:",attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

type Host struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []Port `xml:"ports>port"`
	Times struct {
		SRTT string `xml:"srtt,attr"`
	} `xml:"times"`
}

type Port struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Method    string   `xml:"method,attr"`
		Conf      int      `xml:"conf,attr"`
		DevType   string   `xml:"devicetype,attr"`
		OSType    string   `xml:"ostype,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
}

func (h Host) IP() string {
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	return ""
}

func (h Host) MAC() (string, string) {
	for _, a := range h.Addresses {
		if a.AddrType == "mac" {
			return a.Addr, a.Vendor
		}
	}
	return "", ""
}

func (h Host) Hostname() string {
	for _, n := range h.Hostnames {
		if n.Name != "" {
			return n.Name
		}
	}
	return ""
}

func Parse(r io.Reader) (*Run, error) {
	var run Run
	dec := xml.NewDecoder(r)
	dec.Strict = false
	if err := dec.Decode(&run); err != nil {
		return nil, fmt.Errorf("parsowanie XML nmapa: %w", err)
	}
	return &run, nil
}

// Options: parametry bezpieczeństwa i intensywności wspólne dla obu faz.
type Options struct {
	Binary         string
	Privileged     bool
	MaxRate        int // pakiety/s dla tego procesu
	Retries        int
	HostTimeout    time.Duration
	DiscoveryPorts string // np. "22,80,443"
	NoARP          bool
	Intensity      int
}

func (o Options) bin() string {
	if o.Binary != "" {
		return o.Binary
	}
	return "nmap"
}

func IsRoot() bool { return os.Geteuid() == 0 }

func common(o Options) []string {
	a := []string{"-n", "-oX", "-", "--max-retries", strconv.Itoa(max(0, o.Retries))}
	if o.MaxRate > 0 {
		a = append(a, "--max-rate", strconv.Itoa(o.MaxRate))
	}
	if o.HostTimeout > 0 {
		a = append(a, "--host-timeout", fmt.Sprintf("%ds", int(o.HostTimeout.Seconds())))
	}
	if o.Privileged {
		a = append(a, "--privileged")
	} else {
		a = append(a, "--unprivileged")
	}
	return a
}

// Discovery: wykrywanie aktywnych hostów (-sn) dla listy adresów.
func Discovery(ctx context.Context, o Options, ips []string, aggressive bool) (*Run, []string, error) {
	args := append([]string{"-sn", "-T4"}, common(o)...)
	dp := o.DiscoveryPorts
	if dp == "" {
		dp = "22,80,443,3389,8080"
	}
	if aggressive { // ponowny pomiar hostów niestabilnych: więcej sond i prób
		args = append(args, "-PE", "-PP", "-PS21,22,23,25,53,80,110,139,443,445,3389,5900,8000,8080,8443,"+dp, "-PA80,443,"+dp)
		if o.Privileged {
			args = append(args, "-PU53,161")
		}
		args = append(args, "--max-retries", "3")
	} else {
		args = append(args, "-PE", "-PS"+dp, "-PA80,443")
	}
	if o.NoARP {
		args = append(args, "--disable-arp-ping")
	}
	return run(ctx, o, args, ips)
}

// Services: skan portów i wersji usług na żywych hostach.
func Services(ctx context.Context, o Options, ips []string, portArg string, hasUDP bool) (*Run, []string, error) {
	scanType := "-sT"
	if o.Privileged {
		scanType = "-sS"
	}
	args := []string{scanType, "-sV", "-Pn", "-T4", "-p", portArg, "--version-intensity", strconv.Itoa(clamp(o.Intensity, 0, 9))}
	if hasUDP && o.Privileged {
		args = append(args, "-sU")
	}
	args = append(args, common(o)...)
	return run(ctx, o, args, ips)
}

func run(ctx context.Context, o Options, args, ips []string) (*Run, []string, error) {
	f, err := os.CreateTemp("", "asi-targets-*.txt")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(strings.Join(ips, "\n") + "\n")
	_ = f.Close()
	args = append(args, "-iL", f.Name())
	cmd := exec.CommandContext(ctx, o.bin(), args...)
	cmd.WaitDelay = 3 * time.Second
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, args, ctx.Err()
	}
	if err != nil {
		return nil, args, fmt.Errorf("nmap: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	r, err := Parse(&out)
	return r, args, err
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
