#!/usr/bin/env python3
"""Pomiar trafności MoNet względem prawdziwego stanu labu (endpoint /truth symulatora).

Użycie:
  docker exec asi-lab-sim wget -qO- http://127.0.0.1:9999/truth > /tmp/truth.json
  python3 scripts/accuracy.py --truth /tmp/truth.json --scan 1 [--url http://127.0.0.1:8095 --user admin --password admin123!]

Hosty o zachowaniu zmiennym (flap/daytime/changing) są raportowane osobno, bo ich stan zależy od chwili skanu.
"""
import argparse
import http.cookiejar
import json
import urllib.request


def client(url, user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    req = urllib.request.Request(url + "/api/auth/login", data=json.dumps({"username": user, "password": pw}).encode(),
                                 headers={"Content-Type": "application/json"})
    op.open(req).read()
    return lambda path: json.loads(op.open(url + "/api" + path).read())


def pr(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True)
    ap.add_argument("--scan", type=int, required=True)
    ap.add_argument("--url", default="http://127.0.0.1:8095")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin123!")
    ap.add_argument("--ports", default="", help="porty objęte skanem (domyślnie z konfiguracji skanu)")
    a = ap.parse_args()

    truth = json.load(open(a.truth))["hosts"]
    get = client(a.url, a.user, a.password)
    scan = get(f"/scans/{a.scan}")
    ports = set()
    spec = a.ports or scan["scan"]["ports"]
    for tok in spec.replace("T:", "").split(","):
        if "-" in tok:
            lo, hi = tok.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif tok.strip():
            ports.add(int(tok))
    obs = get(f"/scans/{a.scan}/observations")
    found_hosts = {o["ip"] for o in obs}
    found_ports = {(o["ip"], o["port"]) for o in obs}
    techs = {}
    for o in obs:
        techs.setdefault(o["ip"], set()).update(t["id"] for t in o["techs"])

    stable = [t for t in truth if not t.get("special")]
    special = [t for t in truth if t.get("special")]

    # hosty z co najmniej jednym portem z listy (host bez otwartych portów nie ma obserwacji)
    exp_hosts = {t["ip"] for t in stable if t["up"] and any(p in ports for p in t["open_ports"])}
    stable_ips = {t["ip"] for t in stable}
    got = found_hosts & stable_ips
    tp, fp, fn = len(got & exp_hosts), len(got - exp_hosts), len(exp_hosts - got)
    hp, hr = pr(tp, fp, fn)

    exp_ports = {(t["ip"], p) for t in stable if t["up"] for p in t["open_ports"] if p in ports}
    gotp = {x for x in found_ports if x[0] in stable_ips}
    ptp, pfp, pfn = len(gotp & exp_ports), len(gotp - exp_ports), len(exp_ports - gotp)
    pp, prc = pr(ptp, pfp, pfn)

    # technologie: oczekiwane id sygnatur na hostach stabilnych
    ttp = tfn = 0
    missed = {}
    for t in stable:
        if not t["up"] or t["ip"] not in exp_hosts:
            continue
        for tech in t["expected_techs"]:
            if tech in techs.get(t["ip"], set()):
                ttp += 1
            else:
                tfn += 1
                missed[f'{t["profile"]}:{tech}'] = missed.get(f'{t["profile"]}:{tech}', 0) + 1
    tr = ttp / (ttp + tfn) if ttp + tfn else 1.0

    print(f"Skan #{a.scan}: {scan['scan']['name']}  ({len(truth)} hostów w symulatorze, {len(special)} o zmiennym zachowaniu)")
    print(f"Hosty   : precyzja {hp:.1%}  czułość {hr:.1%}   (TP {tp}, FP {fp}, FN {fn})")
    print(f"Porty   : precyzja {pp:.1%}  czułość {prc:.1%}   (TP {ptp}, FP {pfp}, FN {pfn})")
    print(f"Technol.: wykryto {ttp}/{ttp + tfn} oczekiwanych detekcji ({tr:.1%})")
    if missed:
        print("Najczęściej pominięte:", ", ".join(f"{k}×{v}" for k, v in sorted(missed.items(), key=lambda x: -x[1])[:12]))
    if fn:
        print("Przykładowe pominięte hosty:", sorted(exp_hosts - got)[:10])


if __name__ == "__main__":
    main()
