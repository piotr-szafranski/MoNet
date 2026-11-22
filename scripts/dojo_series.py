#!/usr/bin/env python3
"""Seria testów integracji MoNet ↔ DefectDojo na zmieniających się pulach adresów.

Dla każdego przebiegu: wybiera grupę końcówek (różne podsieci, a grupa „losowa” to za każdym razem inne pojedyncze IP),
uruchamia skan w MoNet, wysyła wynik do DefectDojo (reimport do testu danej grupy) i WERYFIKUJE, że zestaw aktywnych
findingów w DefectDojo jest dokładnie równy zestawowi obserwacji wysłanych przez MoNet (bez braków i duplikatów).
Wyniki zapisuje na bieżąco do docs/DEFECTDOJO_SERIA.md i logs/dojo_series.json.

Użycie: python3 scripts/dojo_series.py --runs 30 --dojo-token TOKEN [--truth /tmp/truth.json]
"""
import argparse, http.client, http.cookiejar, json, random, subprocess, sys, time, urllib.request
from datetime import datetime

MoNet = "http://127.0.0.1:8095/api"
DOJO = "http://127.0.0.1:8096/api/v2"
PORTS = "21-23,80,443,554,3000,3306,3389,6379,8000,8080-8081,8443,9100,9200"
GROUPS = {
    "A · 10.66.8.0/22": ["10.66.8.0/22"],
    "B · 10.66.12.0/22 + 10.66.30.0/23": ["10.66.12.0/22", "10.66.30.0/23"],
    "C · 10.66.20.0/21": ["10.66.20.0/21"],
    "D · 10.66.40.0/22 + 10.66.56.0/23": ["10.66.40.0/22", "10.66.56.0/23"],
    "E · 10.66.48.0/21": ["10.66.48.0/21"],
    "F · losowe pojedyncze IP": None,  # za każdym razem inne
}
MIN_INTEREST = 20


class ASIClient:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.login()

    def login(self):
        self.call("POST", "/auth/login", {"username": "admin", "password": "admin123!"})

    def call(self, m, p, body=None, retry=True):
        # odporne na restart aplikacji (wdrożenia w trakcie serii): ponawianie przez ~3 min
        for attempt in range(36):
            req = urllib.request.Request(MoNet + p, data=json.dumps(body).encode() if body is not None else None, method=m,
                                         headers={"Content-Type": "application/json"})
            try:
                return json.loads(self.op.open(req, timeout=120).read() or b"null")
            except urllib.error.HTTPError as e:
                if e.code == 401 and retry:
                    self.login()
                    return self.call(m, p, body, False)
                if e.code >= 500 or e.code == 502:
                    time.sleep(5)
                    continue
                raise RuntimeError(f"{m} {p}: {e.code} {e.read()[:200]}")
            except (urllib.error.URLError, ConnectionError, OSError, http.client.HTTPException):
                time.sleep(5)
                try:
                    self.login()
                except Exception:
                    pass
        raise RuntimeError(f"{m} {p}: brak połączenia z MoNet")


def dojo_get(token, path):
    req = urllib.request.Request(DOJO + path, headers={"Authorization": "Token " + token})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


def dojo_active_ids(token, test_id):
    ids, url = [], f"/findings/?test={test_id}&active=true&limit=1000"
    while url:
        d = dojo_get(token, url)
        ids += [f.get("unique_id_from_tool") for f in d["results"]]
        nxt = d.get("next")
        url = nxt.split("/api/v2", 1)[1] if nxt else None
    return ids


def ensure_config(c, name, tags):
    for cfg in c.call("GET", "/configs"):
        if cfg["name"] == name:
            if cfg["target_tags"] != tags:
                cfg["target_tags"] = tags
                c.call("PUT", f"/configs/{cfg['id']}", cfg)
            return cfg["id"]
    cfg = c.call("POST", "/configs", {"name": name, "target_tags": tags, "ports": PORTS, "rate": 3000, "workers": 6, "http_rps": 60,
                                      "chunk_target_sec": 30, "retries": 1, "retry_unstable": True, "http_probe": True,
                                      "host_timeout_sec": 60, "excludes": "10.66.0.1"})
    return cfg["id"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--dojo-token", required=True)
    ap.add_argument("--truth", default="")
    ap.add_argument("--out", default="docs/DEFECTDOJO_SERIA.md")
    ap.add_argument("--resume-log", default="", help="dopisz do wyników z poprzedniego uruchomienia (logs/dojo_series.json)")
    a = ap.parse_args()
    c = ASIClient()
    truth_ips = []
    if a.truth:
        truth_ips = [h["ip"] for h in json.load(open(a.truth))["hosts"]]
    rows = json.load(open(a.resume_log)) if a.resume_log else []
    names = list(GROUPS)
    order = names * (a.runs // len(names) + 1)
    random.seed(time.time_ns())  # inne losowanie przy każdym uruchomieniu
    for i in range(len(rows), a.runs):
        g = order[i]
        tag = "seria-" + g.split(" ")[0].lower()
        if GROUPS[g] is None:
            tag = f"seria-f{i}"
            sample = random.sample(truth_ips, 40) + [f"10.66.{random.randint(8, 63)}.{random.randint(1, 254)}" for _ in range(10)]
            c.call("POST", "/targets", {"text": "\n".join(sample), "tags": [tag]})
        else:
            c.call("POST", "/targets", {"text": "\n".join(GROUPS[g]), "tags": [tag]})
        cfg = ensure_config(c, "Seria · " + g.split(" ·")[0], [tag])
        t0 = time.time()
        sid = c.call("POST", f"/configs/{cfg}/run", {"name": f"Seria #{i + 1} · grupa {g}"})["scan_id"]
        paused_since = None
        while True:
            s = c.call("GET", f"/scans/{sid}")["scan"]
            if s["status"] in ("completed", "failed", "cancelled"):
                break
            if s["status"] == "paused":  # restart aplikacji: zwykle wznawia się sam, w razie czego wznawiamy ręcznie
                paused_since = paused_since or time.time()
                if time.time() - paused_since > 20:
                    try:
                        c.call("POST", f"/scans/{sid}/resume", {})
                    except RuntimeError:
                        pass
                    paused_since = None
            else:
                paused_since = None
            time.sleep(5)
        title = "MoNet – seria · grupa " + g.split(" ·")[0]
        push = c.call("POST", "/dojo/push", {"scan_id": sid, "min_interest": MIN_INTEREST, "reimport": True, "test_title": title})
        hist = c.call("GET", "/dojo/history")[0]
        expected = sorted(f["unique_id_from_tool"] for f in json.loads(json.dumps(c.call("GET", f"/dojo/preview?scan_id={sid}&min_interest={MIN_INTEREST}")))["findings"])
        active = dojo_active_ids(a.dojo_token, hist["test_id"]) if hist["test_id"] else []
        dup = len(active) - len(set(active))
        missing = len(set(expected) - set(active))
        extra = len(set(active) - set(expected))
        ok = dup == 0 and missing == 0 and extra == 0 and not hist["error"]
        row = {"n": i + 1, "ts": datetime.now().strftime("%H:%M"), "group": g, "scan": sid, "ips": s["total_ips"], "hosts": s["live_hosts"],
               "services": s["open_services"], "sec": round(time.time() - t0), "sent": hist["sent"], "untouched": hist["untouched"],
               "created": hist["created"], "closed": hist["closed"], "reactivated": hist["reactivated"], "active": len(active),
               "missing": missing, "extra": extra, "dup": dup, "ok": ok, "test": hist["test_id"], "error": hist["error"]}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        write(a.out, rows)
        json.dump(rows, open("logs/dojo_series.json", "w"), ensure_ascii=False, indent=1)


def write(path, rows):
    okn = sum(r["ok"] for r in rows)
    lines = ["# Seria testów MoNet ↔ DefectDojo na zmieniających się pulach adresów", "",
             f"Wygenerowano automatycznie przez `scripts/dojo_series.py` ({datetime.now().strftime('%Y-%m-%d %H:%M')}). "
             f"Przebiegów: **{len(rows)}**, zgodnych: **{okn}/{len(rows)}**.", "",
             "Każdy przebieg: skan grupy końcówek w MoNet, potem reimport do testu DefectDojo tej grupy (obserwacje z klasą ≥ "
             f"{MIN_INTEREST}%), a na koniec weryfikacja, że **aktywne findingi w DefectDojo = obserwacje wysłane przez MoNet** "
             "(porównanie identyfikatorów `unique_id_from_tool`: brak braków, nadmiarowych i duplikatów). Grupa F to za każdym "
             "razem inne, losowo wybrane pojedyncze adresy (część nie odpowiada).", "",
             "| # | Czas | Grupa (pula adresów) | Skan | Adresów | Hosty | Usługi | Czas skanu | Wysłano | Bez zmian | Nowe | Zamknięte | Przywrócone | Aktywne w DD | Zgodność |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        status = "✅ zgodne" if r["ok"] else f"❌ braki {r['missing']}, nadmiar {r['extra']}, duplikaty {r['dup']} {r['error'][:40]}"
        lines.append(f"| {r['n']} | {r['ts']} | {r['group']} | #{r['scan']} | {r['ips']} | {r['hosts']} | {r['services']} | {r['sec']} s | "
                     f"{r['sent']} | {r['untouched']} | {r['created']} | {r['closed']} | {r['reactivated']} | {r['active']} | {status} |")
    open(path, "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
