#!/usr/bin/env python3
"""Test rozgraniczenia ról (RBAC) przez API: każda rola wykonuje akcje dozwolone i zabronione.

Użycie: python3 scripts/rbac_test.py [--url http://127.0.0.1:8095]
Wymaga kont demo (ASI_DEMO_USERS=1).
"""
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

USERS = {"Administrator": ("admin", "admin123!"), "Operator": ("operator", "operator123!"),
         "Analityk": ("analityk", "analityk123!"), "Obserwator": ("obserwator", "obserwator123!")}


class Client:
    def __init__(self, url, user, pw):
        self.url = url
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call("POST", "/auth/login", {"username": user, "password": pw})

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + "/api" + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            r = self.op.open(req)
            txt = r.read()
            return r.status, (json.loads(txt) if txt and txt[:1] in b"[{" else txt)
        except urllib.error.HTTPError as e:
            return e.code, e.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8095")
    a = ap.parse_args()
    c = {role: Client(a.url, *cred) for role, cred in USERS.items()}

    # przygotowanie: administrator tworzy cel testowy
    _, r = c["Administrator"].call("POST", "/targets", {"text": "10.255.255.77", "tags": ["rbac-test"]})
    _, targets = c["Administrator"].call("GET", "/targets")
    tid = next(t["id"] for t in targets["targets"] if t["value"] == "10.255.255.77")

    checks = [
        # (opis, metoda, ścieżka, body, {rola: oczekiwany_kod_ok?})
        ("odczyt celów", "GET", "/targets", None, {"Administrator": 1, "Operator": 1, "Analityk": 1, "Obserwator": 1}),
        ("dodanie celu", "POST", "/targets", {"text": "198.51.100.78"}, {"Administrator": 1, "Operator": 1, "Analityk": 0, "Obserwator": 0}),
        ("modyfikacja celu", "PUT", f"/targets/{tid}", {"note": "zmiana"}, {"Administrator": 1, "Operator": 1, "Analityk": 1, "Obserwator": 0}),
        ("adnotacja wyniku", "PUT", "/annotations", {"entity": "host:10.255.255.77", "tags": ["x"]}, {"Administrator": 1, "Operator": 1, "Analityk": 1, "Obserwator": 0}),
        ("dashboard", "GET", "/dashboard", None, {"Administrator": 1, "Operator": 1, "Analityk": 1, "Obserwator": 1}),
        ("eksport", "GET", "/export/targets?format=json", None, {"Administrator": 1, "Operator": 1, "Analityk": 1, "Obserwator": 1}),
        ("lista użytkowników", "GET", "/users", None, {"Administrator": 1, "Operator": 0, "Analityk": 0, "Obserwator": 0}),
        ("ustawienia DefectDojo", "GET", "/settings/dojo", None, {"Administrator": 1, "Operator": 0, "Analityk": 0, "Obserwator": 0}),
        ("ponowienie wysyłki DefectDojo", "POST", "/dojo/retry/999999", {}, {"Administrator": 1, "Operator": 1, "Analityk": 0, "Obserwator": 0}),
        ("dziennik audytu", "GET", "/audit", None, {"Administrator": 1, "Operator": 0, "Analityk": 0, "Obserwator": 0}),
        ("nowa konfiguracja", "POST", "/configs", {"name": "rbac", "ports": "80"}, {"Administrator": 1, "Operator": 1, "Analityk": 0, "Obserwator": 0}),
        ("nowa sygnatura", "POST", "/signatures", {"body": "id: rbac-x\nname: X\ncategory: other\nmatchers:\n  - {type: title, regex: zzzz}\n"}, {"Administrator": 0, "Operator": 1, "Analityk": 0, "Obserwator": 0}),
        ("usunięcie celu", "DELETE", f"/targets/{tid}", None, {"Administrator": 0, "Operator": 0, "Analityk": 0, "Obserwator": 0}),
    ]
    order = ["Obserwator", "Analityk", "Operator", "Administrator"]
    failed = 0
    print(f"{'akcja':28s} " + " ".join(f"{r:>13s}" for r in order))
    for name, m, p, body, exp in checks:
        row = []
        for role in order:
            want = exp[role]
            code, _ = c[role].call(m, p, body)
            ok = code < 300 or (code == 404 and name.startswith("ponowienie"))  # 404 = uprawnienie jest, wpisu brak
            if name == "usunięcie celu":  # tylko operator i admin mogą; testujemy obserwatora/analityka, potem operator usuwa
                want = role in ("Operator",)
                if role == "Administrator":
                    row.append(f"{'(usunięty)':>13s}")
                    continue
            if name == "nowa sygnatura" and role == "Administrator":
                row.append(f"{'(duplikat)':>13s}")
                continue
            mark = "✓" if ok == bool(want) else "✗ BŁĄD"
            if ok != bool(want):
                failed += 1
            row.append(f"{('dozwolone' if ok else 'zabronione') + ' ' + mark:>13s}")
        print(f"{name:28s} " + " ".join(row))
    # sprzątanie
    _, targets = c["Administrator"].call("GET", "/targets")
    for t in targets["targets"]:
        if t["value"].startswith("10.255.255."):
            c["Administrator"].call("DELETE", f"/targets/{t['id']}")
    for cfg in c["Administrator"].call("GET", "/configs")[1]:
        if cfg["name"] == "rbac":
            c["Administrator"].call("DELETE", f"/configs/{cfg['id']}")
    for s in c["Administrator"].call("GET", "/signatures")[1]:
        if s["sid"] == "rbac-x":
            c["Administrator"].call("DELETE", f"/signatures/{s['id']}")
    print("\nWYNIK:", "wszystkie uprawnienia zgodne z rolami" if not failed else f"{failed} niezgodności")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
