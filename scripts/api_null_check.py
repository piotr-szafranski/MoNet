#!/usr/bin/env python3
"""Sprawdza odpowiedzi GET API pod kątem wartości null (frontend oczekuje tablic/obiektów). Użycie: python3 scripts/api_null_check.py"""
import http.cookiejar, json, sys, urllib.request
URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8095"
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
op.open(urllib.request.Request(URL + "/api/auth/login", data=b'{"username":"admin","password":"admin123!"}', headers={"Content-Type": "application/json"}))
get = lambda p: json.loads(op.open(URL + "/api" + p).read())
scans = get("/scans")
paths = ["/me", "/dashboard", "/targets", "/configs", "/scans", "/hosts", "/services", "/services/groups", "/signatures", "/users", "/roles",
         "/permissions", "/audit", "/settings/dojo", "/ports/presets", "/diff"]
ids = [s["id"] for s in scans[:4]]
for i in ids:
    paths += [f"/scans/{i}", f"/scans/{i}/observations"]
for c in get("/configs"):
    paths += [f"/configs/{c['id']}/retry", f"/configs/{c['id']}/estimate"]
hosts = get("/hosts")
if hosts:
    paths.append(f"/hosts/{hosts[0]['ip']}")
svcs = get("/services")
if svcs:
    paths.append(f"/observations/{svcs[0]['id']}")
OPTIONAL = {"annotation", "favicon_hash", "tls", "http", "latest_diff", "techs_override"}
bad = []
def walk(v, path):
    if isinstance(v, dict):
        for k, x in v.items():
            if x is None and k not in OPTIONAL:
                bad.append(path + "." + k)
            walk(x, path + "." + k)
    elif isinstance(v, list):
        for i, x in enumerate(v[:50]):
            walk(x, f"{path}[{i}]")
for p in paths:
    try:
        walk(get(p), p)
    except Exception as e:
        bad.append(f"{p}: {e}")
uniq = sorted(set(b.split("[")[0] + ("[]" if "[" in b else "") for b in bad))
print("sprawdzono", len(paths), "endpointów;", "brak null" if not uniq else "null w:\n  " + "\n  ".join(uniq[:40]))
