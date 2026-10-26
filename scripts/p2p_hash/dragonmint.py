"""Read, change and restore the pool settings of a miner with the DragonMint web UI.

    dragonmint.py HOST save FILE           the current pools, in full, to FILE (mode 600); prints them without passwords
    dragonmint.py HOST show                the current pools, without passwords
    dragonmint.py HOST test URL USER FILE  pool 1 = URL with USER (password "x"), pool 2 = the saved pool 1 as the fallback
    dragonmint.py HOST restore FILE        exactly the saved pools; then reads them back and compares

The web login comes from the environment (DM_USER, DM_PASS); it is never printed.
"""
import json
import os
import sys
import urllib.parse
import urllib.request


def call(host, path, form, jwt=None):
    req = urllib.request.Request(f"http://{host}{path}", data=urllib.parse.urlencode(form).encode())
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if jwt:
        req.add_header("Authorization", f"Bearer {jwt}")
    with urllib.request.urlopen(req, timeout=20) as r:
        d = json.loads(r.read())
    if d.get("success") is not True:
        raise SystemExit(f"{path}: refused: {d.get('message', '')}")
    return d


def login(host):
    return call(host, "/api/auth", {"username": os.environ["DM_USER"], "password": os.environ["DM_PASS"]})["jwt"]


def pools(host, jwt):
    p = call(host, "/api/pools", {}, jwt)["pools"]
    return [{"url": x.get("url", ""), "user": x.get("user", ""), "pass": x.get("pass", "")} for x in p][:3]


def redacted(p):
    return [{"url": x["url"], "user": x["user"], "pass": "(set)" if x["pass"] else ""} for x in p]


def update(host, jwt, p):
    p = (p + [{"url": "", "user": "", "pass": ""}] * 3)[:3]
    form = {}
    for i, x in enumerate(p, 1):
        form[f"Pool{i}"], form[f"UserName{i}"], form[f"Password{i}"] = x["url"], x["user"], x["pass"]
    call(host, "/api/updatePools", form, jwt)


def main():
    host, cmd, *rest = sys.argv[1:]
    jwt = login(host)
    if cmd == "show":
        print(json.dumps(redacted(pools(host, jwt))))
    elif cmd == "save":
        p = pools(host, jwt)
        fd = os.open(rest[0], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(p, f)
        print(json.dumps(redacted(p)))
    elif cmd == "test":
        url, user, saved = rest
        orig = json.load(open(saved))
        update(host, jwt, [{"url": url, "user": user, "pass": "x"}, orig[0]])
        print(json.dumps(redacted(pools(host, jwt))))
    elif cmd == "restore":
        orig = json.load(open(rest[0]))
        update(host, jwt, orig)
        now = pools(host, jwt)
        same = [x for x in now if x["url"]] == [x for x in orig if x["url"]]
        print(json.dumps({"restored": same, "pools": redacted(now)}))
        sys.exit(0 if same else 1)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
