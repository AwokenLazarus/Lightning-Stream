"""A small client for an umbrelOS 2.0 box: the dashboard's own tRPC API (what the web UI calls) and the
app gateway's login handoff (what a browser does when it opens an app). Stdlib only.

    box = Box("http://umbrel.local")        # the box's dashboard origin
    box.login(password)                     # user.login: a dashboard token and the browser-session cookies
    box.q("apps.state", appId="...")        # a tRPC query
    box.m("apps.install", appId="...")      # a tRPC mutation
    jar = box.app_session(app_id, port)     # the app gateway's cookie for http://<box>:<port>/

The password is passed in, never logged. Nothing here prints a token or a cookie.
"""
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request


class TrpcError(RuntimeError):
    pass


class Box:
    def __init__(self, origin):
        self.origin = origin.rstrip("/")
        self.host = urllib.parse.urlparse(self.origin).hostname
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
        self.token = None

    def _req(self, method, url, body=None, headers=None, timeout=900):
        h = {"Content-Type": "application/json", **(headers or {})}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, method=method, data=body, headers=h)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _result(self, path, code, text):
        try:
            j = json.loads(text)
        except json.JSONDecodeError:
            raise TrpcError(f"{path}: HTTP {code} {text[:300]}") from None
        if "error" in j:
            err = j["error"].get("json", j["error"]) if isinstance(j["error"], dict) else j["error"]
            raise TrpcError(f"{path}: {err.get('message', err) if isinstance(err, dict) else err}")
        return j.get("result", {}).get("data")

    def q(self, path, **inp):
        url = f"{self.origin}/trpc/{path}" + (("?input=" + urllib.parse.quote(json.dumps(inp))) if inp else "")
        return self._result(path, *self._req("GET", url))

    def m(self, path, inp=None, timeout=900, **kw):
        body = json.dumps(inp if inp is not None else kw).encode()
        return self._result(path, *self._req("POST", f"{self.origin}/trpc/{path}", body, timeout=timeout))

    def login(self, password):
        self.token = None
        self.token = self.m("user.login", password=password)
        return bool(self.token)

    def app_session(self, app_id, port, password):
        """What a browser does on opening an app: the app-auth login on the box's auth port (2000), then the
        handoff form posted to the app's own port. Returns a cookie jar the app gateway accepts."""
        jar = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
        qs = urllib.parse.urlencode({"app": app_id, "origin": "host", "path": "/"})
        req = urllib.request.Request(f"http://{self.host}:2000/app-auth/v1/account/login?{qs}", method="POST",
                                     data=json.dumps({"password": password}).encode(), headers={"Content-Type": "application/json"})
        with op.open(req, timeout=60) as r:
            handoff = json.loads(r.read().decode())
        form = urllib.parse.urlencode(handoff["params"]).encode()
        req = urllib.request.Request(handoff["url"], method="POST", data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with op.open(req, timeout=60) as r:
                st = r.status
        except urllib.error.HTTPError as e:
            st = e.code
        return jar, st, handoff["url"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def cookie_header(jar, host):
    return "; ".join(f"{c.name}={c.value}" for c in jar if c.domain.lstrip(".") in (host, host + ".local") or c.domain == host)
