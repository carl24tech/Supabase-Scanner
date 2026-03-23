import json
import urllib.request
import urllib.error
import urllib.parse


class SupabaseClient:
    def __init__(self, url, key):
        self.url = url.rstrip("/")
        self.key = key
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(self, method, path, params=None, body=None, extra_headers=None):
        url = f"{self.url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body else None
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                response_headers = dict(resp.headers)
                try:
                    return resp.status, json.loads(raw), response_headers
                except Exception:
                    return resp.status, raw.decode(errors="replace"), response_headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            response_headers = dict(e.headers)
            try:
                return e.code, json.loads(raw), response_headers
            except Exception:
                return e.code, raw.decode(errors="replace"), response_headers
        except Exception as ex:
            return 0, {"error": str(ex)}, {}

    def get(self, path, params=None, extra_headers=None):
        return self.request("GET", path, params=params, extra_headers=extra_headers)

    def post(self, path, body=None, extra_headers=None):
        return self.request("POST", path, body=body, extra_headers=extra_headers)

    def patch(self, path, body=None, params=None):
        return self.request("PATCH", path, params=params, body=body)

    def delete(self, path, params=None):
        return self.request("DELETE", path, params=params)
