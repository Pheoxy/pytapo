"""Offline fake Tapo H200 hub for tests.

It answers the real pyTapo transport (pytapo/transport/pytapo/pytapo.py) at the
HTTP level: the "Checking for secure connection" probe, the nonce /
device_confirm / digest_passwd login, the stok URL, and securePassthrough
requests checked by Seq and Tapo_tag. Only `requests.session` is replaced, so
every line of the transport runs as it does against a real hub.

Behaviour, all configurable on FakeHub:
- one session per user (measured on a real H200 fw 1.7.7: a second login
  from the same client address ends the first; another address does not;
  an idle session ends after about 2 minutes): each login issues a new stok
  and ends the previous one; a request on an ended stok gets a plain {"error_code": -40401}. The stok
  is checked when the request arrives, so a request already in flight when a
  new login happens still gets its answer.
- multipleRequest for the hub and controlChild-wrapped requests for children.
- `delays[(who, method)]`: seconds the hub takes to answer. If that is longer
  than the client's timeout, the fake session sleeps for the timeout and raises
  requests.exceptions.ReadTimeout, like a real slow hub. The hub still counts
  the request and uses up its Seq, as a real one would.
- counters for probes, logins, requests by (who, method), stale stoks, seq and
  tag errors, and how many requests were in flight at once.

Usage in a test (see test_fake_hub.py):

    from fake_hub import fake_hub, offline  # noqa: F401  (pytest fixtures)

    def test_x(fake_hub):
        hub = fake_hub.make_tapo()
        child = fake_hub.make_tapo(childID=fake_hub.hub.child_ids[0])
"""

import asyncio
import base64
import concurrent.futures
import copy
import hashlib
import json
import secrets
import socket
import threading
import time
from collections import Counter
from urllib.parse import urlparse

import pytest
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import pytapo.transport.pytapo.pytapo as pytapo_transport
from pytapo import Tapo

HOST = "127.0.0.1"
USER = "admin"
PASSWORD = "hub-password"
CHILD_ID = "CHILD1"


def _sha256_upper(data):
    return hashlib.sha256(data.encode("utf8")).hexdigest().upper()


def _md5_upper(data):
    return hashlib.md5(data.encode("utf8")).hexdigest().upper()


class FakeResponse:
    def __init__(self, body, status=200):
        self.text = json.dumps(body)
        self.status_code = status

    def json(self):
        return json.loads(self.text)

    def close(self):
        pass


class _Session:
    """Server side of one stok."""

    def __init__(self, stok, cnonce, nonce, hashed_password, start_seq):
        self.stok = stok
        self.cnonce = cnonce
        self.next_seq = start_seq
        self.tag_base = _sha256_upper(hashed_password + cnonce)
        hashed_key = _sha256_upper(cnonce + hashed_password + nonce)
        self.lsk = self._token(b"lsk", cnonce, nonce, hashed_key)
        self.ivb = self._token(b"ivb", cnonce, nonce, hashed_key)

    @staticmethod
    def _token(kind, cnonce, nonce, hashed_key):
        return hashlib.sha256(
            kind + cnonce.encode() + nonce.encode() + hashed_key.encode()
        ).digest()[:16]

    def decrypt(self, b64):
        cipher = AES.new(self.lsk, AES.MODE_CBC, self.ivb)
        return unpad(cipher.decrypt(base64.b64decode(b64)), AES.block_size)

    def encrypt(self, obj):
        cipher = AES.new(self.lsk, AES.MODE_CBC, self.ivb)
        raw = cipher.encrypt(pad(json.dumps(obj).encode(), AES.block_size))
        return base64.b64encode(raw).decode()


class FakeHub:
    def __init__(
        self,
        user=USER,
        password=PASSWORD,
        child_ids=(CHILD_ID,),
        hub_device_type="SMART.TAPOHUB",
        child_device_type="SMART.IPCAMERA",
        child_model="D230",
        search_results=None,
        delays=None,
        sha256=True,
    ):
        self.user = user
        # the password hash the hub holds; the client tries SHA256 then MD5
        self.hashed_password = (
            _sha256_upper(password) if sha256 else _md5_upper(password)
        )
        self.child_ids = list(child_ids)
        self.hub_device_type = hub_device_type
        self.child_device_type = child_device_type
        self.child_model = child_model
        self.search_results = (
            search_results
            if search_results is not None
            else [{"date": "20261122"}, {"date": "20261123"}]
        )
        self.delays = dict(delays or {})
        self.lock = threading.Lock()
        self.slow_arrived = threading.Event()  # set when a delayed request arrives
        self.pending = {}  # cnonce -> nonce, from login step one
        self.current = None  # the one live _Session
        self.reset_counters()

    # ------------------------------------------------------------------ counters
    def reset_counters(self):
        with getattr(self, "lock", threading.Lock()):
            self.probes = 0
            self.logins = 0
            self.stale = 0  # -40401 answers
            self.seq_errors = 0
            self.tag_errors = 0
            self.timeouts = 0
            self.requests = Counter()  # (who, method) -> count
            self.in_flight = 0
            self.max_in_flight = 0
            self.log = []  # (time, event, detail)

    def snapshot(self):
        with self.lock:
            return {
                "probes": self.probes,
                "logins": self.logins,
                "stale": self.stale,
                "seq_errors": self.seq_errors,
                "tag_errors": self.tag_errors,
                "timeouts": self.timeouts,
                "max_in_flight": self.max_in_flight,
                "requests": dict(self.requests),
            }

    def _event(self, event, detail=None):
        self.log.append((time.monotonic(), event, detail))

    # ------------------------------------------------------------------ HTTP
    def handle(self, method, url, data=None, headers=None, timeout=None, **_):
        """Called by FakeSession.request. Returns (response, delay)."""
        path = urlparse(url).path
        body = json.loads(data) if data else {}
        headers = dict(headers or {})
        with self.lock:
            if path in ("", "/"):
                return self._login(body), 0
            if not path.startswith("/stok=") or not path.endswith("/ds"):
                return FakeResponse({"error_code": -40210}), 0
            stok = path[len("/stok=") : -len("/ds")]
            session = self.current
            if session is None or stok != session.stok:
                self.stale += 1
                self._event("stale", stok)
                return FakeResponse({"error_code": -40401}), 0
            if body.get("method") != "securePassthrough":
                return FakeResponse({"error_code": -40210}), 0
            seq = int(headers.get("Seq", -1))
            if seq != session.next_seq:
                self.seq_errors += 1
                self._event("seq_error", (seq, session.next_seq))
                return FakeResponse({"error_code": -1}), 0
            tag = _sha256_upper(session.tag_base + data + str(seq))
            if headers.get("Tapo_tag") != tag:
                self.tag_errors += 1
                self._event("tag_error", seq)
                return FakeResponse({"error_code": -1}), 0
            session.next_seq += 1
            inner = json.loads(session.decrypt(body["params"]["request"]))
            reply, delay = self._answer(inner)
            return (
                FakeResponse(
                    {"error_code": 0, "result": {"response": session.encrypt(reply)}}
                ),
                delay,
            )

    def _login(self, body):
        params = body.get("params", {})
        cnonce = params.get("cnonce", "")
        if params.get("username") != self.user:
            return FakeResponse({"error_code": -40411}, 401)
        if "digest_passwd" not in params:
            # the "Checking for secure connection" probe and login step one
            self.probes += 1
            nonce = secrets.token_hex(8).upper()
            self.pending[cnonce] = nonce
            confirm = (
                _sha256_upper(cnonce + self.hashed_password + nonce) + nonce + cnonce
            )
            return FakeResponse(
                {
                    "error_code": -40413,
                    "result": {
                        "data": {
                            "code": -40413,
                            "encrypt_type": ["3"],
                            "key": "",
                            "nonce": nonce,
                            "device_confirm": confirm,
                        }
                    },
                },
                500,
            )
        nonce = self.pending.pop(cnonce, None)
        expected = (
            None
            if nonce is None
            else _sha256_upper(self.hashed_password + cnonce + nonce) + cnonce + nonce
        )
        if params["digest_passwd"] != expected:
            return FakeResponse(
                {"error_code": -40411, "result": {"data": {"code": -40411}}}, 401
            )
        self.logins += 1
        start_seq = secrets.randbelow(1000) + 100
        stok = secrets.token_hex(16)
        # one session per user: this login ends the previous one
        self.current = _Session(stok, cnonce, nonce, self.hashed_password, start_seq)
        self._event("login", self.logins)
        return FakeResponse(
            {
                "error_code": 0,
                "result": {"stok": stok, "user_group": "root", "start_seq": start_seq},
            }
        )

    # ------------------------------------------------------------------ methods
    def _answer(self, request):
        if request.get("method") != "multipleRequest":
            self.requests[("hub", request.get("method"))] += 1
            return {"error_code": -40210}, 0
        responses, delay = [], 0
        for item in request["params"]["requests"]:
            if item["method"] == "controlChild":
                control = item["params"]["childControl"]
                data, d = self._child(control["device_id"], control["request_data"])
                responses.append(
                    {
                        "method": "controlChild",
                        "result": {"response_data": data},
                        "error_code": 0,
                    }
                )
            else:
                result, d = self._method("hub", item["method"], item.get("params"))
                responses.append(result)
            delay = max(delay, d)
        return {"error_code": 0, "result": {"responses": responses}}, delay

    def _child(self, device_id, request_data):
        if device_id not in self.child_ids:
            return {"error_code": -10006}, 0
        responses, delay = [], 0
        for item in request_data.get("params", {}).get("requests", []):
            result, d = self._method("child", item["method"], item.get("params"))
            responses.append(result)
            delay = max(delay, d)
        return {"error_code": 0, "result": {"responses": responses}}, delay

    def _method(self, who, method, params):
        self.requests[(who, method)] += 1
        self._event("request", (who, method))
        delay = self.delays.get((who, method), 0)
        if delay:
            self.slow_arrived.set()
        result = None
        if method == "getDeviceInfo":
            basic = {
                "device_type": (
                    self.child_device_type if who == "child" else self.hub_device_type
                ),
                "device_model": self.child_model if who == "child" else "H200",
                "dev_id": self.child_ids[0] if who == "child" else "HUB",
            }
            result = {"device_info": {"basic_info": basic}}
        elif method == "getClockStatus":
            result = {
                "system": {
                    "clock_status": {
                        "seconds_from_1970": int(time.time()),
                        "local_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                }
            }
        elif method == "getPresetConfig":
            result = {"preset": {"preset": {"id": [], "name": []}}}
        elif method == "searchDateWithVideo":
            if who == "child":
                # like the real hub: only days inside the asked date range
                util = (params or {}).get("playback", {}).get("search_year_utility", {})
                start = util.get("start_date", "00000000")
                end = util.get("end_date", "99999999")
                found = [
                    copy.deepcopy(r)
                    for r in self.search_results
                    if start
                    <= (r["date"] if "date" in r else list(r.values())[0]["date"])
                    <= end
                ]
                result = {"playback": {"search_results": found}}
            else:
                result = {}
        if result is None:
            code = -10008 if who == "child" else -40210
            return {"method": method, "error_code": code}, delay
        return {"method": method, "result": result, "error_code": 0}, delay


class FakeSession:
    """Stands in for requests.Session; every request goes to one FakeHub."""

    def __init__(self, hub):
        self.hub = hub
        self.closed = False

    def mount(self, prefix, adapter):
        pass

    def close(self):
        self.closed = True

    def request(self, method, url, timeout=None, **kwargs):
        host = urlparse(url).hostname
        if host not in ("127.0.0.1", "localhost"):
            raise AssertionError(f"fake hub refuses non-local host {host}")
        hub = self.hub
        with hub.lock:
            hub.in_flight += 1
            hub.max_in_flight = max(hub.max_in_flight, hub.in_flight)
        try:
            response, delay = hub.handle(method, url, timeout=timeout, **kwargs)
            limit = timeout[1] if isinstance(timeout, tuple) else timeout
            if delay:
                if limit is not None and delay > limit:
                    time.sleep(limit)
                    with hub.lock:
                        hub.timeouts += 1
                        hub._event("timeout", delay)
                    raise requests.exceptions.ReadTimeout(
                        f"Read timed out. (read timeout={limit})"
                    )
                time.sleep(delay)
            return response
        finally:
            with hub.lock:
                hub.in_flight -= 1


class FakeHass:
    """Home Assistant stand-in: one running loop in a background thread, and an
    executor for blocking jobs, as hass.loop / hass.async_add_executor_job."""

    def __init__(self, workers=8):
        self.loop = asyncio.new_event_loop()
        self.executor = concurrent.futures.ThreadPoolExecutor(workers)
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    async def async_add_executor_job(self, func, *args):
        return await self.loop.run_in_executor(self.executor, func, *args)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.executor.shutdown(wait=False, cancel_futures=True)


class HubHarness:
    def __init__(self, hub):
        self.hub = hub
        self.hasses = []

    def make_tapo(self, **kwargs):
        kwargs.setdefault("isKLAP", False)
        if "transport" not in kwargs:
            kwargs.setdefault("transportMethod", "pytapo")
        return Tapo(HOST, USER, PASSWORD, PASSWORD, **kwargs)

    def make_hass(self):
        hass = FakeHass()
        self.hasses.append(hass)
        return hass

    def close(self):
        for hass in self.hasses:
            hass.stop()


@pytest.fixture
def offline(monkeypatch):
    """Fail loudly if anything tries to open a real socket connection."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"network access attempted in offline test: {args}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture
def fake_hub(monkeypatch, offline):
    """A FakeHub wired into requests.session, with fast timeouts and backoff."""
    hub = FakeHub()
    monkeypatch.setattr(requests, "session", lambda: FakeSession(hub))
    monkeypatch.setattr(requests, "Session", lambda: FakeSession(hub))
    monkeypatch.setattr(pytapo_transport, "CONNECTION_TIMEOUT", 0.5)
    monkeypatch.setattr(pytapo_transport, "RETRY_BACKOFF_SECONDS", 0.05)
    harness = HubHarness(hub)
    yield harness
    harness.close()
