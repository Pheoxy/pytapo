"""Offline tests for hub children sharing the hub's transport.

The fake hub keeps one session per user, as a Tapo H200 appears to do:
each login ends the previous session, and a request on an ended session
gets -40401.
"""

import pytapo
from pytapo import Tapo

CHILD_ID = "CHILD1"


class FakeHub:
    def __init__(self):
        self.current = None
        self.logins = 0
        self.requests = []

    def login(self):
        self.logins += 1
        self.current = self.logins
        return self.current

    def answer(self, request):
        inner = request["params"]["requests"]
        if inner and inner[0]["method"] == "controlChild":
            data = inner[0]["params"]["childControl"]["request_data"]
            self.requests.append(("child", data["params"]["requests"][0]["method"]))
            child = {
                "error_code": 0,
                "result": {"responses": [self._result(data)]},
            }
            return {
                "error_code": 0,
                "result": {
                    "responses": [
                        {
                            "method": "controlChild",
                            "result": {"response_data": child},
                            "error_code": 0,
                        }
                    ]
                },
            }
        self.requests.append(("hub", inner[0]["method"]))
        return {"error_code": 0, "result": {"responses": [self._result(request)]}}

    def _result(self, request):
        method = request["params"]["requests"][0]["method"]
        if method == "getDeviceInfo":
            result = {"device_info": {"basic_info": {"device_type": "SMART.IPCAMERA"}}}
        else:
            result = {}
        return {"method": method, "result": result, "error_code": 0}


class FakeTransport:
    method = "pytapo"

    def __init__(self, hub, *args, **kwargs):
        self.hub = hub
        self.token = None
        self.asyncHandler = kwargs.get("asyncHandler")

    async def authenticate(self, retry=False):
        if self.token is None:
            self.token = self.hub.login()

    async def send(self, request, retry=0):
        if self.token != self.hub.current:
            return {"error_code": -40401, "result": {"data": {"code": -40401}}}
        return self.hub.answer(request)

    async def close(self):
        self.token = None


def make(monkeypatch, hub):
    monkeypatch.setattr(pytapo, "Transport", lambda *a, **k: FakeTransport(hub, **k))
    common = dict(isKLAP=False, transportMethod="pytapo")
    parent = Tapo("hub", "admin", "pw", "pw", **common)
    return parent, common


def poll(parent, child, rounds):
    for _ in range(rounds):
        parent.getTime()
        child.getTime()


def test_separate_logins_end_each_others_session(monkeypatch):
    hub = FakeHub()
    parent, common = make(monkeypatch, hub)
    child = Tapo("hub", "admin", "pw", "pw", childID=CHILD_ID, **common)
    start = hub.logins
    poll(parent, child, 5)
    # every switch between hub and child forces a fresh login
    assert hub.logins - start == 10


def test_child_with_hub_transport_keeps_one_login(monkeypatch):
    hub = FakeHub()
    parent, common = make(monkeypatch, hub)
    child = Tapo(
        "hub", "admin", "pw", "pw", childID=CHILD_ID, transport=parent.transport
    )
    assert child.transport is parent.transport
    assert child.isKLAP is False
    start = hub.logins
    poll(parent, child, 5)
    assert hub.logins == start == 1
    assert ("child", "getDeviceInfo") in hub.requests
    assert hub.requests.count(("child", "getClockStatus")) == 5
